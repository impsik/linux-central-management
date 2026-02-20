import bz2
import logging
import asyncio
import xml.etree.ElementTree as ET
import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import select, update
from app.models import CVEDefinition
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Official Ubuntu OVAL definitions
SUPPORTED_RELEASES = ["focal", "jammy", "noble"]
OVAL_URL_TEMPLATE = "https://security-metadata.canonical.com/oval/com.ubuntu.{}.cve.oval.xml.bz2"

async def sync_cve_definitions(db: AsyncSession):
    """
    Downloads OVAL definitions for all supported releases, parses them,
    and updates the cve_definitions table.
    """
    # Map: cve_id -> { codename: { "packages": { pkg_name: { "status": "released", "fixed_version": "1.2.3" } } } }
    master_cve_map = {}

    async with aiohttp.ClientSession() as session:
        for codename in SUPPORTED_RELEASES:
            url = OVAL_URL_TEMPLATE.format(codename)
            logger.info(f"Downloading OVAL data for {codename} from {url}...")
            
            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        logger.error(f"Failed to fetch {url}: {resp.status}")
                        continue
                    
                    content = await resp.read()
                    # Decompress bz2
                    try:
                        xml_content = bz2.decompress(content)
                    except OSError as e:
                        logger.error(f"Failed to decompress {codename} OVAL: {e}")
                        continue
                    
                    # Parse XML
                    parse_oval_xml(xml_content, codename, master_cve_map)
                    
            except Exception as e:
                logger.error(f"Error processing {codename}: {e}")

    if not master_cve_map:
        logger.warning("No CVE data collected.")
        return

    logger.info(f"Upserting {len(master_cve_map)} CVE definitions...")
    
    # Batch upsert
    chunk_size = 200
    items = list(master_cve_map.items())
    
    for i in range(0, len(items), chunk_size):
        chunk = items[i:i+chunk_size]
        values = []
        for cve_id, data in chunk:
            values.append({
                "cve_id": cve_id,
                "definition_data": data,
                "last_updated_at": datetime.now(timezone.utc)
            })
        
        stmt = insert(CVEDefinition).values(values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[CVEDefinition.cve_id],
            set_={
                "definition_data": stmt.excluded.definition_data,
                "last_updated_at": stmt.excluded.last_updated_at
            }
        )
        await db.execute(stmt)
    
    await db.commit()
    logger.info("CVE sync complete.")

def parse_oval_xml(xml_content: bytes, codename: str, master_cve_map: dict):
    """
    Parses Ubuntu OVAL XML and updates the master_cve_map.
    This uses a simplified approach to extract package names and versions from criteria.
    """
    try:
        # Register namespaces to make finding easier
        namespaces = {
            'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
            'unix': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix',
            'linux': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
            'dpkg': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux' # often reused
        }
        
        root = ET.fromstring(xml_content)
        
        # 1. First pass: Collect all tests/objects/states to map IDs to package names/versions
        # OVAL structure: definition -> criteria -> criterion (ref test) -> test -> object (ref obj) -> state (ref state)
        
        # For Ubuntu OVAL, typical test:
        # <linux_def:dpkginfo_test id="oval:com.ubuntu.jammy:tst:202412340000000" ...>
        #   <linux_def:object object_ref="oval:com.ubuntu.jammy:obj:..." />
        #   <linux_def:state state_ref="oval:com.ubuntu.jammy:ste:..." />
        # </linux_def:dpkginfo_test>
        
        # We need to map test_id -> (package_name, fixed_version, operator)
        
        # Map: object_id -> package_name
        objects = {}
        for obj in root.findall(".//{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}dpkginfo_object"):
            obj_id = obj.get("id")
            name_elem = obj.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}name")
            if name_elem is not None and name_elem.text:
                objects[obj_id] = name_elem.text

        # Map: state_id -> version_string (and operator)
        states = {}
        for state in root.findall(".//{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}dpkginfo_state"):
            state_id = state.get("id")
            evr_elem = state.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}evr")
            if evr_elem is not None and evr_elem.text:
                op = evr_elem.get("operation", "equals")
                states[state_id] = (evr_elem.text, op)

        # Map: test_id -> (package_name, version, operator)
        tests = {}
        for test in root.findall(".//{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}dpkginfo_test"):
            test_id = test.get("id")
            obj_ref = test.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}object")
            state_ref = test.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}state")
            
            if obj_ref is not None and state_ref is not None:
                oid = obj_ref.get("object_ref")
                sid = state_ref.get("state_ref")
                
                pkg = objects.get(oid)
                ver_info = states.get(sid)
                
                if pkg and ver_info:
                    tests[test_id] = (pkg, ver_info[0], ver_info[1])

        # 2. Second pass: definitions
        for definition in root.findall(".//{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition"):
            if definition.get("class") != "vulnerability":
                continue
                
            metadata = definition.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata")
            if metadata is None:
                continue
                
            title = metadata.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}title")
            if title is None:
                continue
            
            cve_id = title.text.split(" ")[0] # "CVE-2024-1234 on Ubuntu..." -> "CVE-2024-1234"
            
            if not cve_id.startswith("CVE-"):
                # fallback for USN?
                pass

            # Extract criteria
            criteria = definition.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria")
            if criteria is None:
                continue

            # In Ubuntu OVAL, criteria usually contains <criterion test_ref="...">
            # The test checks if the package is LESS THAN the fixed version.
            # So if the test matches, the system IS VULNERABLE.
            
            pkgs_for_cve = {}
            
            # Recursive function to find tests
            def find_tests(elem):
                for child in elem:
                    if child.tag.endswith("criterion"):
                        test_ref = child.get("test_ref")
                        if test_ref in tests:
                            pkg, ver, op = tests[test_ref]
                            # "less than" means 'ver' is the fixed version
                            if op == "less than":
                                pkgs_for_cve[pkg] = {
                                    "status": "released", # fixed version exists
                                    "fixed_version": ver
                                }
                            else:
                                # other ops might mean "equals" (still vulnerable?)
                                pass
                    elif child.tag.endswith("criteria"):
                        find_tests(child)

            find_tests(criteria)
            
            if pkgs_for_cve:
                if cve_id not in master_cve_map:
                    master_cve_map[cve_id] = {}
                
                if codename not in master_cve_map[cve_id]:
                    master_cve_map[cve_id][codename] = {}
                    
                master_cve_map[cve_id][codename]["packages"] = pkgs_for_cve

    except ET.ParseError as e:
        logger.error(f"XML parse error for {codename}: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error parsing OVAL for {codename}")


async def cve_sync_loop(stop_event: asyncio.Event):
    """
    Background task to sync CVE definitions once per day (or on startup).
    """
    from app.db import AsyncSessionLocal
    
    # Run immediately on startup
    logger.info("Starting initial CVE sync...")
    try:
        async with AsyncSessionLocal() as db:
            await sync_cve_definitions(db)
    except Exception:
        logger.exception("Initial CVE sync failed")
        
    while not stop_event.is_set():
        # Wait 24 hours
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=86400)
        except asyncio.TimeoutError:
            pass
            
        if stop_event.is_set():
            break
            
        logger.info("Starting daily CVE sync...")
        try:
            async with AsyncSessionLocal() as db:
                await sync_cve_definitions(db)
        except Exception:
            logger.exception("Daily CVE sync failed")
