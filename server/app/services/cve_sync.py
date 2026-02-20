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
    Uses namespace-agnostic parsing to be robust against schema version changes.
    """
    try:
        root = ET.fromstring(xml_content)
        
        # Helper to get local tag name (ignoring {namespace})
        def local_tag(tag):
            return tag.split('}')[-1] if '}' in tag else tag

        objects = {}
        states = {}
        tests = {}

        # Pass 1: Collect Objects, States, Tests (build lookup tables)
        for elem in root.iter():
            tag = local_tag(elem.tag)
            
            if tag == "dpkginfo_object":
                obj_id = elem.get("id")
                for child in elem:
                    if local_tag(child.tag) == "name" and child.text:
                        objects[obj_id] = child.text
                        break
            
            elif tag == "dpkginfo_state":
                state_id = elem.get("id")
                for child in elem:
                    if local_tag(child.tag) == "evr" and child.text:
                        op = child.get("operation", "equals")
                        states[state_id] = (child.text, op)
                        break

            elif tag == "dpkginfo_test":
                test_id = elem.get("id")
                obj_ref = None
                state_ref = None
                for child in elem:
                    ctag = local_tag(child.tag)
                    if ctag == "object":
                        obj_ref = child.get("object_ref")
                    elif ctag == "state":
                        state_ref = child.get("state_ref")
                
                if obj_ref and state_ref:
                    tests[test_id] = (obj_ref, state_ref)

        # Pass 2: Process Definitions (Vulnerabilities)
        count = 0
        for elem in root.iter():
            if local_tag(elem.tag) == "definition":
                if elem.get("class") != "vulnerability":
                    continue
                
                # Find title
                title_text = ""
                criteria_node = None
                
                for child in elem:
                    ctag = local_tag(child.tag)
                    if ctag == "metadata":
                        for mchild in child:
                            if local_tag(mchild.tag) == "title":
                                title_text = mchild.text
                    elif ctag == "criteria":
                        criteria_node = child
                
                if not title_text or not criteria_node:
                    continue
                    
                cve_id = title_text.split(" ")[0]
                if not cve_id.startswith("CVE-"):
                    continue

                pkgs_for_cve = {}
                
                # Recursive criteria check to find referenced tests
                def check_criteria(node):
                    for child in node:
                        ctag = local_tag(child.tag)
                        if ctag == "criterion":
                            t_ref = child.get("test_ref")
                            if t_ref in tests:
                                oid, sid = tests[t_ref]
                                pkg = objects.get(oid)
                                ver_info = states.get(sid)
                                if pkg and ver_info:
                                    ver, op = ver_info
                                    # "less than" means 'ver' is the fixed version (if pkg < ver, then vulnerable)
                                    if op == "less than":
                                        pkgs_for_cve[pkg] = {
                                            "status": "released",
                                            "fixed_version": ver
                                        }
                        elif ctag == "criteria":
                            check_criteria(child)

                check_criteria(criteria_node)
                
                if pkgs_for_cve:
                    count += 1
                    if cve_id not in master_cve_map:
                        master_cve_map[cve_id] = {}
                    if codename not in master_cve_map[cve_id]:
                        master_cve_map[cve_id][codename] = {}
                    master_cve_map[cve_id][codename]["packages"] = pkgs_for_cve

        logger.info(f"Parsed {count} CVE definitions for {codename}")

    except Exception as e:
        logger.exception(f"Error parsing OVAL for {codename}")


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
