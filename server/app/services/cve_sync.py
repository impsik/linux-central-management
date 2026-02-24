import bz2
import logging
import asyncio
import xml.etree.ElementTree as ET
import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import delete
from app.models import CVEDefinition, CVEPackage
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Official Ubuntu OVAL definitions
SUPPORTED_RELEASES = ["focal", "jammy", "noble"]
OVAL_URL_TEMPLATE = "https://security-metadata.canonical.com/oval/com.ubuntu.{}.cve.oval.xml.bz2"

async def sync_cve_definitions(db: AsyncSession):
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
                    try:
                        xml_content = bz2.decompress(content)
                    except OSError as e:
                        logger.error(f"Failed to decompress {codename} OVAL: {e}")
                        continue
                    
                    parse_oval_xml(xml_content, codename, master_cve_map)
                    
            except Exception as e:
                logger.error(f"Error processing {codename}: {e}")

    if not master_cve_map:
        logger.warning("No CVE data collected.")
        return

    logger.info(f"Upserting {len(master_cve_map)} CVE definitions...")
    
    # 1. Update master definition blob (for legacy agent usage)
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
    
    # 2. Populate lookup table (for fast UI queries)
    # We replace data for supported releases to ensure freshness and handle removed CVEs.
    logger.info("Populating CVE lookup table...")
    
    # Clear old data for these releases first
    await db.execute(delete(CVEPackage).where(CVEPackage.release.in_(SUPPORTED_RELEASES)))
    
    lookup_rows = []
    
    for cve_id, data in master_cve_map.items():
        for release, rel_data in data.items():
            if release not in SUPPORTED_RELEASES:
                continue
            
            packages = rel_data.get("packages", {})
            for pkg_name, pkg_info in packages.items():
                lookup_rows.append({
                    "cve_id": cve_id,
                    "package_name": pkg_name,
                    "release": release,
                    "fixed_version": pkg_info.get("fixed_version", "0"),
                    "status": pkg_info.get("status", "unknown")
                })
                
                # Bulk insert in chunks
                if len(lookup_rows) >= 5000:
                    await db.execute(insert(CVEPackage).values(lookup_rows))
                    lookup_rows = []

    if lookup_rows:
        await db.execute(insert(CVEPackage).values(lookup_rows))

    await db.commit()
    logger.info("CVE sync complete.")

def parse_oval_xml(xml_content: bytes, codename: str, master_cve_map: dict):
    try:
        root = ET.fromstring(xml_content)
        
        def local_tag(tag):
            return tag.split('}')[-1] if '}' in tag else tag

        objects = {}
        states = {}
        tests = {}
        variables = {}

        # Pass 1: Collect Objects, States, Tests, Variables
        for elem in root.iter():
            tag = local_tag(elem.tag)
            
            if tag == "dpkginfo_object":
                obj_id = elem.get("id")
                # Look for name or reference
                for child in elem:
                    if local_tag(child.tag) == "name":
                        if child.get("var_ref"):
                            objects[obj_id] = { "type": "var", "ref": child.get("var_ref") }
                        elif child.text:
                            objects[obj_id] = { "type": "text", "value": child.text.strip() }
                        break
            
            elif tag == "constant_variable":
                var_id = elem.get("id")
                vals = []
                for child in elem:
                    if local_tag(child.tag) == "value" and child.text:
                        vals.append(child.text.strip())
                variables[var_id] = vals

            elif tag == "dpkginfo_state":
                state_id = elem.get("id")
                for child in elem:
                    if local_tag(child.tag) == "evr" and child.text:
                        op = child.get("operation", "equals")
                        states[state_id] = (child.text.strip(), op)

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

        # Pass 2: Process Definitions
        count = 0
        for elem in root.iter():
            if local_tag(elem.tag) == "definition":
                if elem.get("class") != "vulnerability":
                    continue
                
                title = ""
                criteria_node = None
                
                for child in elem:
                    ctag = local_tag(child.tag)
                    if ctag == "metadata":
                        for m in child:
                            if local_tag(m.tag) == "title":
                                title = m.text
                    elif ctag == "criteria":
                        criteria_node = child
                
                if not title:
                    continue
                    
                cve_id = title.strip().split(" ")[0]
                if not cve_id.startswith("CVE-"):
                    continue

                pkgs_for_cve = {}
                
                # BFS/DFS traversal of criteria
                nodes_to_visit = [criteria_node]
                while nodes_to_visit:
                    node = nodes_to_visit.pop(0)
                    if node is None: 
                        continue
                        
                    for child in node:
                        ctag = local_tag(child.tag)
                        if ctag == "criterion":
                            t_ref = child.get("test_ref")
                            if t_ref in tests:
                                oid, sid = tests[t_ref]
                                
                                # Resolve object to package name(s)
                                pkg_names = []
                                obj_info = objects.get(oid)
                                if obj_info:
                                    if obj_info["type"] == "var":
                                        pkg_names = variables.get(obj_info["ref"], [])
                                    else:
                                        pkg_names = [obj_info["value"]]
                                
                                ver_info = states.get(sid)
                                
                                if pkg_names and ver_info:
                                    ver_str, op = ver_info
                                    if op == "less than":
                                        for pkg in pkg_names:
                                            pkgs_for_cve[pkg] = {
                                                "status": "released",
                                                "fixed_version": ver_str
                                            }
                        elif ctag == "criteria":
                            nodes_to_visit.append(child)
                
                if pkgs_for_cve:
                    count += 1
                    if cve_id not in master_cve_map:
                        master_cve_map[cve_id] = {}
                    if codename not in master_cve_map[cve_id]:
                        master_cve_map[cve_id][codename] = {}
                    
                    if "packages" not in master_cve_map[cve_id][codename]:
                         master_cve_map[cve_id][codename]["packages"] = {}
                    
                    master_cve_map[cve_id][codename]["packages"].update(pkgs_for_cve)

        logger.info(f"Parsed {count} CVE definitions for {codename}")

    except Exception as e:
        logger.exception(f"Error parsing OVAL for {codename}")


async def cve_sync_loop(stop_event: asyncio.Event):
    from app.db import AsyncSessionLocal
    
    logger.info("Starting initial CVE sync...")
    try:
        async with AsyncSessionLocal() as db:
            await sync_cve_definitions(db)
    except Exception:
        logger.exception("Initial CVE sync failed")
        
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=43200)
        except asyncio.TimeoutError:
            pass

        if stop_event.is_set():
            break

        logger.info("Starting scheduled CVE sync (12h interval)...")
        try:
            async with AsyncSessionLocal() as db:
                await sync_cve_definitions(db)
        except Exception:
            logger.exception("Scheduled CVE sync failed")
