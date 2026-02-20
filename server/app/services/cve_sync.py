
async def cve_sync_loop(stop_event: asyncio.Event):
    """
    Background task to sync CVE definitions once per day (or on startup).
    """
    from app.db import AsyncSessionLocal
    
    # Run immediately on startup
    logger.info("Starting initial CVE sync...")
    async with AsyncSessionLocal() as db:
        await sync_cve_definitions(db)
        
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
