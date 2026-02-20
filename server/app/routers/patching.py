
@router.get("/cve/{cve_id}")
def get_cve(cve_id: str, distro_codename: str | None = None, db: Session = Depends(get_db)):
    """Check CVE status locally (no internet leak)."""
    cve_id = cve_id.upper()
    cve = db.execute(select(CVEDefinition).where(CVEDefinition.cve_id == cve_id)).scalar_one_or_none()

    if not cve:
        return {"cve": cve_id, "found": False}

    data = cve.definition_data or {}

    if not distro_codename:
        return {"cve": cve_id, "found": True, "data": data}

    distro_data = data.get(distro_codename)
    if not distro_data:
        return {"cve": cve_id, "found": True, "distro_found": False, "data": None}

    return {"cve": cve_id, "found": True, "distro_found": True, "data": distro_data}
