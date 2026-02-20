
class CVEPackage(Base):
    __tablename__ = "cve_packages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String, ForeignKey("cve_definitions.cve_id", ondelete="CASCADE"), nullable=False, index=True)
    
    package_name = Column(String, nullable=False, index=True)
    release = Column(String, nullable=False, index=True)  # e.g. "jammy"
    
    # Version that fixes the issue (or "0" if always vulnerable/no fix?)
    fixed_version = Column(String, nullable=False)
    
    # Status (released, needs-triage, etc.)
    status = Column(String, nullable=False, default="unknown")

    __table_args__ = (
        Index("ix_cve_packages_lookup", "release", "package_name"),
    )
