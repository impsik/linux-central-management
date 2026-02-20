

class CVEDefinition(Base):
    __tablename__ = "cve_definitions"

    # "CVE-2024-1234"
    cve_id = Column(String, primary_key=True)

    # Store per-release status:
    # {
    #   "jammy": { "status": "released", "package": "openssl", "details": "..." },
    #   "noble": { "status": "needs-triage", "package": "openssl" }
    # }
    definition_data = Column(JSON, nullable=False, default=dict)

    last_updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
