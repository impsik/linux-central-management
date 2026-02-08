from pydantic import BaseModel, Field
from typing import Optional, Dict, List

class AgentRegister(BaseModel):
    agent_id: str
    hostname: str
    fqdn: Optional[str] = None
    os_id: Optional[str] = None
    os_version: Optional[str] = None
    kernel: Optional[str] = None
    labels: Dict[str,str] = Field(default_factory=dict)

class PackagesInventory(BaseModel):
    agent_id: str
    collected_at_unix: int
    packages: List[dict]

class PackageUpdateItem(BaseModel):
    name: str
    installed_version: Optional[str] = None
    candidate_version: Optional[str] = None
    is_security: Optional[bool] = None

class PackageUpdatesInventory(BaseModel):
    agent_id: str
    checked_at_unix: int
    reboot_required: Optional[bool] = None
    updates: List[PackageUpdateItem] = Field(default_factory=list)

class JobCreatePkgUpgrade(BaseModel):
    agent_ids: Optional[List[str]] = None
    labels: Optional[Dict[str,str]] = None
    packages: List[str]

class JobCreatePkgQuery(BaseModel):
    agent_ids: Optional[List[str]] = None
    labels: Optional[Dict[str,str]] = None
    packages: List[str]


class JobCreateInventoryNow(BaseModel):
    agent_ids: Optional[List[str]] = None
    labels: Optional[Dict[str,str]] = None


class JobCreateDistUpgrade(BaseModel):
    agent_ids: Optional[List[str]] = None
    labels: Optional[Dict[str,str]] = None

class JobEvent(BaseModel):
    agent_id: str
    job_id: str
    status: str
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    error: Optional[str] = None

class JobCreateServiceControl(BaseModel):
    agent_ids: Optional[List[str]] = None
    labels: Optional[Dict[str,str]] = None
    service_name: str
    action: str  # start, stop, restart


class JobCreateCVECheck(BaseModel):
    agent_ids: Optional[List[str]] = None
    labels: Optional[Dict[str, str]] = None
    cve: str
