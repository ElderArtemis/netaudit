from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
import ipaddress


class ScanCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    target_cidr: str = Field(min_length=1, max_length=255)
    ports: str = "1-65535"
    masscan_rate: int = Field(default=10000, ge=100, le=100000)
    nmap_scripts: str = "vuln,auth,default"

    @field_validator("target_cidr")
    @classmethod
    def validate_targets(cls, v: str) -> str:
        for target in v.split(","):
            target = target.strip()
            try:
                ipaddress.ip_network(target, strict=False)
            except ValueError as e:
                raise ValueError(f"Rango inválido '{target}': {e}")
        return v


class PortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    port: int | None
    script_id: str
    severity: str
    cve: str | None
    title: str
    output: str | None


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ip: str
    hostname: str | None
    mac_address: str | None
    vendor: str | None
    os_name: str | None
    os_accuracy: int | None
    state: str
    ports: list[PortOut] = []
    vulnerabilities: list[VulnerabilityOut] = []


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    target_cidr: str
    ports: str
    masscan_rate: int
    nmap_scripts: str
    status: str
    progress: float
    error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class ScanDetail(ScanOut):
    hosts: list[HostOut] = []
