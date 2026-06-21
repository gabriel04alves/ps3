from datetime import datetime
from typing import Literal
from pydantic import BaseModel


class ScanInput(BaseModel):
    hostname: str
    port: int = 443


class Finding(BaseModel):
    id: str
    category: Literal["protocol", "cipher", "certificate", "configuration"]
    title: str
    detail: str
    severity_hint: Literal["critical", "high", "medium", "low", "info"]


class ScanResponse(BaseModel):
    target: str
    scanned_at: datetime
    reachable: bool
    summary: dict[str, int]
    total_findings: int
    findings: list[Finding]


class ScanError(BaseModel):
    target: str
    reachable: bool
    error: str
    findings: list
