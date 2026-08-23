from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Vulnerability, Host
from app.schemas import VulnerabilityOut

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=list[VulnerabilityOut])
async def list_vulnerabilities(
    scan_id: int | None = Query(None),
    severity: str | None = Query(None),
    cve: str | None = Query(None),
    limit: int = 500,
    db: AsyncSession = Depends(get_db),
) -> list[Vulnerability]:
    stmt = select(Vulnerability).join(Host, Vulnerability.host_id == Host.id)
    if scan_id is not None:
        stmt = stmt.where(Host.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity.lower())
    if cve:
        stmt = stmt.where(Vulnerability.cve.ilike(f"%{cve}%"))
    stmt = stmt.order_by(Vulnerability.severity, Vulnerability.id).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/summary")
async def vulnerability_summary(
    scan_id: int | None = Query(None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    stmt = (
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .join(Host, Vulnerability.host_id == Host.id)
        .group_by(Vulnerability.severity)
    )
    if scan_id is not None:
        stmt = stmt.where(Host.scan_id == scan_id)
    result = await db.execute(stmt)
    counts = {sev: total for sev, total in result.all()}
    for sev in ("critical", "high", "medium", "low", "info"):
        counts.setdefault(sev, 0)
    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts
