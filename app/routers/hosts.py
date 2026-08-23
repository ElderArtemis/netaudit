from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import Host
from app.schemas import HostOut

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


@router.get("", response_model=list[HostOut])
async def list_hosts(
    scan_id: int | None = Query(None),
    ip: str | None = Query(None),
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
) -> list[Host]:
    stmt = select(Host).options(
        selectinload(Host.ports), selectinload(Host.vulnerabilities)
    )
    if scan_id is not None:
        stmt = stmt.where(Host.scan_id == scan_id)
    if ip:
        stmt = stmt.where(Host.ip.ilike(f"%{ip}%"))
    stmt = stmt.order_by(Host.ip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/{host_id}", response_model=HostOut)
async def get_host(host_id: int, db: AsyncSession = Depends(get_db)) -> Host:
    result = await db.execute(
        select(Host)
        .where(Host.id == host_id)
        .options(selectinload(Host.ports), selectinload(Host.vulnerabilities))
    )
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(404, "Host no encontrado")
    return host
