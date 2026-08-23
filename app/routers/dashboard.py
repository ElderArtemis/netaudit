from pathlib import Path
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import Scan, Host, Vulnerability

router = APIRouter(tags=["dashboard"])

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    scans_q = await db.execute(select(Scan).order_by(desc(Scan.created_at)).limit(20))
    scans = list(scans_q.scalars().all())

    total_hosts = (await db.execute(select(func.count(Host.id)))).scalar_one()
    total_vulns = (await db.execute(select(func.count(Vulnerability.id)))).scalar_one()
    critical = (
        await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.severity == "critical"
            )
        )
    ).scalar_one()

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "scans": scans,
            "total_hosts": total_hosts,
            "total_vulns": total_vulns,
            "total_critical": critical,
        },
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail_view(
    scan_id: int, request: Request, db: AsyncSession = Depends(get_db)
) -> HTMLResponse:
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.hosts).selectinload(Host.ports),
            selectinload(Scan.hosts).selectinload(Host.vulnerabilities),
        )
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(404, "Escaneo no encontrado")

    # Resumen por severidad
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for h in scan.hosts:
        for v in h.vulnerabilities:
            summary[v.severity] = summary.get(v.severity, 0) + 1

    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        {"scan": scan, "summary": summary},
    )
