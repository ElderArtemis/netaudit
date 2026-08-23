import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.database import get_db
from app.models import Scan, ScanStatus, Host
from app.redis_client import enqueue_scan, get_redis, get_last_progress
from app.schemas import ScanCreate, ScanOut, ScanDetail
from app.services.pdf_export import render_scan_pdf


router = APIRouter(prefix="/api/scans", tags=["scans"])
settings = get_settings()


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)) -> Scan:
    scan = Scan(
        name=payload.name,
        target_cidr=payload.target_cidr,
        ports=payload.ports,
        masscan_rate=payload.masscan_rate,
        nmap_scripts=payload.nmap_scripts,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    await enqueue_scan(scan.id)
    return scan


@router.get("", response_model=list[ScanOut])
async def list_scans(limit: int = 50, db: AsyncSession = Depends(get_db)) -> list[Scan]:
    result = await db.execute(
        select(Scan).order_by(desc(Scan.created_at)).limit(limit)
    )
    return list(result.scalars().all())


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)) -> Scan:
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
    return scan


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)) -> None:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Escaneo no encontrado")
    await db.delete(scan)
    await db.commit()


@router.get("/{scan_id}/export.pdf")
async def export_scan_pdf(scan_id: int, db: AsyncSession = Depends(get_db)) -> Response:
    """Genera y descarga un informe PDF profesional del escaneo."""
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
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            409,
            f"El escaneo no está completado (estado actual: {scan.status.value})",
        )

    # ReportLab es síncrono y CPU-bound: lo movemos a un thread
    pdf_bytes = await asyncio.to_thread(render_scan_pdf, scan)

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in scan.name)[:60]
    filename = f"netaudit_scan{scan.id}_{safe_name}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.websocket("/ws/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: int) -> None:
    await websocket.accept()
    r = await get_redis()
    channel = f"{settings.scan_progress_channel_prefix}{scan_id}"

    # Envía el último estado conocido si existe (para reconectores)
    last = await get_last_progress(scan_id)
    if last:
        await websocket.send_json(last)

    pubsub = r.pubsub()
    await pubsub.subscribe(channel)
    try:
        while True:
            try:
                message = await asyncio.wait_for(
                    pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                # Ping para detectar cierres
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
                continue
            if message is None:
                continue
            data = message.get("data")
            if isinstance(data, str):
                try:
                    await websocket.send_text(data)
                except Exception:
                    break
                # Si el mensaje indica fin, cerramos
                try:
                    parsed = json.loads(data)
                    if parsed.get("status") in ("completed", "failed", "cancelled"):
                        break
                except json.JSONDecodeError:
                    pass
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()
