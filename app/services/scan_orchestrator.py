"""Orquesta el pipeline de auditoría: masscan -> nmap NSE -> persistencia."""
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Scan, ScanStatus, Host, Port, Vulnerability
from app.redis_client import publish_progress
from app.services.masscan import Masscan, MasscanError
from app.services.nmap import Nmap, NmapError, NmapHost


class ScanOrchestrator:
    def __init__(self, masscan: Masscan | None = None, nmap: Nmap | None = None) -> None:
        self.masscan = masscan or Masscan()
        self.nmap = nmap or Nmap()

    async def run(self, db: AsyncSession, scan_id: int) -> None:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            return

        scan.status = ScanStatus.RUNNING_MASSCAN
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 5.0
        await db.commit()
        await publish_progress(scan_id, {
            "status": scan.status.value,
            "progress": 5.0,
            "message": "Iniciando masscan",
        })

        try:
            # Fase 1: masscan
            discovered, _stderr = await self.masscan.scan(
                targets=scan.target_cidr,
                ports=scan.ports,
                rate=scan.masscan_rate,
            )
            scan.masscan_output = {ip: ports for ip, ports in discovered.items()}
            scan.progress = 40.0
            scan.status = ScanStatus.RUNNING_NMAP
            await db.commit()
            await publish_progress(scan_id, {
                "status": scan.status.value,
                "progress": 40.0,
                "message": f"Masscan: {len(discovered)} hosts con puertos abiertos",
                "hosts_found": len(discovered),
            })

            if not discovered:
                scan.status = ScanStatus.COMPLETED
                scan.progress = 100.0
                scan.finished_at = datetime.now(timezone.utc)
                await db.commit()
                await publish_progress(scan_id, {
                    "status": "completed",
                    "progress": 100.0,
                    "message": "Sin hosts con puertos abiertos",
                })
                return

            # Fase 2: nmap NSE
            nmap_hosts = await self.nmap.scan_targeted(
                targets=discovered,
                scripts=scan.nmap_scripts,
            )
            scan.progress = 90.0
            await db.commit()
            await publish_progress(scan_id, {
                "status": "running_nmap",
                "progress": 90.0,
                "message": f"Nmap analizó {len(nmap_hosts)} hosts",
            })

            # Persistencia
            await self._persist_results(db, scan, nmap_hosts)

            scan.status = ScanStatus.COMPLETED
            scan.progress = 100.0
            scan.finished_at = datetime.now(timezone.utc)
            await db.commit()

            # Resumen
            total_vulns = sum(len(h.vulnerabilities) for h in nmap_hosts)
            critical = sum(
                1 for h in nmap_hosts for v in h.vulnerabilities if v.severity == "critical"
            )
            await publish_progress(scan_id, {
                "status": "completed",
                "progress": 100.0,
                "message": "Escaneo completado",
                "hosts": len(nmap_hosts),
                "vulnerabilities": total_vulns,
                "critical": critical,
            })

        except (MasscanError, NmapError) as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.finished_at = datetime.now(timezone.utc)
            await db.commit()
            await publish_progress(scan_id, {
                "status": "failed",
                "progress": scan.progress,
                "message": f"Error: {e}",
            })
        except Exception as e:  # último resorte
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Error inesperado: {e}"
            scan.finished_at = datetime.now(timezone.utc)
            await db.commit()
            await publish_progress(scan_id, {
                "status": "failed",
                "progress": scan.progress,
                "message": scan.error_message,
            })
            raise

    async def _persist_results(
        self, db: AsyncSession, scan: Scan, nmap_hosts: list[NmapHost]
    ) -> None:
        for nh in nmap_hosts:
            # Upsert lógico por (scan_id, ip)
            existing = await db.execute(
                select(Host).where(Host.scan_id == scan.id, Host.ip == nh.ip)
            )
            host = existing.scalar_one_or_none()
            if host is None:
                host = Host(scan_id=scan.id, ip=nh.ip)
                db.add(host)

            host.hostname = nh.hostname
            host.mac_address = nh.mac_address
            host.vendor = nh.vendor
            host.os_name = nh.os_name
            host.os_accuracy = nh.os_accuracy
            host.state = nh.state
            await db.flush()

            for np in nh.ports:
                port_obj = Port(
                    host_id=host.id,
                    port=np.port,
                    protocol=np.protocol,
                    state=np.state,
                    service=np.service,
                    product=np.product,
                    version=np.version,
                    extra_info=np.extra_info,
                    banner=np.banner,
                )
                db.add(port_obj)

            for nv in nh.vulnerabilities:
                vuln_obj = Vulnerability(
                    host_id=host.id,
                    port=nv.port,
                    script_id=nv.script_id,
                    severity=nv.severity,
                    cve=nv.cve,
                    title=nv.title,
                    output=nv.output,
                )
                db.add(vuln_obj)

        await db.flush()
