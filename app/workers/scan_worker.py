"""Worker async: consume la cola Redis y ejecuta los escaneos secuencialmente."""
import asyncio
import logging
import signal

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.redis_client import get_redis, close_redis
from app.services.scan_orchestrator import ScanOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("netaudit.worker")

settings = get_settings()


class Worker:
    def __init__(self) -> None:
        self.orchestrator = ScanOrchestrator()
        self._running = True

    def request_stop(self, *_args) -> None:
        log.info("Señal de parada recibida")
        self._running = False

    async def run(self) -> None:
        r = await get_redis()
        log.info("Worker iniciado. Escuchando cola %s", settings.scan_queue_key)

        while self._running:
            try:
                # BLPOP bloqueante con timeout 5s para poder atender señales
                item = await r.blpop(settings.scan_queue_key, timeout=5)
            except Exception as e:
                log.error("Error leyendo de Redis: %s", e)
                await asyncio.sleep(2)
                continue

            if item is None:
                continue

            _key, scan_id_raw = item
            try:
                scan_id = int(scan_id_raw)
            except ValueError:
                log.warning("Mensaje inválido en cola: %r", scan_id_raw)
                continue

            log.info("Procesando scan_id=%s", scan_id)
            async with AsyncSessionLocal() as db:
                try:
                    await self.orchestrator.run(db, scan_id)
                except Exception as e:
                    log.exception("Fallo procesando scan %s: %s", scan_id, e)

        log.info("Worker detenido")
        await close_redis()


def main() -> None:
    worker = Worker()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, worker.request_stop)
    try:
        loop.run_until_complete(worker.run())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
