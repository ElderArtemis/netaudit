from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.redis_client import close_redis, get_redis
from app.routers import dashboard, hosts, scans, vulnerabilities

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ping a redis para fallar pronto si no hay conexión
    r = await get_redis()
    await r.ping()
    yield
    await close_redis()


app = FastAPI(
    title="NetAudit",
    description="Plataforma de auditoría de redes corporativas",
    version="1.0.0",
    root_path=settings.root_path,
    lifespan=lifespan,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(dashboard.router)
app.include_router(scans.router)
app.include_router(hosts.router)
app.include_router(vulnerabilities.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
