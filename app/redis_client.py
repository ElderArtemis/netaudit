import json
from typing import Any
import redis.asyncio as redis

from app.config import get_settings

settings = get_settings()

_redis: redis.Redis | None = None


async def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(settings.redis_url, decode_responses=True)
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None


async def enqueue_scan(scan_id: int) -> None:
    r = await get_redis()
    await r.rpush(settings.scan_queue_key, scan_id)


async def publish_progress(scan_id: int, payload: dict[str, Any]) -> None:
    r = await get_redis()
    channel = f"{settings.scan_progress_channel_prefix}{scan_id}"
    await r.publish(channel, json.dumps(payload))
    # Cache también del último estado para reconectores
    await r.setex(f"netaudit:scans:state:{scan_id}", 3600, json.dumps(payload))


async def get_last_progress(scan_id: int) -> dict[str, Any] | None:
    r = await get_redis()
    raw = await r.get(f"netaudit:scans:state:{scan_id}")
    return json.loads(raw) if raw else None
