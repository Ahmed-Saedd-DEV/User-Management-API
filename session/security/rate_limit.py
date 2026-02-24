from fastapi import Request, HTTPException
from session.core.redis import redis_client


REFRESH_LIMIT = 5
WINDOW_SECONIDS = 60
ABUSE_WINDOW = 300
ABUSE_LIMIT = 20
BAN_SECONIDS = 600


async def _get_device_identifier(request: Request):
    # request.cookies.get and request.client.host are synchronous accessors
    device_id = request.cookies.get("device_id")
    if device_id:
        return device_id

    ip = request.client.host
    return ip


async def rate_limit_refresh(request: Request):
    device = await _get_device_identifier(request=request)
    if not device:
        raise HTTPException(status_code=401, detail="Device Not Found")
    # unified keys use plain identifier
    refresh_key = f"refresh_limit:{device}"
    abuse_key = f"refresh_abuse:{device}"
    ban_key = f"ban:{device}"
    if await redis_client.exists(ban_key):
        ttl = await redis_client.ttl(ban_key)
        raise HTTPException(
            status_code=429, detail="too many refresh, temporarily banned"
        )

    current = await redis_client.incr(refresh_key)
    if current == 1:
        await redis_client.expire(refresh_key, WINDOW_SECONIDS)
    if current > REFRESH_LIMIT:
        abuse_count = await redis_client.incr(abuse_key)
        if abuse_count == 1:
            await redis_client.expire(abuse_key, ABUSE_WINDOW)
        if abuse_count >= ABUSE_LIMIT:
            await redis_client.setex(ban_key, BAN_SECONIDS, "1")
            await redis_client.delete(refresh_key, abuse_key)
        raise HTTPException(status_code=429, detail="too many refresh, try later")


async def rate_limit_login(request: Request):
    device = await _get_device_identifier(request)
    key = f"login_attempts:{device}"
    attempts = await redis_client.get(key)
    if attempts and int(attempts) >= REFRESH_LIMIT:
        raise HTTPException(
            status_code=429, detail="too many relogin attempts fresh, try later"
        )


async def register_failed_login(request: Request):
    device = await _get_device_identifier(request)
    key = f"login_attempts:{device}"
    attempts = await redis_client.incr(key)
    if attempts == 1:
        await redis_client.expire(key, WINDOW_SECONIDS)


async def reset_login_attempts(request: Request):
    device = await _get_device_identifier(request)
    key = f"login_attempts:{device}"

    await redis_client.delete(key)


async def register_csrf_failure(request: Request):
    """Record a CSRF validation failure and ban device on abuse.

    - Increment csrf_fail:{device}
    - Expire after 5 minutes
    - If counter >= 10 -> ban:{device} for BAN_SECONIDS and delete csrf_fail key
    """
    try:
        device = await _get_device_identifier(request)
        if not device:
            return

        key = f"csrf_fail:{device}"
        count = await redis_client.incr(key)
        if count == 1:
            # expire after 5 minutes
            await redis_client.expire(key, 300)

        if int(count) >= 10:
            ban_key = f"ban:{device}"
            await redis_client.setex(ban_key, BAN_SECONIDS, "1")
            await redis_client.delete(key)
    except Exception:
        # swallow errors - CSRF checks should not crash the app
        return
