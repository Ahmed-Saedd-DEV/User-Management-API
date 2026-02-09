from fastapi import Request, HTTPException
from session.core.redis import redis_client


REFRESH_LIMIT = 5
WINDOW_SECONIDS = 60
ABUSE_WINDOW = 300
ABUSE_LIMIT = 20
BAN_SECONIDS = 600


def _get_device_identifier(request: Request):
    device_id = request.cookies.get("device_id")
    if device_id:
        return f"device:{device_id}"

    ip = request.client.host
    return f"ip:{ip}"


def rate_limit_refresh(request: Request):
    device = _get_device_identifier(request=request)
    if not device:
        raise HTTPException(status_code=401, detail="Device Not Found")

    refresh_key = f"refresh_limit:{device}"
    abuse_key = f"refresh_abuse:{device}"
    ban_key = f"ban:{device}"
    if redis_client.exists(ban_key):
        ttl = redis_client.ttl(ban_key)
        raise HTTPException(
            status_code=429, detail="too many refresh, temporarily banned"
        )

    current = redis_client.incr(refresh_key)
    if current == 1:
        redis_client.expire(refresh_key, WINDOW_SECONIDS)
    if current > REFRESH_LIMIT:
        abuse_count = redis_client.incr(abuse_key)
        if abuse_count == 1:
            redis_client.expire(abuse_key, ABUSE_WINDOW)
        if abuse_count >= ABUSE_LIMIT:
            redis_client.setex(ban_key, BAN_SECONIDS, "1")
            redis_client.delete(refresh_key, abuse_key)
        raise HTTPException(status_code=429, detail="too many refresh, try later")


def rate_limit_login(request: Request):
    device = _get_device_identifier(request)
    key = f"login_attempts:{device}"
    attempts = redis_client.get(key)
    if attempts and int(attempts) >= REFRESH_LIMIT:
        raise HTTPException(
            status_code=429, detail="too many relogin attempts fresh, try later"
        )


def register_failed_login(request: Request):
    device = _get_device_identifier(request)
    key = f"login_attempts:{device}"
    attempts = redis_client.incr(key)
    if attempts == 1:
        redis_client.expire(key, WINDOW_SECONIDS)


def reset_login_attempts(request: Request):
    device = _get_device_identifier(request)
    key = f"login_attempts: {device}"

    redis_client.delete(key)
