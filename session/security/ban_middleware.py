from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from session.core.redis import redis_client
from session.security.rate_limit import _get_device_identifier


class BanMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        device = await _get_device_identifier(request=request)

        # unified key format: ban:{identifier}
        is_banned = await redis_client.get(f"ban:{device}")
        if is_banned:
            raise HTTPException(status_code=403, detail="Device temporarily banned")

        return await call_next(request)
