from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        response.headers["X-frame-options"] = "DENY"
        response.headers["X-content-type-options"] = "strict-origin-when-cross-origin"
        response.headers["permissions-policy"] = (
            "camera=()," "microphone=()," "payment=()"
        )
        response.headers["Content-security-policy"] = (
            "default-str 'none';" "frame-ancestors 'none';" "base-uri 'none';"
        )
        return response
