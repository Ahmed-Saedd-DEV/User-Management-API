from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        # Standard security headers
        response.headers["X-Frame-Options"] = "DENY"
        # Prevent content sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Permissions-Policy (formerly Feature-Policy) - deny by default
        response.headers["Permissions-Policy"] = (
            "camera=() , microphone=() , payment=()"
        )
        # Content-Security-Policy - minimal restrictive policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none';"
        )
        return response
