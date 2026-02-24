import os


def cookie_options(name: str | None = None, is_csrf: bool = False) -> dict:
    """Return cookie settings based on ENV.

    - ENV=production -> secure=True, httponly=True (except csrf), samesite='strict'
    - ENV=development (default) -> secure=False, samesite='lax'
    """
    env = os.getenv("ENV", "development").lower()
    if env == "production":
        secure = True
        samesite = "strict"
        # csrf cookie intentionally not httponly so JS can read header value if needed
        httponly = False if is_csrf else True
    else:
        secure = False
        samesite = "lax"
        httponly = False

    return {"secure": secure, "httponly": httponly, "samesite": samesite}
