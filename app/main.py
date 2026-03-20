from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.routers import auth, password_reset, devices
from app.routers.vulnerable import weak_auth, no_rate_limit

app = FastAPI(
    title="IoT Backend Security Suite - Target API",
    description=(
        "A FastAPI application serving as the target for OWASP ISVS "
        "security testing. Exposes both secure and intentionally vulnerable "
        "endpoints to validate security controls at the API layer."
    ),
    version="0.1.0",
    docs_url="/docs" if settings.APP_ENV != "production" else None,
    redoc_url="/redoc" if settings.APP_ENV != "production" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.APP_ENV == "development" else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    """
    ISVS 4.3 - Add security headers to every response.
    These headers are the baseline for any API serving IoT devices.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-xSS-Protection"] = "; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Server"] = ""
    return response


# Secure Routers
app.include_router(auth.router)
app.include_router(password_reset.router)
app.include_router(devices.router)

# Vulnerable routers  - intentional test targets, documented in ISVS test suite
app.include_router(weak_auth.router)
app.include_router(no_rate_limit.router)


@app.get("/health", tags=["health"])
async def health_check() -> dict:
    """
    Health check endpoint
    Used by Docker healthcheck and CI to verify the app is running.
    """
    return {
        "status": "ok",
        "environment": settings.APP_ENV,
        "version": "0.1.0",
    }