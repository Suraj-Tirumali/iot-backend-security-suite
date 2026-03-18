from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.routers import auth, password_reset

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

# Routers
app.include_router(auth.router)
app.include_router(password_reset.router)


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