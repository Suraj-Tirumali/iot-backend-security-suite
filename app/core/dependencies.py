from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_token
from app.models.user import User
from app.services.auth_service import get_user_by_email

# Extracts Bearer token from Authorization header
bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency — validates JWT and returns the current user.

    ISVS 2.1 — Every protected endpoint uses this dependency.
    Rejects expired, tampered, or missing tokens with 401.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(credentials.credentials)
    except JWTError:
        raise credentials_exception

    if payload.get("type") != "access":
        raise credentials_exception

    email: str | None = payload.get("sub")
    if not email:
        raise credentials_exception

    user = await get_user_by_email(db, email)
    if not user or not user.is_active:
        raise credentials_exception

    return user