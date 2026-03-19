"""
VULNERABLE ENDPOINTS — INTENTIONALLY MISCONFIGURED
====================================================
These endpoints simulate common IoT backend API weaknesses.
They exist as test targets for OWASP ISVS security controls.

DO NOT use these patterns in production code.
Each vulnerability is documented with the ISVS control it violates.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import create_access_token
from app.services.auth_service import get_user_by_email

router = APIRouter(prefix="/vulnerable", tags=["vulnerable — weak auth"])


class WeakLoginPayload(BaseModel):
    email: str
    password: str


@router.post(
    "/login-no-lockout",
    summary="[VULNERABLE] Login with no brute force protection",
)
async def login_no_lockout(
    payload: WeakLoginPayload,
    db: AsyncSession = Depends(get_db),
):
    """
    VULNERABILITY: No rate limiting, no lockout, no delay.

    ISVS 2.1.2 VIOLATED — Should lock account or throttle after
    repeated failed attempts. This endpoint accepts unlimited
    login attempts with no consequence.

    TEST TARGET: test_brute_force_protection.py
    """
    user = await get_user_by_email(db, payload.email)
    if not user:
        # VULNERABILITY: Different error for unknown email vs wrong password
        # ISVS 2.1.5 VIOLATED — Enables user enumeration
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # VULNERABILITY: Plain text password comparison simulation
    # In a real vulnerable app this would be == comparison
    # We use a flag check here to keep the demo safe but testable
    if payload.password != "correct":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong password",  # VULNERABILITY: reveals which field is wrong
        )

    token = create_access_token(subject=user.email)
    return {"access_token": token, "token_type": "bearer"}


@router.post(
    "/login-weak-jwt",
    summary="[VULNERABLE] Login that issues a JWT with no expiry",
)
async def login_weak_jwt(
    payload: WeakLoginPayload,
    db: AsyncSession = Depends(get_db),
):
    """
    VULNERABILITY: Issues a JWT with algorithm=none simulation and
    an extremely long expiry (effectively never expires).

    ISVS 2.1.3 VIOLATED — Tokens must have reasonable expiry.
    ISVS 2.1.4 VIOLATED — Algorithm should be explicitly enforced.

    TEST TARGET: test_jwt_controls.py
    """
    import time
    from jose import jwt

    user = await get_user_by_email(db, payload.email)
    if not user:
        raise HTTPException(status_code=404, detail="Not found")

    # VULNERABILITY: Token never expires (exp = year 2099)
    payload_data = {
        "sub": user.email,
        "exp": 4102444800,  # 2099-01-01 — effectively never expires
        "type": "access",
        "alg_check": "skipped",  # Documents that alg enforcement is missing
    }

    # VULNERABILITY: Signed with a hardcoded weak secret
    weak_token = jwt.encode(payload_data, "secret", algorithm="HS256")
    return {
        "access_token": weak_token,
        "token_type": "bearer",
        "warning": "This token never expires — ISVS 2.1.3 violated",
    }


@router.get(
    "/user-info/{user_id}",
    summary="[VULNERABLE] Fetch any user's info without authorization check",
)
async def get_any_user_info(
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    VULNERABILITY: No authentication required, no ownership check.
    Any caller can retrieve any user's information by guessing IDs.

    ISVS 2.1.1 VIOLATED — Authorization must be enforced on every request.
    This is a classic Broken Object Level Authorization (BOLA) vulnerability.

    TEST TARGET: test_authorization_enforcement.py
    """
    from sqlalchemy import select
    from app.models.user import User

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # VULNERABILITY: Returns hashed password in response
    return {
        "id": user.id,
        "email": user.email,
        "hashed_password": user.hashed_password,  # Never expose this
        "is_superuser": user.is_superuser,
    }