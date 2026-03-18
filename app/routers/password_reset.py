from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.services.auth_service import get_user_by_email
from app.services.email_service import send_password_reset_email
from app.services.token_service import (
    generate_and_store_reset_token,
    validate_and_consume_reset_token,
)

router = APIRouter(prefix="/auth", tags=["password reset"])


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


@router.post(
    "/password-reset/request",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a password reset email",
)
async def request_password_reset(
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    ISVS 2.1 — Always returns 202 regardless of whether the email exists.
    This prevents user enumeration via the password reset flow.
    """
    user = await get_user_by_email(db, payload.email)

    if user and user.is_active:
        token = await generate_and_store_reset_token(db, user)
        await send_password_reset_email(user.email, token)

    # Always return the same response — do not reveal if email exists
    return {"message": "If that email is registered, a reset link has been sent"}


@router.post(
    "/password-reset/confirm",
    status_code=status.HTTP_200_OK,
    summary="Confirm password reset with token and new password",
)
async def confirm_password_reset(
    payload: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
):
    """
    ISVS 2.1 — Token is validated, single-use enforced, and invalidated after use.
    Same error returned for expired, invalid, and already-used tokens.
    """
    success = await validate_and_consume_reset_token(
        db, payload.token, payload.new_password
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )
    return {"message": "Password updated successfully"}