from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_reset_token, decode_token, hash_password
from app.models.user import User
from jose import JWTError


async def generate_and_store_reset_token(db: AsyncSession, user: User) -> str:
    """
    Creates a reset JWT and stores it on the user record.
    Storing the token allows single-use invalidation after use.
    """
    token = create_reset_token(subject=user.email)
    user.reset_token = token
    user.reset_token_used = False
    await db.flush()
    return token


async def validate_and_consume_reset_token(
    db: AsyncSession, token: str, new_password: str
) -> bool:
    """
    Validates the reset token, updates the password, and invalidates the token.
    Returns True on success, False on any failure.

    ISVS 2.1 — Reset tokens are single-use and short-lived.
    """
    try:
        payload = decode_token(token)
    except JWTError:
        return False

    if payload.get("type") != "reset":
        return False

    email = payload.get("sub")
    if not email:
        return False

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user:
        return False

    # Reject if token doesn't match stored token or already used
    if user.reset_token != token:
        return False
    if user.reset_token_used:
        return False

    # Apply new password and invalidate token
    user.hashed_password = hash_password(new_password)
    user.reset_token = None
    user.reset_token_used = True
    await db.flush()
    return True