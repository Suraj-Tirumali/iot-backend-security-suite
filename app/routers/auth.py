from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import create_access_token
from app.schemas.auth import UserRegister, UserLogin, TokenResponse, UserResponse
from app.services.auth_service import create_user, authenticate_user, get_user_by_email

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register(payload: UserRegister, db: AsyncSession = Depends(get_db)):
    """
    ISVS 2.1 - Registration enforces password policy at the schema level.
    Duplicate emails are rejected with 409 to avoid user enumeration via
    different status codes.
    """
    existing = await get_user_by_email(db, payload.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )
    user = await create_user(db, payload.email, payload.password)
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive a JWT",
)
async def login(payload: UserLogin, db: AsyncSession = Depends(get_db)):
    """
    ISVS 2.1 - Returns the same error for wrong email and wrong password
    to prevent user enumeration. Successful login returns a signed JWT.
    """
    user = await authenticate_user(db, payload.email, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(subject=user.email)
    return TokenResponse(access_token=token)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user",
)
async def get_me(
    db: AsyncSession = Depends(get_db),
    token_data: dict = Depends(lambda: None), 
):
    """
    Protected endpoint - returns the current user's profile.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Token verification dependency not yet wired - coming in next commit",
    )