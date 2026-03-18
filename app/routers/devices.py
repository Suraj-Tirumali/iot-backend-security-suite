import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.device import Device
from app.models.user import User
from app.schemas.device import DeviceCreate, DeviceResponse, TelemetryPayload

router = APIRouter(prefix="/devices", tags=["devices"])


@router.post(
    "",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new IoT device",
)
async def register_device(
    payload: DeviceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    ISVS 2.1 — Requires authentication. Device is owned by the
    authenticated user. Duplicate device_id is rejected with 409.
    """
    result = await db.execute(
        select(Device).where(Device.device_id == payload.device_id)
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A device with this ID already exists",
        )

    device = Device(
        owner_id=current_user.id,
        device_id=payload.device_id,
        name=payload.name,
        device_type=payload.device_type,
    )
    db.add(device)
    await db.flush()
    await db.refresh(device)
    return device


@router.get(
    "",
    response_model=list[DeviceResponse],
    summary="List all devices owned by current user",
)
async def list_devices(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    ISVS 2.1 — Authorization enforced: only returns devices owned
    by the authenticated user, never another user's devices.
    """
    result = await db.execute(
        select(Device).where(Device.owner_id == current_user.id)
    )
    return result.scalars().all()


@router.post(
    "/{device_id}/telemetry",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit telemetry data for a device",
)
async def submit_telemetry(
    device_id: str,
    payload: TelemetryPayload,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    ISVS 2.1 — Authorization enforced: only the device owner can
    submit telemetry. Returns 404 for devices not owned by the
    caller to avoid device enumeration.
    """
    result = await db.execute(
        select(Device).where(
            Device.device_id == device_id,
            Device.owner_id == current_user.id,
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    device.last_telemetry = json.dumps(payload.payload)
    device.last_seen = datetime.now(timezone.utc)
    await db.flush()
    return {"message": "Telemetry accepted", "device_id": device_id}