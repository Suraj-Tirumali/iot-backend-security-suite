from datetime import datetime

from pydantic import BaseModel


class DeviceCreate(BaseModel):
    device_id: str
    name: str
    device_type: str


class DeviceResponse(BaseModel):
    id: int
    device_id: str
    name: str
    device_type: str
    is_active: bool
    last_seen: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class TelemetryPayload(BaseModel):
    payload: dict