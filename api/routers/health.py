"""
HelixLock API — Health-check router.
"""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    version: str


@router.get("/health", response_model=HealthResponse, summary="Health check")
def health_check() -> HealthResponse:
    """Returns `ok` when the service is running."""
    return HealthResponse(status="ok", version="0.1.0")
