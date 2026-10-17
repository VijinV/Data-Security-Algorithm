"""
HelixLock FastAPI — Application entry point.

Start with:
    uvicorn api.main:app --reload --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import crypto, health

app = FastAPI(
    title="HelixLock API",
    description=(
        "REST API for the HelixLock multi-layer encryption engine. "
        "Layer 1: XOR / XNOR / bit-shift logical-mathematical cipher. "
        "Phase 3+ will add the Layer 2 genetics-inspired encoding."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Allow the frontend / admin console to call the API during local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, tags=["Health"])
app.include_router(crypto.router, prefix="/api/v1", tags=["Crypto"])
