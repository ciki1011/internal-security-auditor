"""
Internal Security Auditor — FastAPI Application Entry Point
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from core.database import init_db
from api.routes_discovery import router as discovery_router
from api.routes_reports import router as reports_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup/shutdown logic."""
    await init_db()
    yield
    # Cleanup on shutdown (close DB connections, etc.)


app = FastAPI(
    title="Internal Security Auditor",
    description="Automated network vulnerability assessment — discovers devices, detects CVEs, generates PDF reports.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten this in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(discovery_router, prefix="/api/v1", tags=["Discovery"])
app.include_router(reports_router, prefix="/api/v1", tags=["Reports"])


@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    return {"status": "ok", "version": app.version}