"""
FastAPI Application Entry Point
Secure Software License Distribution System
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from contextlib import asynccontextmanager
from backend.config import API_PREFIX, BASE_DIR
from backend.database.db import seed_default_data
from backend.routes.auth import router as auth_router
from backend.routes.licenses import router as licenses_router
from backend.routes.admin import router as admin_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize and seed database on startup
    seed_default_data()
    yield

app = FastAPI(
    title="Secure Software License Distribution System API",
    description="CNS Project - Backend API for License Generation, Cryptographic Protection, Distribution, and Verification.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware to allow requests from local frontend interfaces
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Subsystem Routers
app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(licenses_router, prefix=API_PREFIX)
app.include_router(admin_router, prefix=API_PREFIX)

# Mount frontend directory for static UI serving
frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

@app.get("/")
def root():
    return {
        "project": "Secure Software License Distribution System",
        "team": "Team 07 (SoCSE)",
        "status": "online",
        "docs_url": "/docs",
        "ui_url": "/ui"
    }

@app.get("/health")
@app.get(f"{API_PREFIX}/health")
def health_check():
    return {
        "status": "healthy",
        "system": "Secure License Server",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    from backend.config import HOST, PORT
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=True)
