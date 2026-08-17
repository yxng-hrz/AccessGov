from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import Base, engine
from app.routers import anomalies, applications, audit, campaigns, dashboard, grants, identities, imports


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description=(
        "Identity governance and access review portfolio platform: identities, entitlements, "
        "IAM anomaly detection, certification campaigns, decisions and audit evidence."
    ),
    lifespan=lifespan,
)

origins = ["*"] if settings.cors_origins == "*" else settings.cors_origins.split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in [identities.router, applications.router, grants.router, anomalies.router, campaigns.router, dashboard.router, audit.router, imports.router]:
    app.include_router(router, prefix="/api/v1")

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name, "version": "1.0.0"}


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(static_dir / "index.html")
