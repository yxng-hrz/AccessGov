from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.routers import anomalies, applications, audit, campaigns, dashboard, governance, grants, identities, imports
from app.security import _load_keys
from app.services.sod_rules import ensure_default_rules


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        ensure_default_rules(db)
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Identity governance platform for CISO-level access risk management: Joiner-Mover-Leaver automation, "
        "IAM risk signals mapped to ISO 27001 / NIS2 / DORA, certification campaigns, time-bound risk acceptance, "
        "tamper-evident audit evidence and executive reporting."
    ),
    lifespan=lifespan,
)

origins = ["*"] if settings.cors_origins == "*" else settings.cors_origins.split(",")
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not request.url.path.startswith(("/docs", "/redoc")):  # Swagger UI loads its assets from a CDN
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response


for router in [identities.router, applications.router, grants.router, anomalies.router, campaigns.router,
               dashboard.router, governance.router, audit.router, imports.router]:
    app.include_router(router, prefix="/api/v1")

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "auth_mode": "api-key" if _load_keys() else "demo",
    }


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(static_dir / "index.html")
