import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routers import health, events, alerts, incidents, mitre, dashboard, logs, simulator, system, icmp
from app.database.init_db import init_tables

logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("soc_copilot")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting AI SOC Copilot Backend in [{settings.ENVIRONMENT}] mode")
    try:
        init_tables()
    except Exception as exc:
        logger.warning(f"Could not initialize tables at startup (DB might be offline): {exc}")
    yield
    logger.info("Shutting down AI SOC Copilot Backend")

app = FastAPI(
    title="AI SOC Copilot API",
    description="Intelligent Security Operations Center Assistant API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(health.router)
app.include_router(dashboard.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(mitre.router)
app.include_router(logs.router)
app.include_router(simulator.router)
app.include_router(system.router)
app.include_router(icmp.router)

@app.get("/", tags=["Root"])
def root():
    return {
        "message": "AI SOC Copilot API is running",
        "health_check": "/api/health",
        "documentation": "/docs"
    }
