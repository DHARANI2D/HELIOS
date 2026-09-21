from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from aegis.db import engine, init_db, Agent, GlobalStats
from aegis.config import settings
from aegis.logger import logger

# Import routers
from aegis.api.routers import identity, audit, governance, simulator, scenarios, investigation

app = FastAPI(title=settings.APP_NAME)

logger.info(f"Starting {settings.APP_NAME} in {settings.ENVIRONMENT} mode")

# Enable CORS for the React Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(identity.router)
app.include_router(audit.router)
app.include_router(governance.router)
app.include_router(simulator.router)
app.include_router(scenarios.router)
app.include_router(investigation.router)

@app.on_event("startup")
def on_startup():
    init_db()
    # Initialize Global Stats if not exists
    with Session(engine) as session:
        stats = session.get(GlobalStats, 1)
        if not stats:
            session.add(GlobalStats(id=1))
            session.commit()

@app.get("/agents", tags=["Core"])
def get_agents():
    with Session(engine) as session:
        agents = session.exec(select(Agent)).all()
        return [{
            "id": a.id,
            "trust": a.trust,  # Changed from trust_score to trust
            "status": a.status,
            "level": a.level,
            "mode": a.mode
        } for a in agents]

@app.get("/stats", tags=["Core"])
def get_stats():
    with Session(engine) as session:
        agents = session.exec(select(Agent)).all()
        stats = session.get(GlobalStats, 1)
        
        avg_trust = sum(a.trust for a in agents) / len(agents) if agents else 100.0  # Changed from trust_score to trust
        
        return {
            "active_nodes": len(agents),
            "avg_trust": f"{avg_trust:.1f}%",
            "interventions": stats.interventions if stats else 0,
            "pending": stats.pending_reviews if stats else 0
        }

@app.get("/health", tags=["Core"])
def health():
    return {"status": "OPERATIONAL", "safety_layer": "ACTIVE"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
