from sqlmodel import Field, SQLModel, create_engine, select
from typing import Optional, List
import datetime
import time

class Agent(SQLModel, table=True):
    id: str = Field(primary_key=True)
    public_key: str
    trust_score: float = 100.0
    last_update: float = Field(default_factory=time.time)
    status: str = "Active"
    level: int = 10
    mode: str = "FULL_ACCESS"

class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ai_id: str
    intent: str
    decision: str
    reason: str
    current_hash: str
    prev_hash: str
    signature: str
    timestamp_raw: float = Field(default_factory=time.time)
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)

class GlobalStats(SQLModel, table=True):
    id: int = Field(default=1, primary_key=True)
    interventions: int = 0
    pending_reviews: int = 0

# Database Setup
sqlite_url = "sqlite:///./aegis.db"
engine = create_engine(sqlite_url)

def init_db():
    SQLModel.metadata.create_all(engine)
