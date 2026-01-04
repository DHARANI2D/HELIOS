import time
from typing import Dict, Any
from aegis.db import Agent, engine
from sqlmodel import Session, select

class AdaptiveTrustEngine:
    """Calculates and manages dynamic trust scores for AI agents."""
    
    DECAY_RATE = 0.05
    INITIAL_TRUST = 100.0
    
    def __init__(self):
        # Trust scores and last update times are now persisted in the Agent table
        pass

    def get_trust(self, ai_id: str) -> float:
        """Returns the decayed trust score of an AI agent, fetching from DB."""
        with Session(engine) as session:
            agent = session.get(Agent, ai_id)
            if not agent:
                # If agent doesn't exist, create a new one with initial trust
                agent = Agent(id=ai_id, trust_score=self.INITIAL_TRUST, last_update=time.time())
                session.add(agent)
                session.commit()
                session.refresh(agent)
                return self.INITIAL_TRUST
            
            # Time-based decay
            elapsed = (time.time() - agent.last_update) / 60
            decay = elapsed * self.DECAY_RATE
            new_score = max(0, agent.trust_score - decay)
            
            agent.trust_score = new_score
            agent.last_update = time.time()
            session.add(agent)
            session.commit()
            session.refresh(agent)
            
            return round(agent.trust_score, 2)

    def apply_penalty(self, ai_id: str, points: float):
        """Reduces trust score based on security events, persisting to DB."""
        with Session(engine) as session:
            agent = session.get(Agent, ai_id)
            if agent:
                agent.trust_score = max(0, agent.trust_score - points)
                agent.last_update = time.time()
                session.add(agent)
                session.commit()
                session.refresh(agent)
            else:
                # If agent doesn't exist, create it with initial trust and then apply penalty
                agent = Agent(id=ai_id, trust_score=self.INITIAL_TRUST, last_update=time.time())
                agent.trust_score = max(0, agent.trust_score - points)
                session.add(agent)
                session.commit()
                session.refresh(agent)

    def boost_trust(self, ai_id: str, points: float):
        """Increases trust score (e.g., after human approval), persisting to DB."""
        with Session(engine) as session:
            agent = session.get(Agent, ai_id)
            if agent:
                agent.trust_score = min(self.INITIAL_TRUST, agent.trust_score + points)
                agent.last_update = time.time()
                session.add(agent)
                session.commit()
                session.refresh(agent)
            else:
                # If agent doesn't exist, create it with initial trust and then boost
                agent = Agent(id=ai_id, trust_score=self.INITIAL_TRUST, last_update=time.time())
                agent.trust_score = min(self.INITIAL_TRUST, agent.trust_score + points)
                session.add(agent)
                session.commit()
                session.refresh(agent)
