import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from typing import Dict, Optional

class AIIdentity:
    """Represents the cryptographic identity of an AI Agent."""
    
    def __init__(self, ai_id: str, private_key: ed25519.Ed25519PrivateKey):
        self.ai_id = ai_id
        self.__private_key = private_key
        self.public_key = private_key.public_key()
        
    @property
    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode('utf-8')

    def sign_message(self, message: bytes) -> str:
        """Sign a message using the private key."""
        signature = self.__private_key.sign(message)
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(public_key_bytes: bytes, message: bytes, signature_b64: str) -> bool:
        """Verify a signature using the public key."""
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, message)
            return True
        except Exception:
            return False

from sqlmodel import Session, select
from aegis.db import engine, Agent

class TrustAuthority:
    """The central authority for issuing and managing AI identities.
    All identities are persisted in the SQLite database via Agent model.
    """

    def issue_identity(self, ai_id: str) -> AIIdentity:
        """Generates a new identity for an AI workload and persists it."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        identity = AIIdentity(ai_id, private_key)
        
        with Session(engine) as session:
            # Check if agent already exists
            db_agent = session.get(Agent, ai_id)
            if db_agent:
                db_agent.public_key = identity.public_key_b64
                db_agent.status = "Active"
                db_agent.trust_score = 100.0
            else:
                db_agent = Agent(
                    id=ai_id,
                    public_key=identity.public_key_b64,
                    trust_score=100.0,
                    status="Active",
                    level=10,
                    mode="FULL_ACCESS"
                )
            session.add(db_agent)
            session.commit()
            
        return identity

    def get_public_key(self, ai_id: str) -> Optional[bytes]:
        """Retrieve the public key for a given AI identity from the DB."""
        with Session(engine) as session:
            agent = session.get(Agent, ai_id)
            if agent and agent.public_key:
                return base64.b64decode(agent.public_key)
        return None

    def revoke_identity(self, ai_id: str):
        """Revoke an AI identity by updating its status in the DB."""
        with Session(engine) as session:
            agent = session.get(Agent, ai_id)
            if agent:
                agent.status = "REVOKED"
                agent.level = 0
                agent.mode = "ISOLATED"
                session.add(agent)
                session.commit()
