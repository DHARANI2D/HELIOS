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

class TrustAuthority:
    """The central authority for issuing and managing AI identities."""

    def __init__(self):
        # In‑memory registry mapping ai_id -> public_key_bytes
        self.registry: Dict[str, bytes] = {}
    
    def issue_identity(self, ai_id: str) -> AIIdentity:
        """Generates a new identity for an AI workload."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        identity = AIIdentity(ai_id, private_key)
        
        # Register public key
        self.registry[ai_id] = identity.public_key_bytes
        return identity

    def get_public_key(self, ai_id: str) -> Optional[bytes]:
        """Retrieve the public key for a given AI identity."""
        return self.registry.get(ai_id)

    def revoke_identity(self, ai_id: str):
        """Revoke an AI identity by removing it from the registry."""
        if ai_id in self.registry:
            del self.registry[ai_id]
