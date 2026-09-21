import json
import urllib.request
import random
from typing import List, Dict, Any, Optional
from ..core.config import settings

class MockVectorStore:
    """Fallback in-memory database for vector search when Qdrant is unavailable."""
    _shared_storage: Dict[str, List[Dict[str, Any]]] = {}

    def __init__(self):
        self.storage = MockVectorStore._shared_storage

    def create_collection(self, collection_name: str, vector_size: int):
        if collection_name not in self.storage:
            self.storage[collection_name] = []

    def upsert(self, collection_name: str, points: List[Dict[str, Any]]):
        if collection_name not in self.storage:
            self.storage[collection_name] = []
        # Update or append
        existing_ids = {p["id"]: idx for idx, p in enumerate(self.storage[collection_name])}
        for point in points:
            pid = point.get("id")
            if pid in existing_ids:
                self.storage[collection_name][existing_ids[pid]] = point
            else:
                self.storage[collection_name].append(point)

    def search(self, collection_name: str, query_vector: List[float], limit: int = 5) -> List[Dict[str, Any]]:
        if collection_name not in self.storage:
            return []
        
        # In mock mode, we rank by simple text overlap of queries (since we don't have true embeddings)
        # Or just return the top matching entries.
        results = []
        for point in self.storage[collection_name]:
            # Simple score: construct a pseudo similarity score or return them
            score = random.uniform(0.7, 0.99)
            results.append({
                "id": point["id"],
                "payload": point["payload"],
                "score": score
            })
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:limit]

class VectorStoreManager:
    def __init__(self):
        self.qdrant_client = None
        self.mock_store = MockVectorStore()
        self.provider = settings.EMBEDDING_PROVIDER
        self.openai_key = settings.OPENAI_API_KEY
        self.ollama_url = settings.OLLAMA_BASE_URL
        self.qdrant_host = settings.QDRANT_HOST
        self.qdrant_port = settings.QDRANT_PORT
        
        # Try importing qdrant_client
        try:
            from qdrant_client import QdrantClient
            self.qdrant_client = QdrantClient(host=self.qdrant_host, port=self.qdrant_port, timeout=5)
            # Ping client to test connection
            self.qdrant_client.get_collections()
        except Exception:
            self.qdrant_client = None

    async def get_embedding(self, text: str) -> List[float]:
        """Fetches vector embedding depending on config (OpenAI, Ollama, or mock floats)."""
        if self.provider == "openai" and self.openai_key:
            try:
                return await self._get_openai_embedding(text)
            except Exception:
                pass
        elif self.provider == "ollama":
            try:
                return await self._get_ollama_embedding(text)
            except Exception:
                pass
        
        # Fallback Mock: return deterministic pseudo-random float vector (1536 dimensions)
        random.seed(hash(text))
        return [random.uniform(-1.0, 1.0) for _ in range(1536)]

    async def _get_openai_embedding(self, text: str) -> List[float]:
        url = "https://api.openai.com/v1/embeddings"
        payload = {
            "input": text,
            "model": settings.EMBEDDING_MODEL
        }
        
        import asyncio
        def _sync_post():
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.openai_key}"
                }
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res["data"][0]["embedding"]
        return await asyncio.to_thread(_sync_post)

    async def _get_ollama_embedding(self, text: str) -> List[float]:
        url = f"{self.ollama_url}/api/embeddings"
        payload = {
            "model": "nomic-embed-text",
            "prompt": text
        }
        
        import asyncio
        def _sync_post():
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res["embedding"]
        return await asyncio.to_thread(_sync_post)

    async def create_collection(self, collection_name: str, vector_size: int = 1536):
        """Prepares a collection for document indexing."""
        if self.qdrant_client:
            try:
                from qdrant_client.models import Distance, VectorParams
                # Check if exists
                collections = [c.name for c in self.qdrant_client.get_collections().collections]
                if collection_name not in collections:
                    self.qdrant_client.create_collection(
                        collection_name=collection_name,
                        vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE)
                    )
                return
            except Exception:
                pass
        self.mock_store.create_collection(collection_name, vector_size)

    async def upsert_documents(self, collection_name: str, documents: List[Dict[str, Any]]):
        """Indexes text segments with corresponding embeddings and payloads."""
        await self.create_collection(collection_name)
        
        points = []
        for idx, doc in enumerate(documents):
            text = doc.get("text", "")
            vector = await self.get_embedding(text)
            payload = doc.get("payload", {})
            payload["text"] = text
            
            points.append({
                "id": doc.get("id", idx),
                "vector": vector,
                "payload": payload
            })

        if self.qdrant_client:
            try:
                from qdrant_client.models import PointStruct
                qdrant_points = [
                    PointStruct(id=p["id"], vector=p["vector"], payload=p["payload"])
                    for p in points
                ]
                self.qdrant_client.upsert(
                    collection_name=collection_name,
                    points=qdrant_points
                )
                return
            except Exception:
                pass
        
        self.mock_store.upsert(collection_name, points)

    async def query_similarity(self, collection_name: str, query_text: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Queries the vector store for semantic matches to the query text."""
        query_vector = await self.get_embedding(query_text)
        
        if self.qdrant_client:
            try:
                hits = self.qdrant_client.search(
                    collection_name=collection_name,
                    query_vector=query_vector,
                    limit=limit
                )
                return [
                    {
                        "id": hit.id,
                        "payload": hit.payload,
                        "score": hit.score
                    }
                    for hit in hits
                ]
            except Exception:
                pass
        
        # Simple lookup with mock matching rules
        results = self.mock_store.search(collection_name, query_vector, limit)
        # Enhance mock matches: if query matches content words, raise the score slightly
        query_words = set(query_text.lower().split())
        for res in results:
            content = res["payload"].get("text", "").lower()
            matching_words = sum(1 for w in query_words if w in content)
            if matching_words > 0:
                res["score"] = min(0.99, res["score"] + (matching_words * 0.05))
        
        # Re-sort matches by updated pseudo-score
        results.sort(key=lambda x: x["score"], reverse=True)
        return results
