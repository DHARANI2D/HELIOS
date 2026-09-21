from typing import List, Dict, Any, Optional
from .vector_store import VectorStoreManager

class IncidentMemoryManager:
    def __init__(self):
        self.vector_store = VectorStoreManager()
        self.collection_name = "incidents"

    async def index_incident(
        self,
        investigation_id: str,
        title: str,
        root_cause: str,
        attack_summary: str
    ):
        """Indexes a completed investigation's reports into the semantic memory database."""
        document_text = f"Incident Title: {title}\nRoot Cause: {root_cause}\nSummary: {attack_summary}"
        payload = {
            "investigation_id": investigation_id,
            "title": title,
            "root_cause": root_cause,
        }
        
        # We index using a deterministic integer-hash derived from investigation_id
        doc_id = abs(hash(investigation_id)) % (10 ** 8)
        
        await self.vector_store.upsert_documents(
            collection_name=self.collection_name,
            documents=[{
                "id": doc_id,
                "text": document_text,
                "payload": payload
            }]
        )

    async def search_similar_incidents(
        self,
        alert_description: str,
        limit: int = 3
    ) -> List[Dict[str, Any]]:
        """Queries the vector collection to find past incident investigations that share similarities."""
        try:
            results = await self.vector_store.query_similarity(
                collection_name=self.collection_name,
                query_text=alert_description,
                limit=limit
            )
            return [
                {
                    "investigation_id": res["payload"].get("investigation_id"),
                    "title": res["payload"].get("title"),
                    "root_cause": res["payload"].get("root_cause"),
                    "score": res["score"]
                }
                for res in results
            ]
        except Exception:
            return []
