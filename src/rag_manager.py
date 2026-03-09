import chromadb
import requests
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class RAGManager:
    """
    Manages Vector Storage and Retrieval for decompiled functions.
    Uses ChromaDB for storage and Ollama for embeddings.
    """
    def __init__(self, collection_name: str = "hexplain_functions", persist_directory: str = "./chroma_db"):
        self.chroma_client = chromadb.PersistentClient(path=persist_directory)
        self.collection = self.chroma_client.get_or_create_collection(name=collection_name)
        self.ollama_base_url = "http://localhost:11434"
        self.embedding_model = "nomic-embed-text"  # Dedicated embedding model (274MB)

    def _get_embedding(self, text: str) -> List[float]:
        """Fetch embedding from Ollama."""
        try:
            response = requests.post(
                f"{self.ollama_base_url}/api/embeddings",
                json={
                    "model": self.embedding_model,
                    "prompt": text
                },
                timeout=30
            )
            response.raise_for_status()
            return response.json()["embedding"]
        except Exception as e:
            logger.error(f"Error fetching embedding from Ollama: {e}")
            # Return a zero vector or handle appropriately? 
            # For now, let it raise to notify the caller
            raise

    def index_functions(self, functions: Dict[str, str], binary_path: str):
        """
        Indexes a set of functions for a specific binary.
        """
        if not functions:
            return

        ids = []
        embeddings = []
        metadatas = []
        documents = []

        logger.info(f"Indexing {len(functions)} functions for {binary_path}...")

        for name, code in functions.items():
            if not code or code.startswith("// Decompilation failed"):
                continue
                
            # Create a unique ID for this function in this binary
            func_id = f"{binary_path}:{name}"
            
            try:
                embedding = self._get_embedding(code)
                ids.append(func_id)
                documents.append(code)
                metadatas.append({"name": name, "binary": binary_path})
                embeddings.append(embedding)
            except Exception:
                logger.warning(f"Skipping indexing for function {name} due to embedding error.")

        if ids:
            self.collection.upsert(
                ids=ids,
                embeddings=embeddings,
                metadatas=metadatas,
                documents=documents
            )
            logger.info(f"Successfully indexed {len(ids)} functions.")

    def query_relevant_functions(self, query: str, n_results: int = 3) -> List[str]:
        """
        Queries the vector store for the most relevant code snippets.
        """
        try:
            query_embedding = self._get_embedding(query)
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results
            )
            # Flatten the results (chroma returns a list of lists for multiple queries)
            if results["documents"] and len(results["documents"]) > 0:
                return results["documents"][0]
            return []
        except Exception as e:
            logger.error(f"Error querying RAG: {e}")
            return []

    def clear_collection(self):
        """Reset the vector store."""
        self.chroma_client.delete_collection(self.collection.name)
        self.collection = self.chroma_client.get_or_create_collection(name=self.collection.name)
