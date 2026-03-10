import chromadb
import requests
import logging
import time
from typing import List, Dict, Any, Iterator

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Tuning constants
# ──────────────────────────────────────────────────────────────────────────────
# nomic-embed-text has an 8 192-token context window.
# Decompiled C uses ~3-4 chars per token on average (lots of identifiers).
# We use 3 chars/token (conservative) → 8 000 tokens × 3 = 24 000 chars as
# the absolute ceiling. We keep our working MAX_CHARS well below that so we
# never hit the edge.  2 400 chars ≈ ~800 tokens — safe with plenty of headroom.
MAX_CHUNK_CHARS = 2400
MAX_CHUNKS_PER_FUNC = 60   # caps memory for absurdly large functions

# Embedding request retry settings
EMBED_MAX_RETRIES = 3
EMBED_RETRY_BASE_DELAY = 1.0  # seconds, doubles each retry


class RAGManager:
    """
    Manages Vector Storage and Retrieval for decompiled functions.
    Uses ChromaDB for storage and Ollama for embeddings.

    Embedding strategy
    ------------------
    Functions are embedded **sequentially** (one at a time, with a small sleep
    between requests).  This avoids saturating Ollama's single-model request
    queue, which is the root cause of the "500 Internal Server Error" errors
    seen when using a parallel ThreadPoolExecutor approach.
    """

    def __init__(
        self,
        collection_name: str = "hexplain_functions",
        persist_directory: str = "./chroma_db",
    ):
        self.chroma_client = chromadb.PersistentClient(path=persist_directory)
        self.collection = self.chroma_client.get_or_create_collection(
            name=collection_name
        )
        self.ollama_base_url = "http://localhost:11434"
        self.embedding_model = "nomic-embed-text"  # 8 192-token context, 274 MB

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _get_embedding(self, text: str) -> List[float]:
        """
        Fetch an embedding from Ollama with retry + exponential back-off.
        Raises on permanent failure after EMBED_MAX_RETRIES attempts.
        """
        for attempt in range(1, EMBED_MAX_RETRIES + 1):
            try:
                response = requests.post(
                    f"{self.ollama_base_url}/api/embeddings",
                    json={"model": self.embedding_model, "prompt": text},
                    timeout=60,
                )
                if response.status_code == 200:
                    return response.json()["embedding"]

                # Non-200 response — log and decide whether to retry
                logger.warning(
                    f"Ollama embedding HTTP {response.status_code} "
                    f"(attempt {attempt}/{EMBED_MAX_RETRIES}): {response.text[:200]}"
                )
                if attempt < EMBED_MAX_RETRIES:
                    delay = EMBED_RETRY_BASE_DELAY * (2 ** (attempt - 1))
                    logger.info(f"Retrying in {delay:.1f}s …")
                    time.sleep(delay)
                else:
                    response.raise_for_status()

            except requests.exceptions.Timeout:
                logger.warning(
                    f"Ollama embedding timed out (attempt {attempt}/{EMBED_MAX_RETRIES})"
                )
                if attempt < EMBED_MAX_RETRIES:
                    time.sleep(EMBED_RETRY_BASE_DELAY * (2 ** (attempt - 1)))
                else:
                    raise

        # Should never reach here, but satisfy the type-checker
        raise RuntimeError("Embedding failed after all retries")

    def _smart_chunk(self, code: str) -> List[str]:
        """
        Split *code* into chunks that each fit within MAX_CHUNK_CHARS.

        Strategy:
        1. If the code fits in a single chunk, return it as-is.
        2. Otherwise split greedily at newline boundaries when possible,
           falling back to a hard character cut if no suitable newline is found.
        """
        if len(code) <= MAX_CHUNK_CHARS:
            return [code]

        chunks: List[str] = []
        remaining = code
        while remaining and len(chunks) < MAX_CHUNKS_PER_FUNC:
            if len(remaining) <= MAX_CHUNK_CHARS:
                chunks.append(remaining)
                break

            candidate = remaining[:MAX_CHUNK_CHARS]
            # Prefer to break at the last newline in the second half of the window
            last_nl = candidate.rfind("\n", MAX_CHUNK_CHARS // 2)
            if last_nl != -1:
                chunks.append(remaining[:last_nl])
                remaining = remaining[last_nl + 1 :]
            else:
                chunks.append(candidate)
                remaining = remaining[MAX_CHUNK_CHARS:]

        return chunks

    def _stream_embed_functions(
        self, valid: Dict[str, str], binary_path: str
    ) -> Iterator[tuple]:
        """
        **Sequential streaming** generator.

        Yields (func_id, embedding, metadata, document) tuples one chunk at a
        time, embedding each chunk immediately after chunking.  A tiny sleep
        between requests prevents bursting Ollama's queue.

        Using a generator (rather than collecting all results in a list first)
        means we can flush items to ChromaDB in micro-batches, keeping memory
        usage flat even for large binaries.
        """
        total = len(valid)
        for idx, (name, code) in enumerate(valid.items(), start=1):
            chunks = self._smart_chunk(code)
            multi = len(chunks) > 1
            logger.info(
                f"  [{idx}/{total}] Embedding '{name}' "
                f"({len(code)} chars → {len(chunks)} chunk{'s' if multi else ''})"
            )

            for chunk_i, chunk_text in enumerate(chunks):
                suffix = f"_chunk_{chunk_i}" if multi else ""
                func_id = f"{binary_path}:{name}{suffix}"
                try:
                    embedding = self._get_embedding(chunk_text)
                    yield (
                        func_id,
                        embedding,
                        {"name": name, "binary": binary_path, "chunk": chunk_i},
                        chunk_text,
                    )
                except Exception as e:
                    logger.warning(
                        f"    Skipping chunk {chunk_i} of '{name}' — embedding failed: {e}"
                    )

                # Brief courtesy sleep so Ollama's goroutine can breathe
                time.sleep(0.05)

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def index_functions(self, functions: Dict[str, str], binary_path: str):
        """
        Index *functions* (name → decompiled code) into ChromaDB.

        Embeddings are generated **sequentially** to keep Ollama stable.
        Items are flushed to ChromaDB in micro-batches of 50 so memory stays
        bounded even when indexing hundreds of functions.
        """
        if not functions:
            return

        # Filter out failed decompilations
        valid = {
            name: code
            for name, code in functions.items()
            if code and not code.startswith("// Decompilation failed")
        }
        if not valid:
            logger.warning("No valid functions to index.")
            return

        logger.info(
            f"[RAG] Starting sequential indexing of {len(valid)} functions "
            f"for '{binary_path}' …"
        )
        t0 = time.time()

        BATCH_SIZE = 50
        batch_ids, batch_embs, batch_metas, batch_docs = [], [], [], []
        total_indexed = 0

        for func_id, embedding, metadata, doc in self._stream_embed_functions(
            valid, binary_path
        ):
            batch_ids.append(func_id)
            batch_embs.append(embedding)
            batch_metas.append(metadata)
            batch_docs.append(doc)

            # Flush when the micro-batch is full
            if len(batch_ids) >= BATCH_SIZE:
                self.collection.upsert(
                    ids=batch_ids,
                    embeddings=batch_embs,
                    metadatas=batch_metas,
                    documents=batch_docs,
                )
                total_indexed += len(batch_ids)
                logger.info(f"  [RAG] Flushed batch — {total_indexed} items indexed so far")
                batch_ids, batch_embs, batch_metas, batch_docs = [], [], [], []

        # Flush any remaining items
        if batch_ids:
            self.collection.upsert(
                ids=batch_ids,
                embeddings=batch_embs,
                metadatas=batch_metas,
                documents=batch_docs,
            )
            total_indexed += len(batch_ids)

        elapsed = time.time() - t0
        logger.info(
            f"[RAG] Indexing complete — {total_indexed} items from {len(valid)} functions "
            f"in {elapsed:.1f}s ({elapsed / max(len(valid), 1):.2f}s per function)"
        )

    def query_relevant_functions(self, query: str, n_results: int = 3) -> List[str]:
        """
        Query the vector store for the most relevant code snippets.
        """
        try:
            # Truncate query if the user pasted massive code into the chat
            if len(query) > MAX_CHUNK_CHARS:
                query = query[:MAX_CHUNK_CHARS]

            query_embedding = self._get_embedding(query)
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
            )
            if results["documents"] and len(results["documents"]) > 0:
                return results["documents"][0]
            return []
        except Exception as e:
            logger.error(f"Error querying RAG: {e}")
            return []

    def clear_collection(self):
        """Reset the vector store."""
        self.chroma_client.delete_collection(self.collection.name)
        self.collection = self.chroma_client.get_or_create_collection(
            name=self.collection.name
        )
