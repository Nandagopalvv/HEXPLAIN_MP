from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import shutil
import os
import hashlib
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Optional, Any
import logging
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor

load_dotenv()  # Load variables from .env

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

from src.analyzer import GhidraAnalyzer
from src.explainer import CodeExplainer
from src.rag_manager import RAGManager
from src.malware_detector import detect_malware_behaviors, scan_with_virustotal

app = FastAPI()

# ── Thread pool for running blocking I/O (Ghidra, VT scans) off the event loop ──
_thread_pool = ThreadPoolExecutor(max_workers=4)

# Initialize RAG
rag_manager = RAGManager()

DEFAULT_MODEL    = os.environ.get("HEXPLAIN_MODEL", "llama3.2")
DEFAULT_PROVIDER = os.environ.get("HEXPLAIN_PROVIDER", "local")

_explainer_instance: Optional[CodeExplainer] = None

def get_explainer(model: str = None, provider: str = None) -> CodeExplainer:
    """Get or create a cached CodeExplainer instance."""
    global _explainer_instance
    model    = model    or DEFAULT_MODEL
    provider = provider or DEFAULT_PROVIDER
    if (
        _explainer_instance is None
        or _explainer_instance.model    != model
        or _explainer_instance.provider != provider
    ):
        _explainer_instance = CodeExplainer(
            provider=provider, model=model, rag_manager=rag_manager
        )
    return _explainer_instance

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# In-memory state
# ──────────────────────────────────────────────────────────────────────────────
current_analysis: Dict[str, Any] = {
    "functions":    {},
    "binary_path":  None,
    "binary_hash":  None,   # computed once on /upload
}

# Response cache — keyed by SHA-256 of the binary content
_response_cache: Dict[str, Dict[str, Any]] = {
    "vt":       {},   # hash -> VT report  (shared by security + malware + summary)
    "security": {},   # hash -> security results dict
    "malware":  {},   # hash -> malware report dict
    "summary":  {},   # hash -> {summary, virustotal}
}

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _sha256_file(path: str) -> str:
    """Compute SHA-256 of a file (used as a stable, accurate cache key)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


async def _run_blocking(fn, *args):
    """Run a synchronous blocking function in the thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_thread_pool, fn, *args)


def _ensure_decompiled(binary_path: str) -> Dict[str, str]:
    """
    Return decompiled functions for binary_path.
    Reuses in-memory cache; re-decompiles only when the binary changes.
    Also re-indexes for RAG when freshly decompiled.
    """
    if (
        current_analysis.get("binary_path") == binary_path
        and current_analysis.get("functions")
    ):
        return current_analysis["functions"]

    analyzer  = GhidraAnalyzer(binary_path)
    functions = analyzer.decompile(None)
    current_analysis["functions"]   = functions
    current_analysis["binary_path"] = binary_path
    rag_manager.index_functions(functions, binary_path)
    return functions


def _get_vt_report(binary_path: str, binary_hash: str) -> Dict[str, Any]:
    """
    VirusTotal scan — result is cached by binary hash so every endpoint
    shares the same result without re-scanning.
    """
    if binary_hash in _response_cache["vt"]:
        logger.info(f"[CACHE HIT] VT report for {binary_hash[:12]}...")
        return _response_cache["vt"][binary_hash]

    logger.info(f"[VT] Running scan for {binary_hash[:12]}...")
    t0 = time.time()
    report = scan_with_virustotal(binary_path)
    logger.info(f"[VT] Scan done in {time.time()-t0:.1f}s  verdict={report.get('verdict','?')}")
    _response_cache["vt"][binary_hash] = report
    return report


# ──────────────────────────────────────────────────────────────────────────────
# Request models
# ──────────────────────────────────────────────────────────────────────────────
class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]
    model:    str = DEFAULT_MODEL
    provider: str = DEFAULT_PROVIDER

class AnalysisRequest(BaseModel):
    binary_path: str

class SettingsRequest(BaseModel):
    model:    str = DEFAULT_MODEL
    provider: str = DEFAULT_PROVIDER


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "model": DEFAULT_MODEL, "provider": DEFAULT_PROVIDER}


@app.post("/settings")
async def update_settings(request: SettingsRequest):
    """Update the default model/provider at runtime."""
    global DEFAULT_MODEL, DEFAULT_PROVIDER, _explainer_instance
    DEFAULT_MODEL    = request.model
    DEFAULT_PROVIDER = request.provider
    _explainer_instance = None
    return {"model": DEFAULT_MODEL, "provider": DEFAULT_PROVIDER}


@app.post("/upload")
async def upload_binary(file: UploadFile = File(...)):
    """
    Save uploaded binary to a temp file, compute its hash, and
    kick off a background VT scan so later endpoints get a cache hit.
    """
    try:
        temp_dir  = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, file.filename)

        with open(file_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        # Compute hash immediately (cheap, used as cache key everywhere)
        binary_hash = _sha256_file(file_path)
        current_analysis["binary_hash"] = binary_hash

        # Eagerly start VT scan in background so it runs while Ghidra analyses
        if binary_hash not in _response_cache["vt"]:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(_thread_pool, _get_vt_report, file_path, binary_hash)
            logger.info(f"[UPLOAD] VT scan started in background for {binary_hash[:12]}...")

        return {"path": file_path, "filename": file.filename, "hash": binary_hash}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze")
async def analyze_binary(request: AnalysisRequest):
    """
    Decompile the binary with Ghidra and index functions for RAG.
    Heavy work runs in the thread pool so the event loop stays responsive.
    """
    try:
        # Recompute hash in case the binary path changed
        binary_hash = _sha256_file(request.binary_path)
        current_analysis["binary_hash"] = binary_hash

        functions = await _run_blocking(_ensure_decompiled, request.binary_path)
        return {"functions": functions}
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze_security")
async def analyze_security(request: AnalysisRequest):
    try:
        binary_hash = current_analysis.get("binary_hash") or _sha256_file(request.binary_path)

        if binary_hash in _response_cache["security"]:
            logger.info(f"[CACHE HIT] Security report for {binary_hash[:12]}...")
            return _response_cache["security"][binary_hash]

        # Run Ghidra analysis + VT in parallel (they don't depend on each other)
        def _analyze():
            functions = _ensure_decompiled(request.binary_path)
            analyzer  = GhidraAnalyzer(request.binary_path)
            results   = analyzer.analyze_security(decompiled_functions=functions)
            return results

        results, vt_report = await asyncio.gather(
            _run_blocking(_analyze),
            _run_blocking(_get_vt_report, request.binary_path, binary_hash),
        )

        results["virustotal"] = vt_report

        # Generate NL explanation
        explainer   = get_explainer()
        explanation = await _run_blocking(
            explainer.explain_security_report, results, vt_report
        )
        results["explanation"] = explanation

        _response_cache["security"][binary_hash] = results
        return results
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze_malware")
async def analyze_malware(request: AnalysisRequest):
    """Scans the binary for malware behavioral indicators via VirusTotal."""
    try:
        binary_hash = current_analysis.get("binary_hash") or _sha256_file(request.binary_path)

        if binary_hash in _response_cache["malware"]:
            logger.info(f"[CACHE HIT] Malware report for {binary_hash[:12]}...")
            return _response_cache["malware"][binary_hash]

        # Functions + VT scan in parallel
        def _get_functions():
            return _ensure_decompiled(request.binary_path)

        functions, vt_report = await asyncio.gather(
            _run_blocking(_get_functions),
            _run_blocking(_get_vt_report, request.binary_path, binary_hash),
        )

        # detect_malware_behaviors will reuse the VT report via our cache
        # (scan_with_virustotal is called inside, cache hit is instant)
        def _detect():
            return detect_malware_behaviors(functions, binary_path=request.binary_path)

        malware_report = await _run_blocking(_detect)

        # AI threat assessment
        explainer     = get_explainer()
        ai_assessment = await _run_blocking(
            explainer.explain_malware_report, malware_report
        )
        malware_report["ai_assessment"] = ai_assessment

        _response_cache["malware"][binary_hash] = malware_report
        return malware_report
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/explain_program")
async def explain_program(request: AnalysisRequest):
    try:
        binary_hash = current_analysis.get("binary_hash") or _sha256_file(request.binary_path)

        if binary_hash in _response_cache["summary"]:
            logger.info(f"[CACHE HIT] Program summary for {binary_hash[:12]}...")
            return _response_cache["summary"][binary_hash]

        # ── Parallel: decompile + VT + security + malware ──
        def _get_functions():
            return _ensure_decompiled(request.binary_path)

        def _get_security(functions):
            # Use cached security if available, else run fresh
            cached = _response_cache["security"].get(binary_hash)
            if cached:
                return cached
            analyzer = GhidraAnalyzer(request.binary_path)
            return analyzer.analyze_security(decompiled_functions=functions)

        def _get_malware(functions):
            cached = _response_cache["malware"].get(binary_hash)
            if cached:
                return cached
            return detect_malware_behaviors(functions, binary_path=request.binary_path)

        # Step 1: decompile + VT in parallel (they're independent)
        functions, vt_report = await asyncio.gather(
            _run_blocking(_get_functions),
            _run_blocking(_get_vt_report, request.binary_path, binary_hash),
        )

        # Step 2: security + malware in parallel (both need functions)
        security_report, malware_report = await asyncio.gather(
            _run_blocking(_get_security, functions),
            _run_blocking(_get_malware, functions),
        )

        # ── For accuracy: pass the NL explanation if already generated ──
        security_explanation = security_report.get("explanation") if security_report else None
        malware_explanation  = malware_report.get("ai_assessment") if malware_report else None

        explainer = get_explainer()
        summary = await _run_blocking(
            explainer.explain_program,
            functions,
            vt_report,
            security_explanation or security_report,   # prefer NL text over raw dict
            malware_explanation  or malware_report,
        )

        result = {"summary": summary, "virustotal": vt_report}
        _response_cache["summary"][binary_hash] = result
        return result
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/chat")
async def chat(req: ChatRequest):
    explainer = get_explainer(model=req.model, provider=req.provider)
    reply = await _run_blocking(explainer.chat, req.messages)
    return {"reply": reply}


@app.post("/chat_stream")
async def chat_stream(req: ChatRequest):
    """Streaming version of the chat endpoint."""
    explainer = get_explainer(model=req.model, provider=req.provider)
    
    def generate():
        # This runs inside the generator context
        # We don't use _run_blocking here directly because we need to yield
        # instead we call the streaming method which uses the internal client
        for chunk in explainer.chat_stream(req.messages):
            yield chunk

    return StreamingResponse(generate(), media_type="text/plain")


@app.delete("/cache")
async def clear_cache():
    """Clear all response caches."""
    for key in _response_cache:
        _response_cache[key].clear()
    logger.info("[CACHE] All caches cleared.")
    return {"status": "cache cleared"}
