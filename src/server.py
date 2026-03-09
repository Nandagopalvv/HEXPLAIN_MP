from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import shutil
import os
import hashlib
import tempfile
from pathlib import Path
from typing import List, Dict, Optional

from src.analyzer import GhidraAnalyzer
from src.explainer import CodeExplainer
from src.rag_manager import RAGManager
from src.malware_detector import detect_malware_behaviors

app = FastAPI()

# Initialize RAG
rag_manager = RAGManager()

# ── Performance: Default to llama3.2 (2GB, fits 100% in GPU) ──
DEFAULT_MODEL = os.environ.get("HEXPLAIN_MODEL", "llama3.2")
DEFAULT_PROVIDER = os.environ.get("HEXPLAIN_PROVIDER", "local")

# ── Performance: Reuse single explainer instance ──
_explainer_instance: Optional[CodeExplainer] = None

def get_explainer(model: str = None, provider: str = None) -> CodeExplainer:
    """Get or create a cached CodeExplainer instance."""
    global _explainer_instance
    model = model or DEFAULT_MODEL
    provider = provider or DEFAULT_PROVIDER
    
    if (_explainer_instance is None or 
        _explainer_instance.model != model or 
        _explainer_instance.provider != provider):
        _explainer_instance = CodeExplainer(
            provider=provider, model=model, rag_manager=rag_manager
        )
    return _explainer_instance

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store state in memory for simplicity (single user session assumed)
current_analysis = {
    "functions": {},
    "binary_path": None
}

# ── Performance: Response cache (avoids re-running LLM for same binary) ──
_response_cache = {
    "security": {},   # binary_hash -> security report
    "summary": {},    # binary_hash -> summary text
    "malware": {},    # binary_hash -> malware behavior report
}

def _get_binary_hash(binary_path: str) -> str:
    """Hash binary file for cache key."""
    try:
        h = hashlib.md5()
        with open(binary_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return binary_path  # fallback to path as key

class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]
    model: str = DEFAULT_MODEL
    provider: str = DEFAULT_PROVIDER

class AnalysisRequest(BaseModel):
    binary_path: str

class SettingsRequest(BaseModel):
    model: str = DEFAULT_MODEL
    provider: str = DEFAULT_PROVIDER

@app.get("/health")
def health():
    return {"status": "ok", "model": DEFAULT_MODEL, "provider": DEFAULT_PROVIDER}

@app.post("/settings")
async def update_settings(request: SettingsRequest):
    """Update the default model/provider at runtime."""
    global DEFAULT_MODEL, DEFAULT_PROVIDER, _explainer_instance
    DEFAULT_MODEL = request.model
    DEFAULT_PROVIDER = request.provider
    _explainer_instance = None  # Force re-creation with new settings
    return {"model": DEFAULT_MODEL, "provider": DEFAULT_PROVIDER}

@app.post("/upload")
async def upload_binary(file: UploadFile = File(...)):
    try:
        # Save to a temporary file
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, file.filename)
        
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        return {"path": file_path, "filename": file.filename}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze")
async def analyze_binary(request: AnalysisRequest):
    try:
        analyzer = GhidraAnalyzer(request.binary_path)
        functions = analyzer.decompile(None)
        
        current_analysis["functions"] = functions
        current_analysis["binary_path"] = request.binary_path
        
        # Index for RAG
        rag_manager.index_functions(functions, request.binary_path)
        
        return {"functions": functions}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze_security")
async def analyze_security(request: AnalysisRequest):
    try:
        binary_hash = _get_binary_hash(request.binary_path)
        
        # ── Performance: Check response cache first ──
        if binary_hash in _response_cache["security"]:
            print(f"[CACHE HIT] Security report for {request.binary_path}")
            return _response_cache["security"][binary_hash]
        
        analyzer = GhidraAnalyzer(request.binary_path)
        
        # Use cached decompilation if available
        decompiled = current_analysis.get("functions")
        if not decompiled or current_analysis.get("binary_path") != request.binary_path:
            decompiled = analyzer.decompile(None)
            current_analysis["functions"] = decompiled
            current_analysis["binary_path"] = request.binary_path
            rag_manager.index_functions(decompiled, request.binary_path)
        
        results = analyzer.analyze_security(decompiled_functions=decompiled)
        
        # Generate Natural Language Explanation
        explainer = get_explainer()
        explanation = explainer.explain_security_report(results)
        
        results["explanation"] = explanation
        
        # ── Performance: Cache the response ──
        _response_cache["security"][binary_hash] = results
        
        return results
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/explain_program")
async def explain_program(request: AnalysisRequest):
    try:
        binary_hash = _get_binary_hash(request.binary_path)
        
        # ── Performance: Check response cache first ──
        if binary_hash in _response_cache["summary"]:
            print(f"[CACHE HIT] Program summary for {request.binary_path}")
            return {"summary": _response_cache["summary"][binary_hash]}
        
        # Check decompilation cache
        functions = current_analysis.get("functions")
        if not functions or current_analysis.get("binary_path") != request.binary_path:
             analyzer = GhidraAnalyzer(request.binary_path)
             functions = analyzer.decompile(None)
             current_analysis["functions"] = functions
             current_analysis["binary_path"] = request.binary_path
        
        explainer = get_explainer()
        summary = explainer.explain_program(functions)
        
        # ── Performance: Cache the response ──
        _response_cache["summary"][binary_hash] = summary
        
        return {"summary": summary}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/chat")
async def chat(req: ChatRequest):
    explainer = get_explainer(model=req.model, provider=req.provider)
    response = explainer.chat(req.messages)
    return {"reply": response}

@app.post("/analyze_malware")
async def analyze_malware(request: AnalysisRequest):
    """Scans decompiled code for malware behavioral indicators."""
    try:
        binary_hash = _get_binary_hash(request.binary_path)
        
        # Check cache
        if binary_hash in _response_cache["malware"]:
            print(f"[CACHE HIT] Malware report for {request.binary_path}")
            return _response_cache["malware"][binary_hash]
        
        # Get decompiled functions (reuse cache)
        functions = current_analysis.get("functions")
        if not functions or current_analysis.get("binary_path") != request.binary_path:
            analyzer = GhidraAnalyzer(request.binary_path)
            functions = analyzer.decompile(None)
            current_analysis["functions"] = functions
            current_analysis["binary_path"] = request.binary_path
        
        # Run behavioral detection
        malware_report = detect_malware_behaviors(functions)
        
        # Generate AI threat assessment if indicators found
        if malware_report["total_indicators"] > 0:
            explainer = get_explainer()
            ai_assessment = explainer.explain_malware_report(malware_report)
            malware_report["ai_assessment"] = ai_assessment
        else:
            malware_report["ai_assessment"] = "No suspicious behavioral indicators were detected in the decompiled code. The binary appears to be benign based on static behavioral analysis. Note: This does not guarantee safety — obfuscated or packed malware may evade static detection."
        
        # Cache response
        _response_cache["malware"][binary_hash] = malware_report
        
        return malware_report
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/cache")
async def clear_cache():
    """Clear all response caches."""
    _response_cache["security"].clear()
    _response_cache["summary"].clear()
    _response_cache["malware"].clear()
    return {"status": "cache cleared"}
