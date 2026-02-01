from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import shutil
import os
import tempfile
from pathlib import Path
from typing import List, Dict, Optional

from src.analyzer import GhidraAnalyzer
from src.explainer import CodeExplainer

app = FastAPI()

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

class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]
    model: str = "mistral"
    provider: str = "local"

class AnalysisRequest(BaseModel):
    binary_path: str

@app.get("/health")
def health():
    return {"status": "ok"}

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
        # Decompile all
        functions = analyzer.decompile(None) # None = attempt to find main/entry
        
        # If empty, maybe try to force decompile all? 
        # For now, let's stick to the current logic in Analyzer
        
        current_analysis["functions"] = functions
        current_analysis["binary_path"] = request.binary_path
        
        return {"functions": functions}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze_security")
async def analyze_security(request: AnalysisRequest):
    try:
        analyzer = GhidraAnalyzer(request.binary_path)
        results = analyzer.analyze_security()
        
        # Generate Natural Language Explanation
        # We use default provider for now (likely local in this setup)
        explainer = CodeExplainer(provider="local", model="mistral") 
        explanation = explainer.explain_security_report(results)
        
        results["explanation"] = explanation
        
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/explain_program")
async def explain_program(request: AnalysisRequest):
    try:
        # Check cache first
        functions = current_analysis.get("functions")
        
        # If not in cache or path different, re-analyze (or error if we want strictness)
        # For robustnes, let's re-analyze if needed
        if not functions or current_analysis.get("binary_path") != request.binary_path:
             analyzer = GhidraAnalyzer(request.binary_path)
             functions = analyzer.decompile(None)
             current_analysis["functions"] = functions
             current_analysis["binary_path"] = request.binary_path
        
        explainer = CodeExplainer(provider="local", model="mistral")
        summary = explainer.explain_program(functions)
        
        return {"summary": summary}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/chat")
async def chat(req: ChatRequest):
    # Construct context from current analysis if available
    # We'll prepend a system message if it's the start of convo
    
    explainer = CodeExplainer(provider=req.provider, model=req.model)
    
    # Check if context is needed
    # We could inject the current function code if the user is asking about it
    # For now, we rely on the client sending the conversation history
    
    response = explainer.chat(req.messages)
    return {"reply": response}
