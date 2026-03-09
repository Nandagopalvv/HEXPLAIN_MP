# Hexplain

Hexplain reverses binaries and explains them using AI.

## Features
- **Ghidra Powered**: Uses Ghidra's decompiler via `pyghidra`.
- **AI Explanations**: Supports OpenAI or Local Models (LLaMA 3.2 / Ollama).
- **Security Analysis**: Automated vulnerability scanning with NVD CVE matching.
- **RAG-Powered Chat**: Context-aware AI assistant using ChromaDB embeddings.
- **Web Interface**: Modern React UI with downloadable reports.
- **CLI**: Classic command line tool is still available.
- **Response Caching**: Instant results on repeat analysis of the same binary.

## Prerequisites
- Python 3.10+
- Java 17+ (for Ghidra)
- Ghidra Installation
- **Node.js 18+** (for Web UI)
- **Ollama** (for local AI)

## Quick Start

### 1. Setup Backend
```bash
# Run the helper script (Recommended)
./run_backend.sh

# Or Manual Setup:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn src.server:app --reload --host 0.0.0.0 --port 8000
```

### 2. Setup Frontend
```bash
# From project root (recommended):
npm run dev

# Or from hexplain-ui directory:
cd hexplain-ui
npm install
npm run dev
```

### 3. Setup Local AI (LLaMA 3.2)
Ensure Ollama is running with the LLaMA 3.2 model (2 GB, fits fully in GPU):
```bash
ollama pull llama3.2
ollama run llama3.2
```

> **Note:** You can also use other models like `mistral`, `phi3:mini`, or `qwen2.5:3b`.
> Change the default model via the `/settings` API endpoint or by setting the `HEXPLAIN_MODEL` environment variable.

## CLI Usage
```bash
python -m src.main ./test_binary --model llama3.2 --provider local
```

## Performance Tips
- **Use a GPU**: LLaMA 3.2 (2 GB) fits entirely in a 4 GB GPU for ~3-4x faster inference.
- **Response Caching**: Security reports and program summaries are cached per binary — repeat requests are instant.
- **Parallel CVE Checks**: NVD API lookups run in parallel for faster security analysis.
- **Kill stale servers**: If port 8000 is in use, run `kill $(lsof -t -i:8000)` before starting.
