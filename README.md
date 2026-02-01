# Hexplain

Hexplain reverses binaries and explains them using AI.

## Features
- **Ghidra Powered**: Uses Ghidra's decompiler via `pyghidra`.
- **AI Explanations**: Supports OpenAI or Local Models (Mistral/Ollama).
- **Web Interface**: Modern React UI for easy interaction.
- **CLI**: Classic command line tool is still available.

## Prerequisites
- Python 3.10+
- Java 17+ (for Ghidra)
- Ghidra Installation
- **Node.js 18+** (for Web UI)
- **Ollama** (optional, for local AI)

## Quick Start

### 1. Setup Backend
```bash
# Install dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start Server
uvicorn src.server:app --reload
```

### 2. Setup Frontend
```bash
cd hexplain-ui
npm install
npm run dev
```

### 3. Setup Local AI (Mistral)
If using local AI, ensure your inference server (e.g. Ollama) is running on port 11434.
```bash
ollama run mistral
```

## CLI Usage
```bash
python -m src.main ./test_binary --model mistral --provider local
```
