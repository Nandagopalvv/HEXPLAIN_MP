---
description: Complete workflow for setting up, running, and using Hexplain.
---

# Hexplain Complete Workflow

This workflow covers the initialization, execution, and usage of the Hexplain binary analysis tool.

## // turbo-all

## 1. Environment Setup

### 1.1 Backend Setup
1. Ensure Java 17+ is installed (required for Ghidra).
2. Create and activate a Python virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```
3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

### 1.2 Frontend Setup
1. Navigate to the UI directory:
```bash
cd hexplain-ui
```
2. Install Node dependencies:
```bash
npm install
```

### 1.3 AI Setup (Local)
1. Ensure Ollama is installed and running.
2. Pull the Mistral model:
```bash
ollama pull mistral
```

## 2. Running the System

### 2.1 Start Local AI
```bash
ollama run mistral
```

### 2.2 Start Backend
From the root directory:
```bash
./run_backend.sh
```

### 2.3 Start Frontend
From the `hexplain-ui` directory:
```bash
npm run dev
```

## 3. Core Usage Workflows

### 3.1 CLI Analysis
To quickly analyze a binary from the terminal:
```bash
python -m src.main ./test_binary --model mistral --provider local
```

### 3.2 Web UI Workflow
1. Open your browser to the URL provided by the Vite dev server (usually `http://localhost:5173`).
2. Upload a binary using the upload zone.
3. Once decompiled, select functions from the list to view the code.
4. Use the "Explain" buttons to get AI insights.
5. Use the Chat interface for deeper queries about the binary's logic.
