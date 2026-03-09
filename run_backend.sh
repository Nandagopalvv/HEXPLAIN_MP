#!/bin/bash
set -e

# Change to the directory where the script is located
cd "$(dirname "$0")"

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "Virtual environment not found. Please create one with:"
    echo "python3 -m venv venv"
    echo "source venv/bin/activate"
    echo "pip install -r requirements.txt"
    exit 1
fi

echo "Starting Hexplain Backend..."
exec uvicorn src.server:app --reload --host 0.0.0.0 --port 8000
