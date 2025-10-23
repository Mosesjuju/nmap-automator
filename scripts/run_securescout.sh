#!/bin/bash
# SecureScout Launcher with Virtual Environment Auto-Activation
# This script automatically activates the virtual environment and runs SecureScout

# Navigate to project root (parent of scripts directory)
cd "$(dirname "$0")/.."

# Check if virtual environment exists
if [[ -d ".venv" ]]; then
    echo "🔧 Activating SecureScout virtual environment..."
    source .venv/bin/activate
    python scripts/securescout.py "$@"
else
    echo "⚠️  Virtual environment not found. Running with system Python..."
    echo "💡 For best results, run: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements-fixed.txt"
    python3 scripts/securescout.py "$@"
fi