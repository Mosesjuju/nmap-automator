#!/bin/bash
# Setup and run Nmap Automator in a Python virtual environment

set -e

VENV_DIR=".venv"

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "Virtual environment created at $VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Upgrade pip and install requirements
pip install --upgrade pip
pip install -r requirements.txt

# Run Nmap Automator
python -m nmap_automator "$@"
