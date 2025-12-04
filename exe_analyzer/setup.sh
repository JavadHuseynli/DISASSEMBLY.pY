#!/bin/bash

# EXE Analyzer Setup Script

echo "=========================================="
echo "EXE Analyzer - Setup Script"
echo "=========================================="
echo ""

# Check Python version
echo "[1/4] Checking Python version..."
python3 --version

if [ $? -ne 0 ]; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

echo ""

# Create virtual environment (optional)
echo "[2/4] Creating virtual environment (optional)..."
read -p "Do you want to create a virtual environment? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 -m venv venv
    source venv/bin/activate
    echo "Virtual environment created and activated"
fi

echo ""

# Install dependencies
echo "[3/4] Installing dependencies..."
pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "Error: Failed to install dependencies"
    exit 1
fi

echo ""

# Test installation
echo "[4/4] Testing installation..."
python3 -c "import pefile; import capstone; import dnfile; print('All dependencies installed successfully!')"

if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "Setup complete!"
    echo "=========================================="
    echo ""
    echo "To run the application:"
    echo "  python3 main.py"
    echo ""
else
    echo "Warning: Some dependencies may not be properly installed"
fi
