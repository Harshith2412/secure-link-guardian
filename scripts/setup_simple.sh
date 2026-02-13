#!/bin/bash

# SecureLink Guardian - Simple Setup Script (macOS Compatible)
# Simplified version that works on macOS and Linux

set -e

echo "🛡️  SecureLink Guardian - Setup"
echo "================================"
echo ""

# Check Python
echo "Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.9+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✅ Python $PYTHON_VERSION found"
echo ""

# Create virtual environment
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip -q

# Install dependencies
echo "Installing dependencies (this may take a few minutes)..."
pip install -r requirements.txt -q
echo "✅ Dependencies installed"
echo ""

# Install Playwright browsers
echo "Installing Playwright browsers..."
playwright install chromium
echo "✅ Playwright installed"
echo ""

# Create directories
echo "Creating directories..."
mkdir -p logs
mkdir -p backend/ml/models
mkdir -p datasets/brand_logos
mkdir -p tests/fixtures
echo "✅ Directories created"
echo ""

# Create .env
echo "Configuring environment..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✅ .env created"
else
    echo "✅ .env already exists"
fi
echo ""

# Download NLTK data
echo "Downloading NLTK data..."
python3 << 'EOF'
import nltk
import warnings
warnings.filterwarnings('ignore')
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)
    print("✅ NLTK data downloaded")
except Exception as e:
    print(f"⚠️  NLTK download warning: {e}")
EOF
echo ""

# Generate datasets
echo "Generating datasets..."
python3 scripts/generate_datasets.py
echo ""

# Run tests
echo "Running tests..."
pytest tests/ -v --tb=short || echo "⚠️  Some tests failed (this is okay for initial setup)"
echo ""

echo "================================"
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Start backend:  python backend/app.py"
echo "  2. Start frontend: cd frontend && python3 -m http.server 8080"
echo ""
echo "Or use quick start:"
echo "  ./scripts/run_dev.sh"
echo ""
echo "Happy phishing detection! 🛡️"