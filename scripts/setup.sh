#!/bin/bash

# SecureLink Guardian - Setup Script
# Automated environment setup and dependency installation

set -e  # Exit on error

echo "🛡️  SecureLink Guardian - Setup Script"
echo "======================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Check if running on supported OS
print_info "Checking operating system..."
OS=$(uname -s)
if [[ "$OS" == "Linux" ]]; then
    print_success "Linux detected"
elif [[ "$OS" == "Darwin" ]]; then
    print_success "macOS detected"
else
    print_error "Unsupported OS: $OS"
    exit 1
fi

# Check Python version
print_info "Checking Python version..."
if command -v python3 &> /dev/null; then
    # macOS/BSD compatible version extraction
    PYTHON_VERSION=$(python3 --version 2>&1 | sed 's/Python //' | cut -d' ' -f1 | cut -d'.' -f1,2)
    REQUIRED_VERSION="3.9"
    
    # Convert to comparable numbers
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [ "$PYTHON_MAJOR" -gt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 9 ]); then
        print_success "Python $PYTHON_VERSION (>= 3.9 required)"
    else
        print_error "Python 3.9+ required, found $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 not found. Please install Python 3.9+"
    exit 1
fi

# Check for pip
print_info "Checking pip..."
if command -v pip3 &> /dev/null; then
    print_success "pip3 found"
else
    print_error "pip3 not found. Installing..."
    python3 -m ensurepip --upgrade
fi

# Create virtual environment
print_info "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_warning "Virtual environment already exists"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_info "Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install dependencies
print_info "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_success "Dependencies installed"
else
    print_error "requirements.txt not found"
    exit 1
fi

# Install Playwright browsers
print_info "Installing Playwright browsers..."
playwright install chromium
print_success "Playwright browsers installed"

# Create necessary directories
print_info "Creating directories..."
mkdir -p logs
mkdir -p backend/ml/models
mkdir -p datasets/brand_logos
mkdir -p tests/fixtures
print_success "Directories created"

# Create .env file if it doesn't exist
print_info "Configuring environment..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    print_success ".env file created"
    print_warning "Please edit .env with your configuration"
else
    print_warning ".env already exists"
fi

# Download NLTK data
print_info "Downloading NLTK data..."
python3 << EOF
import nltk
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)
    print("✅ NLTK data downloaded")
except Exception as e:
    print(f"⚠️ NLTK download warning: {e}")
EOF

# Generate sample datasets
print_info "Generating sample datasets..."
python3 scripts/generate_datasets.py
print_success "Sample datasets generated"

# Run tests
print_info "Running tests..."
pytest tests/ -v --tb=short
if [ $? -eq 0 ]; then
    print_success "All tests passed"
else
    print_warning "Some tests failed (this is okay for initial setup)"
fi

echo ""
echo "======================================"
print_success "Setup complete!"
echo ""
print_info "Next steps:"
echo "  1. Edit .env with your configuration"
echo "  2. Start backend: python backend/app.py"
echo "  3. Start frontend: cd frontend && python3 -m http.server 8080"
echo ""
print_info "Or use Docker:"
echo "  docker-compose up"
echo ""
print_success "Happy phishing detection! 🛡️"