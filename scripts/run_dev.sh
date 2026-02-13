#!/bin/bash

# SecureLink Guardian - Development Server Script
# Start backend and frontend in development mode

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

echo "🛡️  SecureLink Guardian - Development Mode"
echo "=========================================="
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_error "Virtual environment not found!"
    print_info "Run './scripts/setup.sh' first"
    exit 1
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate

# Check if .env exists
if [ ! -f ".env" ]; then
    print_warning ".env not found, creating from .env.example..."
    cp .env.example .env
    print_info "Edit .env with your configuration"
fi

# Create necessary directories
mkdir -p logs
mkdir -p backend/ml/models

# Function to cleanup on exit
cleanup() {
    print_info "Shutting down servers..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    print_success "Servers stopped"
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Start backend server
print_info "Starting backend server..."
python backend/app.py &
BACKEND_PID=$!

# Wait for backend to start
sleep 2

# Check if backend is running
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    print_error "Backend failed to start"
    exit 1
fi

print_success "Backend started (PID: $BACKEND_PID)"
print_info "Backend URL: http://localhost:5000"

# Start frontend server
print_info "Starting frontend server..."
cd frontend
python3 -m http.server 8080 > /dev/null 2>&1 &
FRONTEND_PID=$!
cd ..

# Wait for frontend to start
sleep 1

# Check if frontend is running
if ! kill -0 $FRONTEND_PID 2>/dev/null; then
    print_error "Frontend failed to start"
    kill $BACKEND_PID 2>/dev/null || true
    exit 1
fi

print_success "Frontend started (PID: $FRONTEND_PID)"
print_info "Frontend URL: http://localhost:8080"

echo ""
echo "=========================================="
print_success "Development servers running!"
echo ""
print_info "Access the application:"
echo "  Frontend: http://localhost:8080"
echo "  Demo:     http://localhost:8080/demo.html"
echo "  Backend:  http://localhost:5000/api/v1/health"
echo ""
print_info "Press Ctrl+C to stop servers"
echo "=========================================="
echo ""

# Keep script running
wait $BACKEND_PID $FRONTEND_PID