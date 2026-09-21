#!/bin/bash

# AEGIS Startup Script
# This script starts both the backend and frontend servers

echo "🛡️  Starting AEGIS - AI Enforcement & Governance Infrastructure System"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.12 or higher."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18 or higher."
    exit 1
fi

echo "${BLUE}📦 Checking dependencies...${NC}"

# Check backend dependencies
if [ ! -d "backend/venv" ] && [ ! -f "backend/.venv/bin/activate" ]; then
    echo "⚠️  Backend virtual environment not found. Installing dependencies..."
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    cd ..
fi

# Check frontend dependencies
if [ ! -d "frontend/node_modules" ]; then
    echo "⚠️  Frontend dependencies not found. Installing..."
    cd frontend
    npm install
    cd ..
fi

echo ""
echo "${GREEN}✅ Dependencies ready${NC}"
echo ""

# Start backend
echo "${BLUE}🚀 Starting Backend (FastAPI)...${NC}"
cd backend/src/aegis/api
export PYTHONPATH=$PYTHONPATH:$(pwd)/src
python main.py &
BACKEND_PID=$!
cd ../../../..

# Wait for backend to start
sleep 3

# Start frontend
echo "${BLUE}🚀 Starting Frontend (Vite)...${NC}"
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

# Wait for frontend to start
sleep 3

echo ""
echo "${GREEN}✅ AEGIS is running!${NC}"
echo ""
echo "📊 Access the application:"
echo "   Frontend: http://localhost:5173"
echo "   Backend API: http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all servers"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "${BLUE}🛑 Stopping AEGIS...${NC}"
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    echo "${GREEN}✅ AEGIS stopped${NC}"
    exit 0
}

# Trap Ctrl+C
trap cleanup INT

# Wait for processes
wait
