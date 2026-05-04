#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo "[CyberClaw] Starting from $ROOT_DIR"

# Install shared library if needed
if ! python3 -c "import cyberclaw_core" 2>/dev/null; then
  echo "[CyberClaw] Installing cyberclaw_core..."
  cd "$ROOT_DIR/src/cyberclaw_core" && pip install -e . -q
fi

# Start FastAPI backend in background
echo "[CyberClaw] Starting FastAPI backend on port 8000..."
cd "$ROOT_DIR"
python3 -m uvicorn server.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo "[CyberClaw] Backend PID: $BACKEND_PID"

# Wait for backend to be ready (with retry)
for i in $(seq 1 10); do
  if curl -s http://localhost:8000/api/topology > /dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -s http://localhost:8000/api/topology > /dev/null 2>&1; then
  echo "[CyberClaw] ERROR: Backend failed to start"
  kill $BACKEND_PID 2>/dev/null
  exit 1
fi
echo "[CyberClaw] Backend ready"

# Start frontend dev server
echo "[CyberClaw] Starting frontend dev server on port 3001..."
cd "$ROOT_DIR/ui/cyberclaw-hud"
npx vite --host --port 3001 &
FRONTEND_PID=$!
echo "[CyberClaw] Frontend PID: $FRONTEND_PID"

echo ""
echo "[CyberClaw] ============================================"
echo "[CyberClaw] 3D HUD:     http://localhost:3001"
echo "[CyberClaw] Chat:       http://localhost:3001/chat/"
echo "[CyberClaw] API docs:   http://localhost:8000/docs"
echo "[CyberClaw] Backend:    http://localhost:8000"
echo "[CyberClaw] ============================================"
echo ""
echo "[CyberClaw] Press Ctrl+C to stop all services"

cleanup() {
  echo "[CyberClaw] Shutting down..."
  kill $FRONTEND_PID 2>/dev/null
  kill $BACKEND_PID 2>/dev/null
  exit 0
}
trap cleanup SIGINT SIGTERM

wait
