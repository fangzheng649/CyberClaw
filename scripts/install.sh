#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo "[CyberClaw] Installing dependencies..."

# Python dependencies
echo "[CyberClaw] Installing Python dependencies..."
cd "$ROOT_DIR/src/cyberclaw_core"
pip install -e .

cd "$ROOT_DIR/server"
pip install -r requirements.txt

# Node.js dependencies
echo "[CyberClaw] Installing Node.js dependencies..."
cd "$ROOT_DIR/ui/cyberclaw-hud"
npm install

echo "[CyberClaw] Installation complete! Run scripts/start.sh to start."
