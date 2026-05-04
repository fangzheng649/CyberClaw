# CyberClaw Development Guide

## Project Overview
CyberClaw is an IoT security automation platform based on OpenClaw framework.

## Architecture
- Backend: FastAPI (Python 3.10+) on port 8000
- Frontend: Express + Vite on port 3001
- MCP Servers: FastMCP (stdio protocol)
- Shared Library: `src/cyberclaw_core/`

## Commands
- Start backend: `cd D:/臻荣/CyberClaw && python -m uvicorn server.main:app --reload --port 8000`
- Start frontend: `cd ui/cyberclaw-hud && npm run dev`
- Install shared lib: `cd src/cyberclaw_core && pip install -e .`
- One-click start: `bash scripts/start.sh`

## Directory Convention
- `mcp-servers/` — 12 MCP servers (CyberClaw naming, not netclaw naming)
- `src/cyberclaw_core/` — shared Python library
- `server/` — FastAPI backend
- `ui/cyberclaw-hud/` — Three.js 3D HUD + chat interface
- `workspace/skills/` — skill definitions
- `config/` — OpenClaw configuration
- `lab/` — GNS3 lab configurations

## Naming
MCP server names follow task_plan.md: nmap-scan, device-config, simulation, syslog-collector, snmp-collector, cve-intel, security-baseline, flow-analyzer, traffic-analyzer, auto-response, config-audit, attack-timeline.
