# CLAUDE.md — CyberClaw Project

## Project
IoT security automation platform: Sense → Detect → Shield → Review. Based on OpenClaw + FastMCP.

## Tech Stack
Python 3.10+ / FastAPI / FastMCP / Pydantic 2 / Express + Vite / Three.js / WebSocket

## Commands (Windows)
```bash
pip install -r server/requirements.txt && cd src/cyberclaw_core && pip install -e .   # install
python -m uvicorn server.main:app --reload --port 8000                                # backend
cd ui/cyberclaw-hud && npm run dev                                                     # frontend
```
Do NOT use `bash scripts/start.sh` — it breaks in WSL. Use two terminals instead.

## Directory Map
```
mcp-servers/{name}/server.py  — 12 MCP servers (FastMCP, stdio)
src/cyberclaw_core/            — shared lib: security_models, mcp_base, toon/, gait_logger
server/                        — FastAPI backend (api/, services/, websocket/, models/)
ui/cyberclaw-hud/              — Three.js 3D HUD + chat interface (Vite + Express proxy)
config/openclaw.json           — registers all 12 MCP servers
```

## 12 MCP Server Names (DO NOT rename)
nmap-scan · device-config · simulation · syslog-collector · snmp-collector · cve-intel · security-baseline · flow-analyzer · traffic-analyzer · auto-response · config-audit · attack-timeline

Reused from netclaw: syslog-collector←syslog-mcp, snmp-collector←snmptrap-mcp, flow-analyzer←ipfix-mcp, simulation←gns3-mcp-server, device-config←gnmi-mcp.

## Rules
- CyberClaw naming only. Never reference netclaw names in new code.
- Server launch: `python -m uvicorn server.main:app` from project root (package import, NOT `cd server && uvicorn main:app`).
- Frontend proxies /api and /ws to FastAPI :8000. Dev mode via vite.config.js, production via server.js.
- Mock data lives in `server/services/`. When real MCP servers are ready, swap data source only — keep API contracts.
- New MCP servers must use `from cyberclaw_core.mcp_base import create_mcp_server`. See `mcp-servers/_template/`.
- Security events use 5-state FSM: secure → scanning → vulnerable → attacked → isolated. Defined in `cyberclaw_core/security_models.py`.
- Three-tier permission: read-only / write-with-confirmation / prohibited.
