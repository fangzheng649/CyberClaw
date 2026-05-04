# CyberClaw Agent Instructions

## Workflow
Follow the GAIT (Gather, Analyze, Intervene, Track) workflow:
1. Gather data from MCP servers
2. Analyze using security knowledge base
3. Intervene with human-approved actions
4. Track all actions for audit

## IoT Constraints
- Scanning limited to authorized network segments only
- Never execute destructive operations on physical devices
- Always confirm before network configuration changes
- Log all actions for compliance audit

## Security Rules
- Three-tier permission: read / write-with-confirm / prohibited
- TOON serialization for token optimization
- Session tracking for cost management
