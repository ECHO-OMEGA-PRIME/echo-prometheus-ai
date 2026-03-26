# echo-prometheus-ai

> Autonomous security intelligence agent with multi-LLM inference, 600+ security tool integrations, attack chain management, and threat intel tracking.

## Overview

Echo Prometheus AI is the cloud brain behind Prometheus Prime, the cybersecurity operations platform running on the CHARLIE node (Kali Linux). It routes security queries through a multi-tier LLM stack (custom QLoRA-trained Prometheus model, AI Orchestrator with 29 LLM workers, and Workers AI fallback), provides access to 600+ security tool endpoints via the Prometheus Prime API, integrates Argus Panoptes surveillance capabilities, and queries security engine doctrines from the Engine Runtime. Conversations are session-based with full MITRE ATT&CK technique tracking, risk-level classification, and persistent attack chain management.

Covers 30+ security domains including penetration testing, exploitation development, red team operations, OSINT, SIGINT, digital forensics, incident response, malware analysis, and cloud/container security.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check with conversation/query/tool stats, capability summary, and integration status |
| `GET` | `/init` | Initialize database schema (6 tables + 6 indexes) |
| `POST` | `/chat` | Main conversational endpoint. Body: `{message, session_id?, context?, auto_execute?}`. Returns AI response with tool recommendations and MITRE mappings. |
| `POST` | `/tool/execute` | Execute a security tool directly. Body: `{tool_name, parameters, session_id?}` |
| `GET` | `/tools` | List all registered security tools with categories, descriptions, parameters, and risk levels |
| `POST` | `/chain/create` | Create a new attack chain. Body: `{name, target, phases[]}` |
| `POST` | `/chain/:id/advance` | Advance an attack chain to the next phase. Body: `{findings?, tools_used?}` |
| `GET` | `/chain/:id` | Get attack chain details |
| `GET` | `/chains` | List all attack chains |
| `POST` | `/finding` | Record a security finding. Body: `{finding_type, severity, title, description?, target?, evidence?, cvss_score?, cve_ids?, mitre_ids?}` |
| `GET` | `/findings` | Query security findings. Filters: `severity`, `status`, `limit` |
| `POST` | `/threat/add` | Add a threat intel indicator. Body: `{indicator_type, indicator_value, threat_score?, source?, tags?, context?}` |
| `GET` | `/threat/search` | Search threat intel. Filters: `type`, `value`, `min_score`, `limit` |
| `GET` | `/conversations` | List all conversation sessions |
| `GET` | `/conversation/:session_id` | Get full conversation history for a session |
| `GET` | `/stats` | Aggregate statistics: total queries, tools executed, conversations, findings, threat indicators |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `production` | Runtime environment label |
| `VERSION` | `1.0.0` | Version identifier |
| `PROMETHEUS_URL` | `http://192.168.1.202:8370` | Prometheus Prime API on CHARLIE node |
| `CHARLIE_NODE` | `192.168.1.202` | CHARLIE node IP address |

### Secrets

| Secret | Description |
|--------|-------------|
| `ECHO_API_KEY` | API key for inter-service authentication |
| `PROMETHEUS_MODEL_URL` | URL for custom QLoRA-trained Prometheus model (vLLM endpoint) |
| `AI_ORCHESTRATOR_URL` | URL for the multi-LLM AI Orchestrator |
| `COMMANDER_API_URL` | Commander API URL for system operations |
| `OPENROUTER_KEY` | OpenRouter API key for LLM fallback |
| `BRAVO_INFERENCE_URL` | BRAVO node inference endpoint URL |

### Bindings

| Binding | Type | Service/Resource |
|---------|------|------------------|
| `DB` | D1 Database | `echo-prometheus-ai` — conversations, queries, tool executions, threat intel, attack chains, findings |
| `CACHE` | KV Namespace | Session state and query result caching |
| `AI` | Workers AI | Fallback LLM inference |
| `BRAIN` | Service Binding | `echo-shared-brain` — broadcasts security findings and alerts |
| `ENGINES` | Service Binding | `echo-engine-runtime` — security domain engine doctrines (CYBER, PENTEST, MALWARE, DFIR) |
| `SURVEILLANCE` | Service Binding | `echo-prometheus-surveillance` — Argus Panoptes surveillance integration |
| `CHAT` | Service Binding | `echo-chat` — 14-personality AI conversation system |
| `KNOWLEDGE` | Service Binding | `echo-knowledge-forge` — security research and CVE knowledge base |

## Deployment

```bash
cd O:\ECHO_OMEGA_PRIME\WORKERS\echo-prometheus-ai
npx wrangler deploy
echo "your-key" | npx wrangler secret put ECHO_API_KEY
echo "https://model-url/v1" | npx wrangler secret put PROMETHEUS_MODEL_URL
echo "your-openrouter-key" | npx wrangler secret put OPENROUTER_KEY
```

## Architecture

Built on Hono with CORS. The LLM inference stack follows a multi-tier fallback pattern: (1) custom QLoRA-trained Prometheus model via vLLM for security-specific reasoning, (2) AI Orchestrator with 29 LLM workers for general intelligence, (3) Workers AI as the final fallback. The `/chat` endpoint classifies incoming queries to determine relevant security tools, injects tool context and surveillance capabilities into the system prompt, and returns responses with MITRE ATT&CK technique mappings. Attack chains model multi-phase security operations (reconnaissance through post-exploitation) with phase tracking and finding accumulation. The D1 schema includes 6 tables: `conversations`, `queries`, `tool_executions`, `threat_intel`, `attack_chains`, and `security_findings` with indexes on session, tool name, indicator type, severity, and chain status.
