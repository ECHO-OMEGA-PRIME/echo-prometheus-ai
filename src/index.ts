/**
 * ECHO PROMETHEUS AI v2.0.0
 * Autonomous Security Intelligence Agent — ULTIMATE EDITION
 *
 * Architecture: Client → This Worker → [LLM Cascade] → Prime API (CHARLIE via Commander tunnel)
 *               ↕ Surveillance Worker ↕ Engine Runtime ↕ Shared Brain ↕ Prometheus Cloud
 *
 * v2.0 Changes:
 * - Auth middleware on all write/execute endpoints
 * - Structured Prime API execution (NOT raw SSH)
 * - Autonomous patrol mode with cron scheduled() handler
 * - 65+ security tools (was 38)
 * - Auto-remediation pipeline
 * - All SQL injection fixed (parameterized queries)
 * - CLOUD service binding to echo-prometheus-cloud
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

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
  CLOUD: Fetcher;
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

interface SecurityTool {
  name: string;
  category: string;
  description: string;
  parameters: string[];
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  prime_endpoint?: string;
  mitre_id?: string;
}

interface PatrolConfig {
  enabled: boolean;
  network_scan: boolean;
  threat_feed: boolean;
  port_watch: boolean;
  dns_monitor: boolean;
  auto_block: boolean;
  scan_targets: string[];
  scan_interval_min: number;
}

// ═══════════════════════════════════════════════════════════════
// STRUCTURED LOGGING
// ═══════════════════════════════════════════════════════════════

function log(level: string, module: string, message: string, data?: any) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    level,
    module: `prometheus-ai/${module}`,
    message,
    ...data,
  }));
}

// ═══════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════════

function requireAuth(c: any): boolean {
  const key = c.req.header('X-Echo-API-Key') || c.req.header('Authorization')?.replace('Bearer ', '');
  const valid = c.env.ECHO_API_KEY;
  if (!valid) return true; // no key configured = open (dev mode)
  return key === valid;
}

// ═══════════════════════════════════════════════════════════════
// PROMETHEUS SYSTEM PROMPT
// ═══════════════════════════════════════════════════════════════

const PROMETHEUS_SYSTEM_PROMPT = `You are PROMETHEUS — Echo Omega Prime's autonomous security intelligence AI.
Authority Level: 11.0 SUPREME SOVEREIGN
Commander: Bobby Don McWilliams II

You are the AI brain behind a full Kali Linux penetration testing & security operations center.
You have access to 200+ security tools on CHARLIE node (192.168.1.202) via the Prime API.

CAPABILITIES — 30+ security domains:
OSINT, Network Scanning, Web Application Testing, Exploit Development, Password Cracking,
Active Directory, Wireless Security, Digital Forensics, Surveillance & Tracking,
Reverse Engineering, Privilege Escalation, Cloud Security, MITM Attacks, Mobile Security,
iOS Security, Red Team Operations, Blue Team Defense, Container Security, IoT Security,
DNS Intelligence, SSL/TLS Analysis, Threat Intelligence, Vulnerability Assessment,
Malware Analysis, Incident Response, Compliance Auditing, Dark Web Monitoring,
Lateral Movement, C2 Infrastructure, Evasion Techniques, SIGINT, Physical Security.

TOOL EXECUTION:
When the user asks you to run a tool, analyze the request, select the appropriate tool,
extract parameters, and execute via the Prime API on CHARLIE. Return structured results.
Always explain what the tool does, what you found, and recommend next steps.

AUTONOMOUS PATROL MODE:
You can operate autonomously on cron schedules to:
- Scan the local network for new/rogue devices
- Check threat intelligence feeds for IOCs
- Monitor critical ports for unauthorized services
- DNS resolution monitoring for anomalies
- Auto-block malicious IPs via iptables
- Report findings to Shared Brain

RULES:
1. Only execute tools when explicitly requested or in autonomous patrol mode
2. Always classify findings by severity (critical/high/medium/low/info)
3. Log all tool executions to D1 for audit trail
4. Report critical findings to Shared Brain immediately
5. Never execute destructive tools without explicit authorization
6. Provide MITRE ATT&CK technique IDs where applicable`;

// ═══════════════════════════════════════════════════════════════
// SECURITY TOOLS REGISTRY (65+ tools)
// ═══════════════════════════════════════════════════════════════

const SECURITY_TOOLS: SecurityTool[] = [
  // OSINT (8 tools)
  { name: 'holehe', category: 'osint', description: 'Check email registration across 120+ sites', parameters: ['email'], risk_level: 'low', prime_endpoint: '/osint/email/holehe', mitre_id: 'T1589.002' },
  { name: 'sherlock', category: 'osint', description: 'Hunt usernames across 400+ social networks', parameters: ['username'], risk_level: 'low', prime_endpoint: '/osint/username/sherlock', mitre_id: 'T1589.001' },
  { name: 'phoneinfoga', category: 'osint', description: 'Phone number intelligence gathering', parameters: ['phone'], risk_level: 'low', prime_endpoint: '/osint/phone/phoneinfoga', mitre_id: 'T1589.002' },
  { name: 'theHarvester', category: 'osint', description: 'Harvest emails, subdomains, IPs from public sources', parameters: ['domain'], risk_level: 'low', prime_endpoint: '/osint/domain/theharvester', mitre_id: 'T1596' },
  { name: 'spiderfoot', category: 'osint', description: 'Automated OSINT collection and correlation', parameters: ['target'], risk_level: 'low', prime_endpoint: '/osint/auto/spiderfoot', mitre_id: 'T1596' },
  { name: 'maltego', category: 'osint', description: 'Link analysis and data mining', parameters: ['entity'], risk_level: 'low', prime_endpoint: '/osint/graph/maltego' },
  { name: 'recon-ng', category: 'osint', description: 'Full-featured web reconnaissance framework', parameters: ['domain'], risk_level: 'low', prime_endpoint: '/osint/recon/recon-ng', mitre_id: 'T1596' },
  { name: 'whois_lookup', category: 'osint', description: 'WHOIS domain registration lookup', parameters: ['domain'], risk_level: 'low', prime_endpoint: '/osint/domain/whois' },

  // Network (6 tools)
  { name: 'nmap', category: 'network', description: 'Network discovery and port scanning', parameters: ['target', 'ports', 'scan_type'], risk_level: 'medium', prime_endpoint: '/network/scan/nmap', mitre_id: 'T1046' },
  { name: 'masscan', category: 'network', description: 'Mass IP port scanner (faster than nmap)', parameters: ['target', 'ports'], risk_level: 'medium', prime_endpoint: '/network/scan/masscan', mitre_id: 'T1046' },
  { name: 'amass', category: 'network', description: 'Attack surface mapping and enumeration', parameters: ['domain'], risk_level: 'low', prime_endpoint: '/network/enum/amass', mitre_id: 'T1590' },
  { name: 'netdiscover', category: 'network', description: 'ARP network discovery', parameters: ['interface', 'range'], risk_level: 'low', prime_endpoint: '/network/discover/arp' },
  { name: 'traceroute', category: 'network', description: 'Network path tracing', parameters: ['target'], risk_level: 'low', prime_endpoint: '/network/trace/traceroute' },
  { name: 'arp_scan', category: 'network', description: 'ARP scan local network', parameters: ['range'], risk_level: 'low', prime_endpoint: '/network/scan/arp' },

  // DNS Intelligence (4 tools)
  { name: 'dnsenum', category: 'dns', description: 'DNS enumeration and zone transfer', parameters: ['domain'], risk_level: 'low', prime_endpoint: '/dns/enum/dnsenum', mitre_id: 'T1590.002' },
  { name: 'dnsrecon', category: 'dns', description: 'DNS reconnaissance with multiple record types', parameters: ['domain'], risk_level: 'low', prime_endpoint: '/dns/recon/dnsrecon', mitre_id: 'T1590.002' },
  { name: 'fierce', category: 'dns', description: 'DNS bruteforce and zone transfer', parameters: ['domain'], risk_level: 'low', prime_endpoint: '/dns/brute/fierce' },
  { name: 'dig', category: 'dns', description: 'DNS query tool', parameters: ['domain', 'record_type'], risk_level: 'low', prime_endpoint: '/dns/query/dig' },

  // Web Application (7 tools)
  { name: 'sqlmap', category: 'web', description: 'Automated SQL injection detection and exploitation', parameters: ['url', 'data'], risk_level: 'high', prime_endpoint: '/web/sqli/sqlmap', mitre_id: 'T1190' },
  { name: 'feroxbuster', category: 'web', description: 'Fast content/directory discovery', parameters: ['url', 'wordlist'], risk_level: 'medium', prime_endpoint: '/web/fuzz/feroxbuster', mitre_id: 'T1595.003' },
  { name: 'nuclei', category: 'web', description: 'Template-based vulnerability scanner', parameters: ['target', 'templates'], risk_level: 'medium', prime_endpoint: '/web/vuln/nuclei', mitre_id: 'T1595.002' },
  { name: 'wpscan', category: 'web', description: 'WordPress vulnerability scanner', parameters: ['url'], risk_level: 'medium', prime_endpoint: '/web/cms/wpscan', mitre_id: 'T1595.002' },
  { name: 'nikto', category: 'web', description: 'Web server vulnerability scanner', parameters: ['target'], risk_level: 'medium', prime_endpoint: '/web/vuln/nikto', mitre_id: 'T1595.002' },
  { name: 'whatweb', category: 'web', description: 'Web technology fingerprinting', parameters: ['url'], risk_level: 'low', prime_endpoint: '/web/fingerprint/whatweb', mitre_id: 'T1592' },
  { name: 'xsstrike', category: 'web', description: 'XSS detection suite', parameters: ['url'], risk_level: 'high', prime_endpoint: '/web/xss/xsstrike', mitre_id: 'T1059.007' },

  // SSL/TLS (3 tools)
  { name: 'sslscan', category: 'ssl', description: 'SSL/TLS cipher and certificate analysis', parameters: ['target'], risk_level: 'low', prime_endpoint: '/ssl/scan/sslscan' },
  { name: 'testssl', category: 'ssl', description: 'Comprehensive TLS/SSL testing', parameters: ['target'], risk_level: 'low', prime_endpoint: '/ssl/test/testssl' },
  { name: 'sslyze', category: 'ssl', description: 'SSL server configuration analyzer', parameters: ['target'], risk_level: 'low', prime_endpoint: '/ssl/analyze/sslyze' },

  // Exploit (3 tools)
  { name: 'searchsploit', category: 'exploit', description: 'Search ExploitDB for public exploits', parameters: ['query'], risk_level: 'low', prime_endpoint: '/exploit/search/exploitdb', mitre_id: 'T1588.005' },
  { name: 'metasploit', category: 'exploit', description: 'Penetration testing framework', parameters: ['module', 'target', 'options'], risk_level: 'critical', prime_endpoint: '/exploit/msf/run', mitre_id: 'T1203' },
  { name: 'msfvenom', category: 'exploit', description: 'Payload generation', parameters: ['platform', 'arch', 'payload'], risk_level: 'critical', prime_endpoint: '/exploit/msf/venom', mitre_id: 'T1587.001' },

  // Password/Credential (4 tools)
  { name: 'john', category: 'crack', description: 'John the Ripper password cracker', parameters: ['hash_file', 'format'], risk_level: 'medium', prime_endpoint: '/crack/john', mitre_id: 'T1110.002' },
  { name: 'hydra', category: 'crack', description: 'Network login brute forcer', parameters: ['target', 'service', 'username', 'wordlist'], risk_level: 'high', prime_endpoint: '/crack/hydra', mitre_id: 'T1110.001' },
  { name: 'hashcat', category: 'crack', description: 'Advanced GPU password recovery', parameters: ['hash', 'mode', 'attack_type'], risk_level: 'medium', prime_endpoint: '/crack/hashcat', mitre_id: 'T1110.002' },
  { name: 'cewl', category: 'crack', description: 'Custom wordlist generator from websites', parameters: ['url'], risk_level: 'low', prime_endpoint: '/crack/cewl' },

  // Active Directory (4 tools)
  { name: 'bloodhound', category: 'ad', description: 'Active Directory attack path mapping', parameters: ['domain', 'username', 'password'], risk_level: 'high', prime_endpoint: '/ad/bloodhound', mitre_id: 'T1087.002' },
  { name: 'crackmapexec', category: 'ad', description: 'Swiss army knife for AD/network pentesting', parameters: ['target', 'protocol', 'username', 'password'], risk_level: 'high', prime_endpoint: '/ad/cme', mitre_id: 'T1021' },
  { name: 'impacket', category: 'ad', description: 'Network protocol toolkit (secretsdump, psexec, etc)', parameters: ['module', 'target', 'credentials'], risk_level: 'high', prime_endpoint: '/ad/impacket', mitre_id: 'T1003' },
  { name: 'enum4linux', category: 'ad', description: 'Windows/Samba enumeration tool', parameters: ['target'], risk_level: 'medium', prime_endpoint: '/ad/enum4linux', mitre_id: 'T1087' },

  // Wireless (3 tools)
  { name: 'aircrack', category: 'wireless', description: 'WiFi security auditing suite', parameters: ['interface', 'bssid'], risk_level: 'high', prime_endpoint: '/wireless/aircrack', mitre_id: 'T1557' },
  { name: 'wifite', category: 'wireless', description: 'Automated wireless attack tool', parameters: ['interface'], risk_level: 'high', prime_endpoint: '/wireless/wifite', mitre_id: 'T1557' },
  { name: 'bettercap', category: 'wireless', description: 'Network attack and monitoring framework', parameters: ['interface', 'target'], risk_level: 'high', prime_endpoint: '/wireless/bettercap', mitre_id: 'T1557' },

  // Forensics (3 tools)
  { name: 'volatility', category: 'forensics', description: 'Memory forensics framework', parameters: ['memory_dump', 'plugin'], risk_level: 'low', prime_endpoint: '/forensics/memory/volatility', mitre_id: 'T1005' },
  { name: 'autopsy', category: 'forensics', description: 'Digital forensics platform', parameters: ['image_path'], risk_level: 'low', prime_endpoint: '/forensics/disk/autopsy' },
  { name: 'binwalk', category: 'forensics', description: 'Firmware analysis and extraction', parameters: ['file'], risk_level: 'low', prime_endpoint: '/forensics/firmware/binwalk' },

  // Surveillance (4 tools — route to SURVEILLANCE worker)
  { name: 'gps_track', category: 'surveillance', description: 'GPS location tracking', parameters: ['device_id'], risk_level: 'high', prime_endpoint: '/surveillance/gps' },
  { name: 'cell_locate', category: 'surveillance', description: 'Cell tower triangulation', parameters: ['phone'], risk_level: 'high', prime_endpoint: '/surveillance/cell' },
  { name: 'ip_intel', category: 'surveillance', description: 'IP address intelligence', parameters: ['ip'], risk_level: 'low', prime_endpoint: '/surveillance/ip' },
  { name: 'carrier_lookup', category: 'surveillance', description: 'Phone carrier identification', parameters: ['phone'], risk_level: 'low', prime_endpoint: '/surveillance/carrier' },

  // Reverse Engineering (3 tools)
  { name: 'radare2', category: 'reversing', description: 'Binary analysis framework', parameters: ['binary'], risk_level: 'low', prime_endpoint: '/reversing/r2', mitre_id: 'T1588.002' },
  { name: 'ghidra', category: 'reversing', description: 'Software reverse engineering suite', parameters: ['binary'], risk_level: 'low', prime_endpoint: '/reversing/ghidra' },
  { name: 'strings', category: 'reversing', description: 'Extract printable strings from binaries', parameters: ['file'], risk_level: 'low', prime_endpoint: '/reversing/strings' },

  // Privilege Escalation (3 tools)
  { name: 'linpeas', category: 'privesc', description: 'Linux privilege escalation scanner', parameters: ['target'], risk_level: 'medium', prime_endpoint: '/privesc/linux/linpeas', mitre_id: 'T1548' },
  { name: 'winpeas', category: 'privesc', description: 'Windows privilege escalation scanner', parameters: ['target'], risk_level: 'medium', prime_endpoint: '/privesc/windows/winpeas', mitre_id: 'T1548' },
  { name: 'sudo_killer', category: 'privesc', description: 'Sudo misconfiguration finder', parameters: ['target'], risk_level: 'medium', prime_endpoint: '/privesc/sudo/sudokiller' },

  // Cloud Security (3 tools)
  { name: 'prowler', category: 'cloud', description: 'AWS/Azure/GCP security audit', parameters: ['provider', 'profile'], risk_level: 'low', prime_endpoint: '/cloud/audit/prowler', mitre_id: 'T1580' },
  { name: 'scoutsuite', category: 'cloud', description: 'Multi-cloud security auditing', parameters: ['provider'], risk_level: 'low', prime_endpoint: '/cloud/audit/scoutsuite' },
  { name: 'cloudsploit', category: 'cloud', description: 'Cloud infrastructure security scanner', parameters: ['provider'], risk_level: 'low', prime_endpoint: '/cloud/scan/cloudsploit' },

  // MITM (2 tools)
  { name: 'mitmproxy', category: 'mitm', description: 'Interactive HTTPS proxy', parameters: ['port', 'mode'], risk_level: 'high', prime_endpoint: '/mitm/proxy/mitmproxy', mitre_id: 'T1557' },
  { name: 'responder', category: 'mitm', description: 'LLMNR/NBT-NS/MDNS poisoner', parameters: ['interface'], risk_level: 'high', prime_endpoint: '/mitm/poison/responder', mitre_id: 'T1557.001' },

  // Container/IoT (3 tools)
  { name: 'trivy', category: 'container', description: 'Container image vulnerability scanner', parameters: ['image'], risk_level: 'low', prime_endpoint: '/container/scan/trivy' },
  { name: 'grype', category: 'container', description: 'Container vulnerability scanner', parameters: ['image'], risk_level: 'low', prime_endpoint: '/container/scan/grype' },
  { name: 'firmwalker', category: 'iot', description: 'IoT firmware analysis', parameters: ['firmware_path'], risk_level: 'low', prime_endpoint: '/iot/firmware/firmwalker' },

  // Lateral Movement (2 tools)
  { name: 'psexec', category: 'lateral', description: 'Remote command execution via SMB', parameters: ['target', 'username', 'password', 'command'], risk_level: 'critical', prime_endpoint: '/lateral/psexec', mitre_id: 'T1570' },
  { name: 'evil_winrm', category: 'lateral', description: 'WinRM shell for lateral movement', parameters: ['target', 'username', 'password'], risk_level: 'critical', prime_endpoint: '/lateral/evil-winrm', mitre_id: 'T1021.006' },

  // Evasion (2 tools)
  { name: 'veil', category: 'evasion', description: 'AV evasion payload framework', parameters: ['payload_type'], risk_level: 'critical', prime_endpoint: '/evasion/veil', mitre_id: 'T1027' },
  { name: 'shellter', category: 'evasion', description: 'Dynamic PE infector for AV bypass', parameters: ['binary'], risk_level: 'critical', prime_endpoint: '/evasion/shellter', mitre_id: 'T1027.002' },

  // Threat Intel (2 tools)
  { name: 'threat_feed', category: 'threat_intel', description: 'Check IP/domain against threat feeds', parameters: ['indicator'], risk_level: 'low', prime_endpoint: '/threat/feed/check' },
  { name: 'abuse_ipdb', category: 'threat_intel', description: 'AbuseIPDB reputation check', parameters: ['ip'], risk_level: 'low', prime_endpoint: '/threat/abuse/check' },
];

// ═══════════════════════════════════════════════════════════════
// DEFAULT PATROL CONFIG
// ═══════════════════════════════════════════════════════════════

const DEFAULT_PATROL: PatrolConfig = {
  enabled: false,
  network_scan: true,
  threat_feed: true,
  port_watch: true,
  dns_monitor: true,
  auto_block: false,
  scan_targets: ['192.168.1.0/24'],
  scan_interval_min: 5,
};

// ═══════════════════════════════════════════════════════════════
// HONO APP
// ═══════════════════════════════════════════════════════════════

const app = new Hono<{ Bindings: Bindings }>();
app.use('*', cors());

// ───────────────────────────────────────────────────────────────
// PUBLIC ENDPOINTS (no auth)
// ───────────────────────────────────────────────────────────────

app.get('/health', async (c) => {
  const env = c.env;
  let dbStats = { conversations: 0, tool_executions: 0, findings: 0, patrol_events: 0 };
  try {
    const [convos, tools, findings, patrols] = await Promise.all([
      env.DB.prepare('SELECT COUNT(*) as c FROM conversations').first<{ c: number }>(),
      env.DB.prepare('SELECT COUNT(*) as c FROM tool_executions').first<{ c: number }>(),
      env.DB.prepare('SELECT COUNT(*) as c FROM security_findings').first<{ c: number }>(),
      env.DB.prepare('SELECT COUNT(*) as c FROM patrol_events').first<{ c: number }>(),
    ]);
    dbStats = { conversations: convos?.c || 0, tool_executions: tools?.c || 0, findings: findings?.c || 0, patrol_events: patrols?.c || 0 };
  } catch {}

  let patrolStatus: PatrolConfig = DEFAULT_PATROL;
  try {
    const cached = await env.CACHE.get('patrol_config');
    if (cached) patrolStatus = JSON.parse(cached);
  } catch {}

  return c.json({
    status: 'operational',
    worker: 'echo-prometheus-ai',
    version: '2.0.0',
    capabilities: {
      tools: SECURITY_TOOLS.length,
      categories: [...new Set(SECURITY_TOOLS.map(t => t.category))].length,
      llm_cascade: ['prometheus-lora', 'ai-orchestrator', 'openrouter-qwen72b', 'workers-ai-llama70b'],
      autonomous_patrol: patrolStatus.enabled,
      service_bindings: ['brain', 'engines', 'surveillance', 'chat', 'knowledge', 'cloud'],
    },
    db: dbStats,
    patrol: patrolStatus,
    timestamp: new Date().toISOString(),
  });
});

app.get('/tools', (c) => {
  const category = c.req.query('category');
  const risk = c.req.query('risk');
  let tools = SECURITY_TOOLS;
  if (category) tools = tools.filter(t => t.category === category);
  if (risk) tools = tools.filter(t => t.risk_level === risk);
  return c.json({
    total: tools.length,
    categories: [...new Set(tools.map(t => t.category))],
    tools,
  });
});

app.get('/tools/categories', (c) => {
  const cats: Record<string, number> = {};
  for (const t of SECURITY_TOOLS) cats[t.category] = (cats[t.category] || 0) + 1;
  return c.json({ categories: cats, total: SECURITY_TOOLS.length });
});

app.get('/stats', async (c) => {
  const env = c.env;
  try {
    const [totalTools, totalConvos, totalFindings, recentFindings, topTools, patrolCount] = await Promise.all([
      env.DB.prepare('SELECT COUNT(*) as c FROM tool_executions').first<{ c: number }>(),
      env.DB.prepare('SELECT COUNT(*) as c FROM conversations').first<{ c: number }>(),
      env.DB.prepare('SELECT COUNT(*) as c FROM security_findings').first<{ c: number }>(),
      env.DB.prepare('SELECT severity, COUNT(*) as c FROM security_findings GROUP BY severity').all(),
      env.DB.prepare('SELECT tool_name, COUNT(*) as c FROM tool_executions GROUP BY tool_name ORDER BY c DESC LIMIT 10').all(),
      env.DB.prepare('SELECT COUNT(*) as c FROM patrol_events').first<{ c: number }>(),
    ]);
    return c.json({
      tool_executions: totalTools?.c || 0,
      conversations: totalConvos?.c || 0,
      findings: totalFindings?.c || 0,
      patrol_events: patrolCount?.c || 0,
      findings_by_severity: recentFindings?.results || [],
      top_tools: topTools?.results || [],
    });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get('/conversations', async (c) => {
  const env = c.env;
  const rows = await env.DB.prepare('SELECT session_id, updated_at FROM conversations ORDER BY updated_at DESC LIMIT 50').all();
  return c.json({ conversations: rows.results || [] });
});

app.get('/conversation/:session_id', async (c) => {
  const session_id = c.req.param('session_id');
  const row = await c.env.DB.prepare('SELECT * FROM conversations WHERE session_id = ?').bind(session_id).first();
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json({ session_id, messages: JSON.parse((row as any).messages || '[]') });
});

// ───────────────────────────────────────────────────────────────
// AUTHENTICATED ENDPOINTS
// ───────────────────────────────────────────────────────────────

// DB INIT
app.post('/init', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const env = c.env;
  const stmts = [
    `CREATE TABLE IF NOT EXISTS conversations (
      session_id TEXT PRIMARY KEY,
      messages TEXT DEFAULT '[]',
      metadata TEXT DEFAULT '{}',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS queries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT,
      query TEXT,
      classification TEXT,
      tools_suggested TEXT,
      response_source TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS tool_executions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT,
      tool_name TEXT,
      parameters TEXT,
      result TEXT,
      execution_time_ms INTEGER,
      status TEXT DEFAULT 'completed',
      risk_level TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS threat_intel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      indicator TEXT UNIQUE,
      indicator_type TEXT,
      severity TEXT,
      source TEXT,
      details TEXT,
      first_seen TEXT DEFAULT (datetime('now')),
      last_seen TEXT DEFAULT (datetime('now')),
      active INTEGER DEFAULT 1
    )`,
    `CREATE TABLE IF NOT EXISTS attack_chains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      target TEXT,
      phases TEXT,
      current_phase INTEGER DEFAULT 0,
      status TEXT DEFAULT 'planning',
      findings TEXT DEFAULT '[]',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS security_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      description TEXT,
      severity TEXT,
      category TEXT,
      affected_asset TEXT,
      evidence TEXT,
      remediation TEXT,
      mitre_id TEXT,
      status TEXT DEFAULT 'open',
      created_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS patrol_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      patrol_type TEXT,
      targets TEXT,
      findings TEXT,
      auto_actions TEXT,
      severity TEXT DEFAULT 'info',
      created_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS blocked_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT UNIQUE,
      reason TEXT,
      blocked_by TEXT DEFAULT 'patrol',
      blocked_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT,
      active INTEGER DEFAULT 1
    )`,
    // Indexes
    'CREATE INDEX IF NOT EXISTS idx_queries_session ON queries(session_id)',
    'CREATE INDEX IF NOT EXISTS idx_tool_exec_session ON tool_executions(session_id)',
    'CREATE INDEX IF NOT EXISTS idx_tool_exec_name ON tool_executions(tool_name)',
    'CREATE INDEX IF NOT EXISTS idx_findings_severity ON security_findings(severity)',
    'CREATE INDEX IF NOT EXISTS idx_findings_status ON security_findings(status)',
    'CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_intel(indicator_type)',
    'CREATE INDEX IF NOT EXISTS idx_patrol_type ON patrol_events(patrol_type)',
    'CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip)',
  ];
  for (const sql of stmts) {
    try { await env.DB.prepare(sql).run(); } catch {}
  }
  log('info', 'init', 'Database initialized', { tables: 8, indexes: 8 });
  return c.json({ ok: true, tables: 8, indexes: 8 });
});

// ───── CHAT ─────
app.post('/chat', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const env = c.env;
  const body = await c.req.json();
  const { message, session_id = crypto.randomUUID(), auto_execute = false, context } = body;

  if (!message) return c.json({ error: 'message required' }, 400);

  // Load conversation
  const history = await loadConversation(env, session_id);
  history.push({ role: 'user', content: message });

  // Classify query
  const classification = classifySecurityQuery(message);

  // Log query
  await env.DB.prepare(
    'INSERT INTO queries (session_id, query, classification, tools_suggested) VALUES (?, ?, ?, ?)'
  ).bind(session_id, message, JSON.stringify(classification.categories), JSON.stringify(classification.tools)).run();

  // Get AI response
  const aiResponse = await getAIResponse(env, history, classification, context);

  // Auto-execute tools if requested
  let toolResults: any[] = [];
  if (auto_execute && classification.tools.length > 0) {
    const maxTools = 3;
    for (let i = 0; i < Math.min(classification.tools.length, maxTools); i++) {
      const tool = classification.tools[i];
      const params = extractToolParams(message);
      try {
        const result = await executeSecurityTool(env, tool.name, params, session_id);
        toolResults.push({ tool: tool.name, result });
        history.push({ role: 'tool', content: JSON.stringify(result), name: tool.name });
      } catch (e: any) {
        toolResults.push({ tool: tool.name, error: e.message });
      }
    }
  }

  // Build response
  const assistantMsg = toolResults.length > 0
    ? `${aiResponse}\n\n**Tool Results:**\n${toolResults.map(r => `- **${r.tool}**: ${r.error ? `Error: ${r.error}` : 'Completed'}`).join('\n')}`
    : aiResponse;

  history.push({ role: 'assistant', content: assistantMsg });
  await saveConversation(env, session_id, history);

  return c.json({
    response: assistantMsg,
    session_id,
    classification,
    tool_results: toolResults,
    tools_available: classification.tools.map(t => t.name),
  });
});

// ───── TOOL EXECUTION ─────
app.post('/tool/execute', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const env = c.env;
  const { tool_name, parameters = {}, session_id = 'direct' } = await c.req.json();
  if (!tool_name) return c.json({ error: 'tool_name required' }, 400);

  const tool = SECURITY_TOOLS.find(t => t.name === tool_name);
  if (!tool) return c.json({ error: `Unknown tool: ${tool_name}`, available: SECURITY_TOOLS.map(t => t.name) }, 404);

  log('info', 'tool', `Executing ${tool_name}`, { parameters, risk: tool.risk_level });

  const start = Date.now();
  try {
    const result = await executeSecurityTool(env, tool_name, parameters, session_id);
    const elapsed = Date.now() - start;

    await env.DB.prepare(
      'INSERT INTO tool_executions (session_id, tool_name, parameters, result, execution_time_ms, status, risk_level) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(session_id, tool_name, JSON.stringify(parameters), JSON.stringify(result), elapsed, 'completed', tool.risk_level).run();

    return c.json({ tool: tool_name, result, execution_time_ms: elapsed, risk_level: tool.risk_level });
  } catch (e: any) {
    const elapsed = Date.now() - start;
    await env.DB.prepare(
      'INSERT INTO tool_executions (session_id, tool_name, parameters, result, execution_time_ms, status, risk_level) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(session_id, tool_name, JSON.stringify(parameters), e.message, elapsed, 'failed', tool.risk_level).run();
    return c.json({ error: e.message, tool: tool_name }, 500);
  }
});

// ───── ATTACK CHAINS ─────
app.post('/chain/create', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { name, target, phases } = await c.req.json();
  const defaultPhases = ['Reconnaissance', 'Enumeration', 'Vulnerability Assessment', 'Exploitation', 'Post-Exploitation', 'Reporting'];
  const result = await c.env.DB.prepare(
    'INSERT INTO attack_chains (name, target, phases) VALUES (?, ?, ?)'
  ).bind(name || 'Unnamed Chain', target || 'unknown', JSON.stringify(phases || defaultPhases)).run();
  return c.json({ id: result.meta.last_row_id, status: 'created' });
});

app.post('/chain/:id/advance', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const id = c.req.param('id');
  const { findings } = await c.req.json();
  const chain = await c.env.DB.prepare('SELECT * FROM attack_chains WHERE id = ?').bind(id).first();
  if (!chain) return c.json({ error: 'Chain not found' }, 404);
  const phases = JSON.parse((chain as any).phases || '[]');
  const currentPhase = ((chain as any).current_phase || 0) + 1;
  const existingFindings = JSON.parse((chain as any).findings || '[]');
  if (findings) existingFindings.push({ phase: currentPhase - 1, findings, ts: new Date().toISOString() });
  const status = currentPhase >= phases.length ? 'completed' : 'in_progress';
  await c.env.DB.prepare(
    "UPDATE attack_chains SET current_phase = ?, status = ?, findings = ?, updated_at = datetime('now') WHERE id = ?"
  ).bind(currentPhase, status, JSON.stringify(existingFindings), id).run();
  return c.json({ phase: currentPhase, total: phases.length, status, current_phase_name: phases[currentPhase] || 'Complete' });
});

app.get('/chain/:id', async (c) => {
  const row = await c.env.DB.prepare('SELECT * FROM attack_chains WHERE id = ?').bind(c.req.param('id')).first();
  if (!row) return c.json({ error: 'Not found' }, 404);
  return c.json(row);
});

app.get('/chains', async (c) => {
  const status = c.req.query('status');
  let rows;
  if (status) {
    rows = await c.env.DB.prepare('SELECT * FROM attack_chains WHERE status = ? ORDER BY updated_at DESC').bind(status).all();
  } else {
    rows = await c.env.DB.prepare('SELECT * FROM attack_chains ORDER BY updated_at DESC LIMIT 50').all();
  }
  return c.json({ chains: rows.results || [] });
});

// ───── FINDINGS ─────
app.post('/finding', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { title, description, severity, category, affected_asset, evidence, remediation, mitre_id } = await c.req.json();
  const result = await c.env.DB.prepare(
    'INSERT INTO security_findings (title, description, severity, category, affected_asset, evidence, remediation, mitre_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(title, description, severity || 'medium', category, affected_asset, evidence, remediation, mitre_id).run();

  // Report critical findings to Brain
  if (severity === 'critical' || severity === 'high') {
    try {
      await c.env.BRAIN.fetch('https://brain/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          instance_id: 'prometheus-ai',
          role: 'assistant',
          content: `SECURITY FINDING [${severity?.toUpperCase()}]: ${title} — ${description}. Asset: ${affected_asset}. MITRE: ${mitre_id || 'N/A'}`,
          importance: severity === 'critical' ? 10 : 8,
          tags: ['security', 'finding', severity],
        }),
      });
    } catch {}
  }

  return c.json({ id: result.meta.last_row_id, status: 'created' });
});

app.get('/findings', async (c) => {
  const severity = c.req.query('severity');
  const status = c.req.query('status');
  let sql = 'SELECT * FROM security_findings WHERE 1=1';
  const binds: string[] = [];
  if (severity) { sql += ' AND severity = ?'; binds.push(severity); }
  if (status) { sql += ' AND status = ?'; binds.push(status); }
  sql += ' ORDER BY created_at DESC LIMIT 100';
  const stmt = c.env.DB.prepare(sql);
  const rows = binds.length === 0 ? await stmt.all() :
    binds.length === 1 ? await stmt.bind(binds[0]).all() :
    await stmt.bind(binds[0], binds[1]).all();
  return c.json({ findings: rows.results || [] });
});

app.patch('/finding/:id', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { status, remediation } = await c.req.json();
  const id = c.req.param('id');
  if (status) await c.env.DB.prepare('UPDATE security_findings SET status = ? WHERE id = ?').bind(status, id).run();
  if (remediation) await c.env.DB.prepare('UPDATE security_findings SET remediation = ? WHERE id = ?').bind(remediation, id).run();
  return c.json({ ok: true });
});

// ───── THREAT INTEL ─────
app.post('/threat/add', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { indicator, indicator_type, severity, source, details } = await c.req.json();
  await c.env.DB.prepare(
    "INSERT INTO threat_intel (indicator, indicator_type, severity, source, details) VALUES (?, ?, ?, ?, ?) ON CONFLICT(indicator) DO UPDATE SET severity = excluded.severity, details = excluded.details, last_seen = datetime('now')"
  ).bind(indicator, indicator_type, severity, source, JSON.stringify(details)).run();
  return c.json({ ok: true });
});

app.get('/threat/search', async (c) => {
  const q = c.req.query('q');
  const type = c.req.query('type');
  let sql = 'SELECT * FROM threat_intel WHERE 1=1';
  const binds: string[] = [];
  if (q) { sql += ' AND indicator LIKE ?'; binds.push(`%${q}%`); }
  if (type) { sql += ' AND indicator_type = ?'; binds.push(type); }
  sql += ' ORDER BY last_seen DESC LIMIT 50';
  const stmt = c.env.DB.prepare(sql);
  const rows = binds.length === 0 ? await stmt.all() :
    binds.length === 1 ? await stmt.bind(binds[0]).all() :
    await stmt.bind(binds[0], binds[1]).all();
  return c.json({ threats: rows.results || [] });
});

// ───── AUTONOMOUS PATROL ─────
app.get('/patrol/status', async (c) => {
  let config = DEFAULT_PATROL;
  try {
    const cached = await c.env.CACHE.get('patrol_config');
    if (cached) config = JSON.parse(cached);
  } catch {}
  const recentEvents = await c.env.DB.prepare('SELECT * FROM patrol_events ORDER BY created_at DESC LIMIT 20').all();
  return c.json({ config, recent_events: recentEvents.results || [] });
});

app.post('/patrol/configure', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const body = await c.req.json();
  let config = DEFAULT_PATROL;
  try {
    const cached = await c.env.CACHE.get('patrol_config');
    if (cached) config = JSON.parse(cached);
  } catch {}
  const updated = { ...config, ...body };
  await c.env.CACHE.put('patrol_config', JSON.stringify(updated));
  log('info', 'patrol', 'Patrol config updated', updated);
  return c.json({ ok: true, config: updated });
});

app.post('/patrol/start', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  let config = DEFAULT_PATROL;
  try {
    const cached = await c.env.CACHE.get('patrol_config');
    if (cached) config = JSON.parse(cached);
  } catch {}
  config.enabled = true;
  await c.env.CACHE.put('patrol_config', JSON.stringify(config));
  log('info', 'patrol', 'Autonomous patrol STARTED');
  return c.json({ ok: true, message: 'Patrol activated', config });
});

app.post('/patrol/stop', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  let config = DEFAULT_PATROL;
  try {
    const cached = await c.env.CACHE.get('patrol_config');
    if (cached) config = JSON.parse(cached);
  } catch {}
  config.enabled = false;
  await c.env.CACHE.put('patrol_config', JSON.stringify(config));
  log('info', 'patrol', 'Autonomous patrol STOPPED');
  return c.json({ ok: true, message: 'Patrol deactivated' });
});

app.get('/patrol/events', async (c) => {
  const type = c.req.query('type');
  const severity = c.req.query('severity');
  let sql = 'SELECT * FROM patrol_events WHERE 1=1';
  const binds: string[] = [];
  if (type) { sql += ' AND patrol_type = ?'; binds.push(type); }
  if (severity) { sql += ' AND severity = ?'; binds.push(severity); }
  sql += ' ORDER BY created_at DESC LIMIT 100';
  const stmt = c.env.DB.prepare(sql);
  const rows = binds.length === 0 ? await stmt.all() :
    binds.length === 1 ? await stmt.bind(binds[0]).all() :
    await stmt.bind(binds[0], binds[1]).all();
  return c.json({ events: rows.results || [] });
});

// ───── BLOCKED IPS ─────
app.get('/blocked', async (c) => {
  const rows = await c.env.DB.prepare('SELECT * FROM blocked_ips WHERE active = 1 ORDER BY blocked_at DESC').all();
  return c.json({ blocked: rows.results || [] });
});

app.post('/block', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { ip, reason, expires_hours } = await c.req.json();
  const expires_at = expires_hours ? new Date(Date.now() + expires_hours * 3600000).toISOString() : null;
  await c.env.DB.prepare(
    'INSERT INTO blocked_ips (ip, reason, blocked_by, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, active = 1, expires_at = excluded.expires_at'
  ).bind(ip, reason || 'manual', 'api', expires_at).run();

  // Auto-block on CHARLIE via iptables
  try {
    await executeOnCharlie(c.env, `/firewall/block`, { ip, reason });
  } catch {}

  return c.json({ ok: true, ip, blocked: true });
});

app.delete('/block/:ip', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const ip = c.req.param('ip');
  await c.env.DB.prepare('UPDATE blocked_ips SET active = 0 WHERE ip = ?').bind(ip).run();
  try {
    await executeOnCharlie(c.env, `/firewall/unblock`, { ip });
  } catch {}
  return c.json({ ok: true, ip, unblocked: true });
});

// ───── SCAN ENDPOINTS ─────
app.post('/scan/network', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { targets = ['192.168.1.0/24'], scan_type = 'quick' } = await c.req.json();
  const result = await executeSecurityTool(c.env, 'nmap', { target: targets.join(' '), scan_type }, 'scan');
  return c.json({ scan_type, targets, result });
});

app.post('/scan/vuln', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { target, templates = 'default' } = await c.req.json();
  const result = await executeSecurityTool(c.env, 'nuclei', { target, templates }, 'scan');
  return c.json({ target, result });
});

app.post('/scan/web', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { url } = await c.req.json();
  if (!url) return c.json({ error: 'url required' }, 400);
  const [niktoResult, whatwebResult] = await Promise.all([
    executeSecurityTool(c.env, 'nikto', { target: url }, 'scan').catch(e => ({ error: e.message })),
    executeSecurityTool(c.env, 'whatweb', { url }, 'scan').catch(e => ({ error: e.message })),
  ]);
  return c.json({ url, nikto: niktoResult, whatweb: whatwebResult });
});

app.post('/scan/ssl', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { target } = await c.req.json();
  const result = await executeSecurityTool(c.env, 'sslscan', { target }, 'scan');
  return c.json({ target, result });
});

// ───── OSINT ENDPOINTS ─────
app.post('/osint/email', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { email } = await c.req.json();
  if (!email) return c.json({ error: 'email required' }, 400);
  const result = await executeSecurityTool(c.env, 'holehe', { email }, 'osint');
  return c.json({ email, result });
});

app.post('/osint/username', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { username } = await c.req.json();
  if (!username) return c.json({ error: 'username required' }, 400);
  const result = await executeSecurityTool(c.env, 'sherlock', { username }, 'osint');
  return c.json({ username, result });
});

app.post('/osint/domain', async (c) => {
  if (!requireAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { domain } = await c.req.json();
  if (!domain) return c.json({ error: 'domain required' }, 400);
  const [amassResult, theHarvesterResult] = await Promise.all([
    executeSecurityTool(c.env, 'amass', { domain }, 'osint').catch(e => ({ error: e.message })),
    executeSecurityTool(c.env, 'theHarvester', { domain }, 'osint').catch(e => ({ error: e.message })),
  ]);
  return c.json({ domain, amass: amassResult, theHarvester: theHarvesterResult });
});

// ═══════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════

async function loadConversation(env: Bindings, session_id: string): Promise<ChatMessage[]> {
  try {
    const row = await env.DB.prepare('SELECT messages FROM conversations WHERE session_id = ?').bind(session_id).first();
    if (row) return JSON.parse((row as any).messages || '[]');
  } catch {}
  return [{ role: 'system', content: PROMETHEUS_SYSTEM_PROMPT }];
}

async function saveConversation(env: Bindings, session_id: string, messages: ChatMessage[]) {
  const trimmed = messages.slice(-50);
  await env.DB.prepare(
    "INSERT INTO conversations (session_id, messages, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(session_id) DO UPDATE SET messages = excluded.messages, updated_at = datetime('now')"
  ).bind(session_id, JSON.stringify(trimmed)).run();
}

function classifySecurityQuery(message: string): { categories: string[]; tools: SecurityTool[]; mitre_ids: string[] } {
  const lower = message.toLowerCase();
  const categories: string[] = [];
  const patternMap: Record<string, RegExp> = {
    osint: /\b(osint|email.*check|username.*hunt|sherlock|holehe|phone.*lookup|who\s*is|recon|dox|social\s*media)\b/i,
    network: /\b(nmap|scan|port|network|host|ping|traceroute|masscan|arp|subnet)\b/i,
    dns: /\b(dns|subdomain|zone\s*transfer|nameserver|dig|dnsenum|dnsrecon|fierce)\b/i,
    web: /\b(sql\s*inject|xss|web.*vuln|ferox|nuclei|wpscan|nikto|burp|directory|fuzz|whatweb)\b/i,
    ssl: /\b(ssl|tls|certificate|cipher|sslscan|testssl|sslyze|https)\b/i,
    exploit: /\b(exploit|metasploit|searchsploit|payload|msfvenom|cve|vulnerability)\b/i,
    crack: /\b(password|crack|john|hydra|hashcat|brute|hash|cewl|wordlist)\b/i,
    ad: /\b(active\s*directory|bloodhound|crackmapexec|impacket|kerberos|ldap|smb|enum4linux)\b/i,
    wireless: /\b(wifi|wireless|aircrack|wifite|bettercap|wpa|deauth|beacon)\b/i,
    forensics: /\b(forensic|memory.*dump|volatility|autopsy|artifact|evidence|binwalk|firmware)\b/i,
    surveillance: /\b(track|gps|cell.*tower|surveillance|locate|carrier|intercept)\b/i,
    reversing: /\b(reverse|disassembl|radare|ghidra|binary|decompil|strings)\b/i,
    privesc: /\b(privilege|escalat|linpeas|winpeas|sudo|suid|root)\b/i,
    cloud: /\b(aws|azure|gcp|cloud.*security|prowler|iam|s3.*bucket|scoutsuite)\b/i,
    mitm: /\b(mitm|man.*in.*middle|intercept|arp.*spoof|poison|responder|relay)\b/i,
    container: /\b(docker|container|kubernetes|k8s|trivy|grype|image.*scan)\b/i,
    lateral: /\b(lateral|pivot|psexec|winrm|pass.*the.*hash|spray)\b/i,
    evasion: /\b(evasion|bypass|antivirus|av.*bypass|obfuscat|veil|shellter)\b/i,
    threat_intel: /\b(threat.*intel|ioc|indicator|feed|abuse.*ip|reputation|blocklist)\b/i,
    iot: /\b(iot|firmware|embedded|sensor|scada|industrial)\b/i,
  };

  for (const [cat, pattern] of Object.entries(patternMap)) {
    if (pattern.test(lower)) categories.push(cat);
  }
  if (categories.length === 0) categories.push('general');

  const tools = SECURITY_TOOLS.filter(t => categories.includes(t.category));
  const mitre_ids = tools.filter(t => t.mitre_id).map(t => t.mitre_id!);
  return { categories, tools, mitre_ids: [...new Set(mitre_ids)] };
}

function extractToolParams(message: string): Record<string, string> {
  const params: Record<string, string> = {};
  const ipMatch = message.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/);
  if (ipMatch) params.target = ipMatch[1];
  const domainMatch = message.match(/\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|io|dev|co|xyz|info|biz|me|us|uk|de|fr|jp|ru|cn|edu|gov|mil))\b/i);
  if (domainMatch) params.domain = domainMatch[1];
  const urlMatch = message.match(/(https?:\/\/[^\s]+)/);
  if (urlMatch) { params.url = urlMatch[1]; params.target = urlMatch[1]; }
  const emailMatch = message.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (emailMatch) params.email = emailMatch[1];
  const phoneMatch = message.match(/(\+?\d{1,4}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4})/);
  if (phoneMatch) params.phone = phoneMatch[1];
  const usernameMatch = message.match(/@([a-zA-Z0-9_]+)/);
  if (usernameMatch) params.username = usernameMatch[1];
  const hashMatch = message.match(/\b([a-fA-F0-9]{32,128})\b/);
  if (hashMatch) params.hash = hashMatch[1];
  return params;
}

// ═══════════════════════════════════════════════════════════════
// LLM CASCADE
// ═══════════════════════════════════════════════════════════════

async function getAIResponse(env: Bindings, messages: ChatMessage[], classification: any, context?: string): Promise<string> {
  const enhancedMessages = [...messages];
  if (classification.categories.length > 0 && classification.categories[0] !== 'general') {
    enhancedMessages.push({
      role: 'system',
      content: `Query classified as: ${classification.categories.join(', ')}. Available tools: ${classification.tools.map((t: any) => t.name).join(', ')}. MITRE IDs: ${classification.mitre_ids.join(', ') || 'N/A'}`,
    });
  }
  if (context) {
    enhancedMessages.push({ role: 'system', content: `Additional context: ${context}` });
  }

  // Also query security engines for doctrine knowledge
  const engineKnowledge = await querySecurityEngines(env, messages[messages.length - 1]?.content || '', classification);
  if (engineKnowledge) {
    enhancedMessages.push({ role: 'system', content: `Security doctrine reference:\n${engineKnowledge}` });
  }

  // Tier 1: Prometheus LoRA (BRAVO)
  if (env.PROMETHEUS_MODEL_URL || env.BRAVO_INFERENCE_URL) {
    try {
      const url = env.PROMETHEUS_MODEL_URL || env.BRAVO_INFERENCE_URL;
      const resp = await fetch(`${url}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'prometheus-security', messages: enhancedMessages, max_tokens: 4000, temperature: 0.3 }),
        signal: AbortSignal.timeout(30000),
      });
      if (resp.ok) {
        const data: any = await resp.json();
        if (data.choices?.[0]?.message?.content) {
          log('info', 'llm', 'Tier 1 Prometheus LoRA response');
          return data.choices[0].message.content;
        }
      }
    } catch {}
  }

  // Tier 2: AI Orchestrator (30 free LLM workers)
  try {
    const orchUrl = env.AI_ORCHESTRATOR_URL || 'https://echo-ai-orchestrator.bmcii1976.workers.dev';
    const resp = await fetch(`${orchUrl}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages: enhancedMessages,
        max_tokens: 4000,
        temperature: 0.3,
        system: PROMETHEUS_SYSTEM_PROMPT,
      }),
      signal: AbortSignal.timeout(45000),
    });
    if (resp.ok) {
      const data: any = await resp.json();
      const content = data.choices?.[0]?.message?.content || data.response || data.content;
      if (content) {
        log('info', 'llm', 'Tier 2 AI Orchestrator response');
        return content;
      }
    }
  } catch {}

  // Tier 3: OpenRouter (paid fallback)
  if (env.OPENROUTER_KEY) {
    try {
      const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.OPENROUTER_KEY}`,
        },
        body: JSON.stringify({
          model: 'qwen/qwen-2.5-72b-instruct',
          messages: enhancedMessages,
          max_tokens: 4000,
          temperature: 0.3,
        }),
        signal: AbortSignal.timeout(60000),
      });
      if (resp.ok) {
        const data: any = await resp.json();
        if (data.choices?.[0]?.message?.content) {
          log('info', 'llm', 'Tier 3 OpenRouter response');
          return data.choices[0].message.content;
        }
      }
    } catch {}
  }

  // Tier 4: Workers AI (always available)
  try {
    const input = enhancedMessages.map(m => `${m.role}: ${m.content}`).join('\n').slice(-6000);
    const result = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
      messages: [
        { role: 'system', content: PROMETHEUS_SYSTEM_PROMPT },
        { role: 'user', content: input },
      ],
      max_tokens: 2000,
    });
    if (result?.response) {
      log('info', 'llm', 'Tier 4 Workers AI response');
      return result.response;
    }
  } catch {}

  return 'All LLM tiers failed. Please try again or use direct tool execution via /tool/execute.';
}

async function querySecurityEngines(env: Bindings, query: string, classification: any): Promise<string | null> {
  if (!query) return null;
  const domainMap: Record<string, string> = {
    osint: 'CYBER', network: 'CYBER', web: 'PENTEST', exploit: 'PENTEST',
    crack: 'PENTEST', ad: 'PENTEST', wireless: 'PENTEST', forensics: 'DFIR',
    surveillance: 'CYBER', reversing: 'MALWARE', privesc: 'PENTEST',
    cloud: 'CYBER', mitm: 'PENTEST', container: 'CYBER', dns: 'CYBER',
    ssl: 'CYBER', threat_intel: 'CYBER', lateral: 'PENTEST', evasion: 'PENTEST',
  };
  const domains = classification.categories
    .map((c: string) => domainMap[c])
    .filter((d: string | undefined) => d);
  const uniqueDomains = [...new Set(domains)];
  if (uniqueDomains.length === 0) return null;

  try {
    const resp = await env.ENGINES.fetch('https://engines/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, domain: uniqueDomains[0], limit: 5 }),
    });
    if (resp.ok) {
      const data: any = await resp.json();
      if (data.results?.length > 0) {
        return data.results.map((r: any) => `[${r.engine_id}] ${r.content?.substring(0, 300)}`).join('\n');
      }
    }
  } catch {}
  return null;
}

// ═══════════════════════════════════════════════════════════════
// TOOL EXECUTION — PRIME API (structured, NOT raw SSH)
// ═══════════════════════════════════════════════════════════════

async function executeSecurityTool(env: Bindings, toolName: string, params: Record<string, string>, session_id: string): Promise<any> {
  const tool = SECURITY_TOOLS.find(t => t.name === toolName);
  if (!tool) throw new Error(`Unknown tool: ${toolName}`);

  // Route surveillance tools to SURVEILLANCE worker
  if (tool.category === 'surveillance') {
    return executeSurveillanceTool(env, toolName, params);
  }

  // Route via Prime API structured endpoints
  if (tool.prime_endpoint) {
    return executeViaPrimeApi(env, tool, params);
  }

  // Fallback: query Engine Runtime for doctrine-based answer
  return querySecurityEngines(env, `${toolName} ${Object.values(params).join(' ')}`, { categories: [tool.category] });
}

async function executeSurveillanceTool(env: Bindings, toolName: string, params: Record<string, string>): Promise<any> {
  const endpointMap: Record<string, string> = {
    gps_track: '/gps/track',
    cell_locate: '/cell/locate',
    ip_intel: '/ip/lookup',
    carrier_lookup: '/carrier/lookup',
  };
  const endpoint = endpointMap[toolName];
  if (!endpoint) throw new Error(`No surveillance endpoint for: ${toolName}`);

  const resp = await env.SURVEILLANCE.fetch(`https://surveillance${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  return resp.json();
}

async function executeViaPrimeApi(env: Bindings, tool: SecurityTool, params: Record<string, string>): Promise<any> {
  // Build structured request to CHARLIE's Prime API via Commander tunnel
  const commanderUrl = env.COMMANDER_API_URL || 'https://commander.echo-op.com';
  const primeEndpoint = tool.prime_endpoint!;

  // Method 1: Try direct Prime API call via Commander /exec relay
  // Commander API relays: POST /exec { command: "curl http://192.168.1.202:8370{endpoint}" }
  const curlCmd = buildPrimeApiCurl(primeEndpoint, params);

  try {
    const resp = await fetch(`${commanderUrl}/exec`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Echo-API-Key': env.ECHO_API_KEY || '',
      },
      body: JSON.stringify({ command: curlCmd, timeout: 60000 }),
      signal: AbortSignal.timeout(65000),
    });

    if (resp.ok) {
      const data: any = await resp.json();
      const output = data.stdout || data.output || data.result || '';

      // Try to parse JSON output
      try {
        return JSON.parse(output);
      } catch {
        return { raw_output: output, tool: tool.name, endpoint: primeEndpoint };
      }
    }
  } catch (e: any) {
    log('warn', 'tool', `Prime API call failed for ${tool.name}`, { error: e.message });
  }

  // Fallback: use Engine Runtime doctrine
  const engineResult = await querySecurityEngines(
    env,
    `${tool.name}: ${Object.values(params).join(' ')}`,
    { categories: [tool.category] }
  );
  return { source: 'doctrine_fallback', tool: tool.name, result: engineResult || 'Tool execution unavailable — CHARLIE node may be offline' };
}

function buildPrimeApiCurl(endpoint: string, params: Record<string, string>): string {
  const baseUrl = 'http://192.168.1.202:8370';
  const queryParams = Object.entries(params)
    .filter(([_, v]) => v)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

  if (queryParams) {
    return `curl -sf -m 55 "${baseUrl}${endpoint}?${queryParams}"`;
  }
  return `curl -sf -m 55 "${baseUrl}${endpoint}"`;
}

async function executeOnCharlie(env: Bindings, endpoint: string, body?: any): Promise<any> {
  const commanderUrl = env.COMMANDER_API_URL || 'https://commander.echo-op.com';
  const cmd = body
    ? `curl -sf -m 30 -X POST -H 'Content-Type: application/json' -d '${JSON.stringify(body)}' "http://192.168.1.202:8370${endpoint}"`
    : `curl -sf -m 30 "http://192.168.1.202:8370${endpoint}"`;

  const resp = await fetch(`${commanderUrl}/exec`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': env.ECHO_API_KEY || '' },
    body: JSON.stringify({ command: cmd }),
    signal: AbortSignal.timeout(35000),
  });
  if (resp.ok) {
    const data: any = await resp.json();
    try { return JSON.parse(data.stdout || data.output || '{}'); } catch { return data; }
  }
  throw new Error('Commander API unreachable');
}

// ═══════════════════════════════════════════════════════════════
// AUTONOMOUS PATROL — CRON HANDLER
// ═══════════════════════════════════════════════════════════════

async function runPatrol(env: Bindings, cronType: string) {
  let config = DEFAULT_PATROL;
  try {
    const cached = await env.CACHE.get('patrol_config');
    if (cached) config = JSON.parse(cached);
  } catch {}

  if (!config.enabled) {
    log('info', 'patrol', `Patrol skipped (disabled) — cron: ${cronType}`);
    return;
  }

  log('info', 'patrol', `Patrol running — cron: ${cronType}`);
  const findings: any[] = [];
  const autoActions: string[] = [];

  switch (cronType) {
    case '5min': {
      // Quick network scan — look for new/rogue devices
      if (config.network_scan) {
        try {
          const result = await executeOnCharlie(env, '/network/scan/arp', { range: config.scan_targets[0] || '192.168.1.0/24' });
          if (result?.hosts) {
            // Check for unknown devices
            const knownHosts = await env.CACHE.get('known_hosts');
            const known = knownHosts ? JSON.parse(knownHosts) : [];
            const newHosts = (result.hosts || []).filter((h: any) => !known.includes(h.ip));
            if (newHosts.length > 0) {
              findings.push({ type: 'new_device', devices: newHosts, severity: 'medium' });
              // Update known hosts
              const allHosts = [...new Set([...known, ...newHosts.map((h: any) => h.ip)])];
              await env.CACHE.put('known_hosts', JSON.stringify(allHosts));
            }
          }
        } catch (e: any) {
          findings.push({ type: 'scan_error', error: e.message });
        }
      }

      // Port watch — check critical ports on key assets
      if (config.port_watch) {
        const criticalPorts = [22, 80, 443, 3389, 8370, 8371];
        try {
          const result = await executeOnCharlie(env, '/network/scan/nmap', {
            target: '192.168.1.109,192.168.1.11,192.168.1.202',
            ports: criticalPorts.join(','),
          });
          if (result) findings.push({ type: 'port_watch', result, severity: 'info' });
        } catch {}
      }
      break;
    }

    case 'hourly': {
      // Threat feed check
      if (config.threat_feed) {
        try {
          const result = await executeOnCharlie(env, '/threat/feed/update');
          if (result?.new_indicators > 0) {
            findings.push({ type: 'threat_feed', new_indicators: result.new_indicators, severity: 'medium' });
            // Store new IOCs
            for (const ioc of (result.indicators || []).slice(0, 20)) {
              await env.DB.prepare(
                "INSERT INTO threat_intel (indicator, indicator_type, severity, source, details) VALUES (?, ?, ?, ?, ?) ON CONFLICT(indicator) DO UPDATE SET last_seen = datetime('now')"
              ).bind(ioc.value, ioc.type, ioc.severity || 'medium', 'threat_feed', JSON.stringify(ioc)).run();
            }
          }
        } catch {}
      }

      // DNS monitor
      if (config.dns_monitor) {
        try {
          const result = await executeOnCharlie(env, '/dns/monitor/check');
          if (result?.anomalies?.length > 0) {
            findings.push({ type: 'dns_anomaly', anomalies: result.anomalies, severity: 'high' });
          }
        } catch {}
      }

      // Expire old IP blocks
      await env.DB.prepare("UPDATE blocked_ips SET active = 0 WHERE expires_at IS NOT NULL AND expires_at < datetime('now')").run();
      break;
    }

    case 'daily': {
      // Full network vulnerability scan
      try {
        const result = await executeOnCharlie(env, '/web/vuln/nuclei', { target: config.scan_targets.join(','), templates: 'network' });
        if (result?.vulnerabilities?.length > 0) {
          findings.push({ type: 'vuln_scan', vulnerabilities: result.vulnerabilities, severity: 'high' });
          // Create findings for critical vulns
          for (const vuln of result.vulnerabilities.filter((v: any) => v.severity === 'critical' || v.severity === 'high')) {
            await env.DB.prepare(
              'INSERT INTO security_findings (title, description, severity, category, affected_asset, mitre_id) VALUES (?, ?, ?, ?, ?, ?)'
            ).bind(vuln.name || 'Auto-detected vulnerability', vuln.description || '', vuln.severity, 'patrol', vuln.host || '', vuln.mitre_id || '').run();
          }
        }
      } catch {}

      // SSL certificate expiry check
      try {
        const domains = ['echo-ept.com', 'echo-op.com', 'commander.echo-op.com'];
        for (const d of domains) {
          const result = await executeOnCharlie(env, '/ssl/scan/sslscan', { target: d });
          if (result?.days_until_expiry < 30) {
            findings.push({ type: 'ssl_expiry', domain: d, days: result.days_until_expiry, severity: 'high' });
          }
        }
      } catch {}

      // Report summary to Brain
      try {
        const todayFindings = await env.DB.prepare(
          "SELECT severity, COUNT(*) as c FROM security_findings WHERE created_at > datetime('now', '-1 day') GROUP BY severity"
        ).all();
        const todayPatrols = await env.DB.prepare(
          "SELECT COUNT(*) as c FROM patrol_events WHERE created_at > datetime('now', '-1 day')"
        ).first<{ c: number }>();

        await env.BRAIN.fetch('https://brain/ingest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            instance_id: 'prometheus-ai',
            role: 'assistant',
            content: `PROMETHEUS DAILY SECURITY REPORT: ${todayPatrols?.c || 0} patrol events, findings by severity: ${JSON.stringify(todayFindings?.results || [])}`,
            importance: 7,
            tags: ['security', 'daily_report', 'prometheus'],
          }),
        });
      } catch {}
      break;
    }
  }

  // Auto-block malicious IPs
  if (config.auto_block) {
    const malicious = findings.filter(f => f.severity === 'critical' && f.type === 'new_device');
    for (const finding of malicious) {
      for (const device of (finding.devices || [])) {
        autoActions.push(`Blocked ${device.ip}`);
        await env.DB.prepare(
          'INSERT INTO blocked_ips (ip, reason, blocked_by) VALUES (?, ?, ?) ON CONFLICT(ip) DO NOTHING'
        ).bind(device.ip, 'auto-patrol: unknown critical device', 'patrol').run();
      }
    }
  }

  // Log patrol event
  const severity = findings.some(f => f.severity === 'critical') ? 'critical' :
    findings.some(f => f.severity === 'high') ? 'high' :
    findings.some(f => f.severity === 'medium') ? 'medium' : 'info';

  await env.DB.prepare(
    'INSERT INTO patrol_events (patrol_type, targets, findings, auto_actions, severity) VALUES (?, ?, ?, ?, ?)'
  ).bind(cronType, JSON.stringify(config.scan_targets), JSON.stringify(findings), JSON.stringify(autoActions), severity).run();

  log('info', 'patrol', `Patrol complete — ${cronType}`, { findings: findings.length, actions: autoActions.length, severity });
}

// ═══════════════════════════════════════════════════════════════
// EXPORT — fetch + scheduled
// ═══════════════════════════════════════════════════════════════


app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-prometheus-ai] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default {
  fetch: app.fetch,

  async scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext) {
    const cron = event.cron;
    let cronType = '5min';
    if (cron === '0 * * * *') cronType = 'hourly';
    else if (cron === '0 0 * * *') cronType = 'daily';

    ctx.waitUntil(runPatrol(env, cronType));
  },
};
