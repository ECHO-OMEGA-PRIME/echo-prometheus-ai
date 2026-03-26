-- ═══════════════════════════════════════════════════════════════
-- echo-prometheus-ai | D1 Database: echo-prometheus-ai
-- Idempotent schema — safe to run multiple times
-- ═══════════════════════════════════════════════════════════════

DROP TABLE IF EXISTS security_findings;
DROP TABLE IF EXISTS attack_chains;
DROP TABLE IF EXISTS threat_intel;
DROP TABLE IF EXISTS tool_executions;
DROP TABLE IF EXISTS queries;
DROP TABLE IF EXISTS conversations;

CREATE TABLE conversations (
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
);

CREATE TABLE queries (
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
);

CREATE TABLE tool_executions (
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
);

CREATE TABLE threat_intel (
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
);

CREATE TABLE attack_chains (
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
);

CREATE TABLE security_findings (
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
);

CREATE INDEX idx_queries_session ON queries(session_id);
CREATE INDEX idx_tools_session ON tool_executions(session_id);
CREATE INDEX idx_tools_name ON tool_executions(tool_name);
CREATE INDEX idx_threat_type ON threat_intel(indicator_type);
CREATE INDEX idx_findings_severity ON security_findings(severity);
CREATE INDEX idx_chains_status ON attack_chains(status);
