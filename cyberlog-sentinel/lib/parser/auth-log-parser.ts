import type { EventType, LogEvent, Outcome, Severity } from '@/types/log-event';

const MONTHS: Record<string, number> = {
  Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,
  Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11,
};

function parseISO(ts: string): Date | null {
  const m = ts.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  return new Date(+m[1], +m[2]-1, +m[3], +m[4], +m[5], +m[6]);
}

function parseSyslog(ts: string, now: Date): Date | null {
  const m = ts.match(/^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  const mon = MONTHS[m[1]];
  if (mon === undefined) return null;
  const yr = (mon === 11 && now.getMonth() === 0) ? now.getFullYear()-1 : now.getFullYear();
  return new Date(yr, mon, +m[2], +m[3], +m[4], +m[5]);
}

function parseApache(ts: string): Date | null {
  const m = ts.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  const mon = MONTHS[m[2]];
  if (mon === undefined) return null;
  return new Date(+m[3], mon, +m[1], +m[4], +m[5], +m[6]);
}

export function parseTimestamp(month: string, day: string, time: string, now: Date = new Date()): Date {
  return parseSyslog(`${month} ${day} ${time}`, now) ?? now;
}

const IP_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

function extractSourceIP(line: string): string | null {
  const from = line.match(/\bfrom\s+([\d.]+)/i);
  if (from) return from[1];
  const arrow = line.match(/([\d.]+):\d+\s*->/);
  if (arrow) return arrow[1];
  const apacheIP = line.match(/^([\d.]+)\s+-/);
  if (apacheIP) return apacheIP[1];
  const ips = line.match(IP_RE);
  return ips ? ips[0] : null;
}

function isInternalIP(ip: string): boolean {
  return ip.startsWith('10.') || ip.startsWith('192.168.') ||
    ip.startsWith('172.16.') || ip.startsWith('127.') || ip === '::1';
}

// ── Attack patterns ───────────────────────────────────────────────────────────

const SQL_RE = [
  /\bUNION\s+SELECT\b/i,
  /\bOR\s+1\s*=\s*1\b/i,
  /\bAND\s+1\s*=\s*1\b/i,
  /\bSLEEP\s*\(/i,
  /\bWAITFOR\s+DELAY\b/i,
  /\bDROP\s+TABLE\b/i,
  /\bSELECT\s+.*\s+FROM\b/i,
  /\bINFORMATION_SCHEMA\b/i,
  /\bxp_cmdshell\b/i,
  /'\s*OR\s*'/i,
  /\bBENCHMARK\s*\(/i,
  /\bCAST\s*\(.*AS\s+/i,
];

const XSS_RE = [
  /<script[\s>]/i,
  /javascript\s*:/i,
  /on(error|load|click|mouseover|focus|blur|submit|change|keydown|keyup)\s*=/i,
  /document\s*\.\s*(cookie|write|location)/i,
  /<(iframe|svg|img|object|embed)\b[^>]*>/i,
  /eval\s*\(/i,
  /alert\s*\(/i,
  /%3cscript/i,
  /&#\d+;/,
];

const CMD_RE = [
  /;\s*(cat|ls|whoami|id|pwd|uname|wget|curl|nc|bash|sh|python|perl|ruby|cmd)\b/i,
  /&&\s*(cat|ls|whoami|id|pwd|uname|wget|curl|nc|bash|sh)\b/i,
  /\|\|\s*(cat|ls|whoami|id|pwd|uname|wget|curl|nc|bash)\b/i,
  /\|\s*(cat|ls|whoami|id|pwd|uname|bash|sh)\b/i,
  /\bcat\s+\/etc\/passwd\b/i,
  /\bwhoami\b/i,
  /\bpowershell\b/i,
  /\bcmd\.exe\b/i,
  /`[^`]+`/,
  /\$\([^)]+\)/,
];

const TRAV_RE = [
  /\.\.[\/\\]/,
  /%2e%2e[\/\\%]/i,
  /\.\.%2f/i,
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /win\.ini/i,
  /web\.config/i,
  /boot\.ini/i,
  /\.htaccess/i,
  /system32/i,
];

const RANSOM_RE = [
  /\.locked\b/i,
  /\.encrypted\b/i,
  /\.crypt\b/i,
  /\.wnncry\b/i,
  /shadow\s+cop(y|ies)\s+delet/i,
  /vssadmin\s+delete\s+shadows/i,
  /README.*recover/i,
  /your\s+files.*encrypted/i,
  /bcdedit.*recoveryenabled.*no/i,
  /files?\s+renamed\s+to\s+\*?\./i,
];

const EXFIL_RE = [
  /uploaded?\s+.*\d+(\.\d+)?\s*(GB|MB)/i,
  /outbound\s+traffic\s+\d+(\.\d+)?\s*(GB|MB)/i,
  /exfiltrat/i,
  /data\s+transfer.*\d+\s*(GB|MB)/i,
  /copied\s+.*\.(zip|rar|7z|tar|gz|sql|db|bak)/i,
  /sent\s+\d+(\.\d+)?\s*(GB|MB)/i,
];

const PORTSCAN_RE = [
  /firewall\s+(drop|block|deny|reject)/i,
  /DROP\s+TCP/i,
  /BLOCK\s+TCP/i,
  /port\s+scan/i,
  /nmap|masscan|zmap/i,
];

const REVSHELL_RE = [
  /bash\s+-i\s+>&\s*\/dev\/tcp/i,
  /nc\s+-[el]+\s+\d+/i,
  /\/bin\/bash\s+-c/i,
  /python.*import\s+socket/i,
  /mkfifo.*nc/i,
];

const CREDDUMP_RE = [
  /mimikatz/i,
  /procdump/i,
  /lsass/i,
  /sekurlsa/i,
  /hashdump/i,
  /ntds\.dit/i,
];

const PRIVESC_RE = [
  /sudo\s+-i\b/i,
  /sudo\s+su\b/i,
  /sudo\s+\/bin\/bash/i,
  /sudo\s+\/bin\/sh/i,
  /pkexec/i,
  /dirtycow/i,
  /COMMAND=.*\/bin\/bash/,
  /COMMAND=.*\/bin\/sh/,
];

const WEBSHELL_RE = [
  /c99\.php|r57\.php|b374k/i,
  /eval\s*\(\s*base64_decode/i,
  /\$_(GET|POST|REQUEST).*eval/i,
  /system\s*\(\s*\$_(GET|POST)/i,
  /passthru\s*\(\s*\$_(GET|POST)/i,
];

interface AttackMatch {
  type: string;
  severity: Severity;
  mitre_id: string;
  mitre_name: string;
  tactic: string;
  tags: string[];
}

function detectAttack(line: string): AttackMatch | null {
  // Never flag standard syslog sudo audit lines as attacks
  if (/\bsudo\b.*TTY=.*COMMAND=/i.test(line)) return null;
  if (/\bsudo:\s+\S+\s*:.*TTY=/i.test(line)) return null;

  if (SQL_RE.some(r => r.test(line))) return { type: 'sql_injection', severity: 'critical', mitre_id: 'T1190', mitre_name: 'Exploit Public-Facing Application (SQLi)', tactic: 'Initial Access', tags: ['sql_injection'] };
  if (XSS_RE.some(r => r.test(line))) return { type: 'xss', severity: 'high', mitre_id: 'T1059.007', mitre_name: 'XSS / Script Injection', tactic: 'Execution', tags: ['xss'] };
  if (CMD_RE.some(r => r.test(line))) return { type: 'command_injection', severity: 'critical', mitre_id: 'T1059', mitre_name: 'Command Injection', tactic: 'Execution', tags: ['command_injection'] };
  if (TRAV_RE.some(r => r.test(line))) return { type: 'directory_traversal', severity: 'high', mitre_id: 'T1083', mitre_name: 'Directory Traversal / Path Traversal', tactic: 'Discovery', tags: ['traversal'] };
  if (RANSOM_RE.some(r => r.test(line))) return { type: 'ransomware', severity: 'critical', mitre_id: 'T1486', mitre_name: 'Data Encrypted for Impact (Ransomware)', tactic: 'Impact', tags: ['ransomware'] };
  if (EXFIL_RE.some(r => r.test(line))) return { type: 'data_exfiltration', severity: 'critical', mitre_id: 'T1041', mitre_name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', tags: ['data_exfiltration'] };
  if (REVSHELL_RE.some(r => r.test(line))) return { type: 'reverse_shell', severity: 'critical', mitre_id: 'T1059.004', mitre_name: 'Unix Shell / Reverse Shell', tactic: 'Execution', tags: ['reverse_shell'] };
  if (CREDDUMP_RE.some(r => r.test(line))) return { type: 'credential_dumping', severity: 'critical', mitre_id: 'T1003', mitre_name: 'OS Credential Dumping', tactic: 'Credential Access', tags: ['credential_dumping'] };
  if (WEBSHELL_RE.some(r => r.test(line))) return { type: 'web_shell', severity: 'critical', mitre_id: 'T1505.003', mitre_name: 'Web Shell', tactic: 'Persistence', tags: ['web_shell'] };
  if (PRIVESC_RE.some(r => r.test(line))) return { type: 'sudo_command', severity: 'high', mitre_id: 'T1548.003', mitre_name: 'Sudo and Sudo Caching', tactic: 'Privilege Escalation', tags: ['privesc'] };
  if (PORTSCAN_RE.some(r => r.test(line))) return { type: 'port_scan', severity: 'medium', mitre_id: 'T1046', mitre_name: 'Network Service Discovery (Port Scan)', tactic: 'Discovery', tags: ['port_scan'] };

  return null;
}

let _id = 0;
function newId(): string {
  return `evt_${Date.now()}_${++_id}_${Math.random().toString(36).slice(2,7)}`;
}

export function parseLine(line: string, now: Date = new Date()): LogEvent | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;

  let timestamp: Date = now;
  let hostname = 'unknown';
  let service = 'unknown';
  let pid: number | null = null;
  let message = trimmed;
  let event_type: EventType = 'unknown';
  let username: string | null = null;
  let source_ip: string | null = null;
  let source_port: number | null = null;
  let auth_method: string | null = null;
  let outcome: Outcome = 'unknown';
  let severity: Severity = 'info';
  let mitre_technique_id: string | null = null;
  let mitre_technique_name: string | null = null;
  let mitre_tactic: string | null = null;
  let threat_tags: string[] = [];
  let session_id: string | null = null;

  let m: RegExpMatchArray | null;

  // ── Extract timestamp ─────────────────────────────────────────────────────

  // ISO: 2026-07-01 09:00:01 ...
  if ((m = trimmed.match(/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+(.*)/))) {
    timestamp = parseISO(m[1]) ?? now;
    message = m[2];
  }
  // Standard syslog: Jan 15 03:22:17 hostname service[pid]: msg
  else if ((m = trimmed.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)/))) {
    timestamp = parseSyslog(m[1], now) ?? now;
    hostname = m[2];
    service = m[3];
    pid = m[4] ? parseInt(m[4], 10) : null;
    message = m[5];
  }
  // Syslog without host/service: Jul 01 14:00:01 Firewall DROP...
  else if ((m = trimmed.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.*)/))) {
    timestamp = parseSyslog(m[1], now) ?? now;
    message = m[2];
  }
  // Apache: 1.2.3.4 - - [01/Jul/2026:12:05:10] "GET ..."
  else if ((m = trimmed.match(/^([\d.]+)\s+-\s+-\s+\[([^\]]+)\]\s+"(.*)"/))) {
    source_ip = m[1];
    timestamp = parseApache(m[2]) ?? now;
    message = m[3];
    service = 'apache';
  }
  // Apache without IP: [01/Jul/2026:12:05:10] "GET ..."
  else if ((m = trimmed.match(/^\[([^\]]+)\]\s+"(.*)"/))) {
    timestamp = parseApache(m[1]) ?? now;
    message = m[2];
    service = 'apache';
  }
  // Raw HTTP: GET /path?...
  else if ((m = trimmed.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(.*)/i))) {
    message = trimmed;
    service = 'http';
  }

  // ── SSH/auth patterns ─────────────────────────────────────────────────────

  if ((m = message.match(/Failed password for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+)(?:\s+port\s+(\d+))?/i))) {
    event_type = 'ssh_failed_password';
    username = m[1];
    source_ip = source_ip ?? m[2];
    source_port = m[3] ? parseInt(m[3], 10) : null;
    auth_method = 'password';
    outcome = 'failure';
    severity = 'low';
  }
  else if ((m = message.match(/Accepted password for (\S+) from ([\d.a-fA-F:]+)(?:\s+port\s+(\d+))?/i))) {
    event_type = 'ssh_accepted_password';
    username = m[1];
    source_ip = source_ip ?? m[2];
    source_port = m[3] ? parseInt(m[3], 10) : null;
    auth_method = 'password';
    outcome = 'success';
    severity = 'info';
  }
  else if ((m = message.match(/Accepted publickey for (\S+) from ([\d.a-fA-F:]+)/i))) {
    event_type = 'ssh_accepted_publickey';
    username = m[1];
    source_ip = source_ip ?? m[2];
    auth_method = 'publickey';
    outcome = 'success';
    severity = 'info';
  }
  else if ((m = message.match(/Invalid user (\S+) from ([\d.a-fA-F:]+)/i))) {
    event_type = 'ssh_invalid_user';
    username = m[1];
    source_ip = source_ip ?? m[2];
    outcome = 'failure';
    severity = 'medium';
  }
  else if ((m = message.match(/maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+)/i))) {
    event_type = 'ssh_max_attempts';
    username = m[1];
    source_ip = source_ip ?? m[2];
    outcome = 'failure';
    severity = 'high';
  }
  else if (message.match(/TTY=.*COMMAND=/) || service.toLowerCase().includes('sudo')) {
    event_type = 'sudo_command';
    if ((m = message.match(/^(\S+)\s*:/))) username = m[1];
    outcome = 'success';
  }
  else if ((m = message.match(/Disconnected from (?:user (\S+) )?([\d.a-fA-F:]+)(?:\s+port\s+(\d+))?/i))) {
    event_type = 'ssh_disconnect';
    username = m[1] ?? username;
    source_ip = source_ip ?? m[2];
    source_port = m[3] ? parseInt(m[3], 10) : null;
    outcome = 'unknown';
  }
  else if ((m = message.match(/Connection closed by (?:authenticating user (\S+) )?([\d.a-fA-F:]+)(?:\s+port\s+(\d+))?/i))) {
    event_type = 'ssh_connection_closed';
    username = m[1] ?? username;
    source_ip = source_ip ?? m[2];
    source_port = m[3] ? parseInt(m[3], 10) : null;
    outcome = 'unknown';
  }
  else if ((m = message.match(/pam_unix\(.*\):\s+session\s+(opened|closed)\s+for\s+user\s+(\S+)/i))) {
    event_type = m[1].toLowerCase() === 'opened' ? 'pam_session_opened' : 'pam_session_closed';
    username = m[2];
    outcome = 'success';
  }
  else if (message.match(/authentication failure|auth\s+failure/i)) {
    event_type = 'pam_auth_failure';
    outcome = 'failure';
    if ((m = message.match(/user=(\S+)/))) username = m[1];
    if ((m = message.match(/rhost=([\d.]+)/))) source_ip = source_ip ?? m[1];
  }
  else if ((m = message.match(/[Ss]uccessful su for (\S+) by (\S+)/))) {
    event_type = 'su_success';
    username = m[2];
    outcome = 'success';
  }
  else if ((m = message.match(/New session (\S+) of user (\S+?)\.?$/))) {
    event_type = 'systemd_new_session';
    session_id = m[1];
    username = m[2];
    outcome = 'success';
  }
  else if ((m = message.match(/PAM.*more authentication failures.*user=(\S+)/i))) {
    event_type = 'pam_auth_failure';
    username = m[1];
    outcome = 'failure';
    if ((m = message.match(/rhost=([\d.]+)/))) source_ip = source_ip ?? m[1];
  }

  // ── Firewall port scan: DROP TCP src:port -> dst:port ─────────────────────
  if (event_type === 'unknown') {
    if ((m = trimmed.match(/(?:Firewall\s+)?(?:DROP|BLOCK|DENY|REJECT)\s+TCP\s+([\d.]+):(\d+)\s*->\s*([\d.]+):(\d+)/i))) {
      event_type = 'port_scan' as EventType;
      source_ip = m[1];
      source_port = parseInt(m[2], 10);
      severity = 'medium';
      mitre_technique_id = 'T1046';
      mitre_technique_name = 'Network Service Discovery (Port Scan)';
      mitre_tactic = 'Discovery';
      threat_tags = ['port_scan'];
      outcome = 'failure';
    }
  }

  // ── Generic login patterns ────────────────────────────────────────────────
  if (event_type === 'unknown') {
    if ((m = trimmed.match(/User\s+(\S+)\s+logged\s+in\s+from\s+([\d.]+)/i))) {
      event_type = 'ssh_accepted_password';
      username = m[1];
      source_ip = source_ip ?? m[2];
      outcome = 'success';
      severity = 'info';
    } else if (trimmed.match(/logged\s+(in|out)/i)) {
      event_type = 'pam_session_opened';
      outcome = 'success';
      severity = 'info';
    }
  }

  // ── Apply attack detection to raw line ────────────────────────────────────
  const attack = detectAttack(trimmed);
  if (attack) {
    event_type = attack.type as EventType;
    severity = attack.severity;
    mitre_technique_id = attack.mitre_id;
    mitre_technique_name = attack.mitre_name;
    mitre_tactic = attack.tactic;
    threat_tags = attack.tags;
    if (!source_ip) source_ip = extractSourceIP(trimmed);
    if (outcome === 'unknown') outcome = 'failure';
  }

  const is_internal_ip = source_ip ? isInternalIP(source_ip) : false;

  return {
    id: newId(),
    timestamp,
    hostname,
    service,
    pid,
    event_type,
    username,
    source_ip,
    source_port,
    auth_method,
    outcome,
    raw_line: line,
    severity,
    mitre_technique_id,
    mitre_technique_name,
    mitre_tactic,
    threat_tags,
    session_id,
    geo_country: null,
    geo_city: null,
    is_internal_ip,
    analyst_note: null,
    is_false_positive: false,
  };
}

export function parseLogContent(content: string): LogEvent[] {
  const now = new Date();
  return content.split('\n')
    .map(line => parseLine(line, now))
    .filter((e): e is LogEvent => e !== null);
}
