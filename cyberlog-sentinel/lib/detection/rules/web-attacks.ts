import type { LogEvent } from '@/types/log-event';
import type { DetectionResult } from '@/types/detection';

// SQL Injection patterns
const SQL_PATTERNS = [
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
  /\b(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|delete\s+from|update\s+.*\s+set)\b/i,
  /\b(or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+'[^']*'\s*=\s*'[^']*')\b/i,
  /\b(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)\b/i,
  /\b(information_schema|sysobjects|syscolumns|xp_cmdshell)\b/i,
  /(\bexec\b|\bexecute\b)\s*(\(|xp_)/i,
  /\bcast\s*\(.*\bas\s+/i,
  /\bconvert\s*\(.*,/i,
];

// XSS patterns
const XSS_PATTERNS = [
  /<script[\s>]/i,
  /javascript\s*:/i,
  /on(error|load|click|mouseover|focus|blur|change|submit|reset|keydown|keyup|keypress)\s*=/i,
  /document\s*\.\s*(cookie|write|location)/i,
  /<\s*(iframe|object|embed|applet|form|input|img)[^>]*>/i,
  /eval\s*\(/i,
  /expression\s*\(/i,
  /vbscript\s*:/i,
  /&#\d+;/,
  /%3cscript/i,
];

// Command injection patterns
const CMD_PATTERNS = [
  /;\s*(ls|cat|whoami|id|pwd|uname|wget|curl|nc|bash|sh|python|perl|ruby)\b/i,
  /&&\s*(ls|cat|whoami|id|pwd|uname|wget|curl|nc|bash|sh)\b/i,
  /\|\|\s*(ls|cat|whoami|id|pwd|uname|wget|curl|nc|bash)\b/i,
  /\|\s*(ls|cat|whoami|id|pwd|uname|wget|curl|nc|bash|sh)\b/i,
  /`[^`]+`/,
  /\$\([^)]+\)/,
  /\b(cat\s+\/etc\/passwd|cat\s+\/etc\/shadow|\/proc\/self)/i,
  /\b(powershell|cmd\.exe|wscript|cscript|mshta)\b/i,
  /\b(net\s+user|net\s+localgroup|whoami|systeminfo|ipconfig|ifconfig)\b/i,
];

// Directory traversal patterns
const TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/,
  /%2e%2e[\/\\%]/i,
  /\.\.%2f/i,
  /%2e%2e%2f/i,
  /\b(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|\/proc\/version)\b/i,
  /\b(win\.ini|web\.config|boot\.ini|system32)\b/i,
  /\b(\.htaccess|\.htpasswd|wp-config\.php)\b/i,
];

// Port scan patterns (multiple ports from same IP in log)
const PORT_SCAN_PATTERNS = [
  /port\s+(\d+)/gi,
  /connection\s+(refused|reset|timeout)/i,
  /syn\s+(scan|flood|packet)/i,
  /nmap|masscan|zmap|unicornscan/i,
];

// Reverse shell patterns
const REVERSE_SHELL_PATTERNS = [
  /bash\s+-i\s+>&\s*\/dev\/tcp/i,
  /nc\s+-[el]+\s+\d+/i,
  /\/bin\/bash\s+-c/i,
  /python\s+-c\s+['"]import\s+socket/i,
  /perl\s+-e\s+['"]use\s+Socket/i,
  /\b(mkfifo|mknod)\b.*\|.*\b(nc|netcat|bash)\b/i,
];

// Credential dumping patterns
const CRED_DUMP_PATTERNS = [
  /\b(mimikatz|procdump|lsass|sekurlsa|logonpasswords)\b/i,
  /\b(hashdump|wce\.exe|fgdump|pwdump)\b/i,
  /\b(reg\s+save.*sam|reg\s+save.*system|reg\s+save.*security)\b/i,
  /\b(ntds\.dit|shadow\s+copy|vssadmin)\b/i,
];

// Web shell patterns
const WEBSHELL_PATTERNS = [
  /\b(c99|r57|b374k|wso|b374|phpspy)\b/i,
  /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/i,
  /\$_(GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*.*eval/i,
  /system\s*\(\s*\$_(GET|POST|REQUEST)/i,
  /passthru\s*\(\s*\$_(GET|POST|REQUEST)/i,
];

// DNS tunneling patterns
const DNS_TUNNEL_PATTERNS = [
  /\b(iodine|dnscat|dns2tcp|dnscapy)\b/i,
  /TXT\s+record.*base64/i,
  /dns\s+(tunnel|exfil|c2|beacon)/i,
];

// Ransomware patterns
const RANSOMWARE_PATTERNS = [
  /\b(wannacry|petya|notpetya|ryuk|revil|lockbit|conti|blackcat|maze)\b/i,
  /\.(encrypted|enc|locked|crypt|ransom|wnncry|wncry)\b/i,
  /README\.(txt|html|md).*decrypt/i,
  /\b(vssadmin\s+delete|shadow\s+copies\s+delete|bcdedit.*recoveryenabled\s+no)\b/i,
  /your\s+files\s+(have\s+been|are)\s+(encrypted|locked)/i,
];

// C2 communication patterns
const C2_PATTERNS = [
  /\b(cobalt\s*strike|metasploit|meterpreter|beacon)\b/i,
  /User-Agent.*(\bpython-requests\b|\bcurl\b|\bwget\b|\bGo-http-client\b|\bscanner\b)/i,
  /\b(c2|command\s*and\s*control|rat\s+client|reverse\s+shell)\b/i,
  /base64.*==.*http/i,
];

// Privilege escalation patterns
const PRIVESC_PATTERNS = [
  /\b(sudo\s+-i|sudo\s+su|sudo\s+bash|sudo\s+\/bin\/sh)\b/i,
  /\b(setuid|setgid|chmod\s+[0-9]*[46][0-9]*[0-9]*)\b/i,
  /\b(pkexec|polkit|dirty\s*cow|dirtycow)\b/i,
  /\b(exploit\s+.*kernel|local\s+privilege\s+escalation)\b/i,
];

// Lateral movement patterns
const LATERAL_PATTERNS = [
  /\b(psexec|wmiexec|smbexec|atexec|dcomexec)\b/i,
  /\b(pass-the-hash|pass-the-ticket|golden\s+ticket|silver\s+ticket)\b/i,
  /\b(impacket|crackmapexec|bloodhound)\b/i,
  /\b(rdp|winrm|wsman|smb)\s+(lateral|pivot|hop)\b/i,
];

// Persistence patterns
const PERSISTENCE_PATTERNS = [
  /\b(crontab\s+-[el]|\/etc\/cron|at\s+\d)\b/i,
  /\b(HKEY_.*\\CurrentVersion\\Run|registry.*autorun|startup\s+folder)\b/i,
  /\b(systemctl\s+enable|service\s+.*start|init\.d)\b/i,
  /\b(\.bashrc|\.bash_profile|\.profile).*wget|curl\b/i,
];

function testPatterns(text: string, patterns: RegExp[]): { matched: boolean; matches: string[] } {
  const matches: string[] = [];
  for (const p of patterns) {
    const m = text.match(p);
    if (m) matches.push(m[0]);
  }
  return { matched: matches.length > 0, matches };
}

export function detectWebAttacks(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];

  const attackTypes: Array<{
    name: string;
    patterns: RegExp[];
    severity: 'critical' | 'high' | 'medium' | 'low';
    mitre_id: string;
    mitre_name: string;
    tactic: string;
    confidence: number;
  }> = [
    { name: 'SQL Injection', patterns: SQL_PATTERNS, severity: 'critical', mitre_id: 'T1190', mitre_name: 'Exploit Public-Facing Application', tactic: 'Initial Access', confidence: 90 },
    { name: 'Cross-Site Scripting (XSS)', patterns: XSS_PATTERNS, severity: 'high', mitre_id: 'T1059.007', mitre_name: 'Command and Scripting Interpreter: JavaScript', tactic: 'Execution', confidence: 85 },
    { name: 'Command Injection', patterns: CMD_PATTERNS, severity: 'critical', mitre_id: 'T1059', mitre_name: 'Command and Scripting Interpreter', tactic: 'Execution', confidence: 92 },
    { name: 'Directory Traversal', patterns: TRAVERSAL_PATTERNS, severity: 'high', mitre_id: 'T1083', mitre_name: 'File and Directory Discovery', tactic: 'Discovery', confidence: 88 },
    { name: 'Reverse Shell', patterns: REVERSE_SHELL_PATTERNS, severity: 'critical', mitre_id: 'T1059.004', mitre_name: 'Unix Shell', tactic: 'Execution', confidence: 95 },
    { name: 'Credential Dumping', patterns: CRED_DUMP_PATTERNS, severity: 'critical', mitre_id: 'T1003', mitre_name: 'OS Credential Dumping', tactic: 'Credential Access', confidence: 94 },
    { name: 'Web Shell', patterns: WEBSHELL_PATTERNS, severity: 'critical', mitre_id: 'T1505.003', mitre_name: 'Server Software Component: Web Shell', tactic: 'Persistence', confidence: 93 },
    { name: 'DNS Tunneling', patterns: DNS_TUNNEL_PATTERNS, severity: 'high', mitre_id: 'T1572', mitre_name: 'Protocol Tunneling', tactic: 'Command and Control', confidence: 80 },
    { name: 'Ransomware Activity', patterns: RANSOMWARE_PATTERNS, severity: 'critical', mitre_id: 'T1486', mitre_name: 'Data Encrypted for Impact', tactic: 'Impact', confidence: 96 },
    { name: 'C2 Communication', patterns: C2_PATTERNS, severity: 'critical', mitre_id: 'T1071', mitre_name: 'Application Layer Protocol', tactic: 'Command and Control', confidence: 87 },
    { name: 'Privilege Escalation Attempt', patterns: PRIVESC_PATTERNS, severity: 'high', mitre_id: 'T1548', mitre_name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation', confidence: 88 },
    { name: 'Lateral Movement', patterns: LATERAL_PATTERNS, severity: 'high', mitre_id: 'T1021', mitre_name: 'Remote Services', tactic: 'Lateral Movement', confidence: 85 },
    { name: 'Persistence Mechanism', patterns: PERSISTENCE_PATTERNS, severity: 'high', mitre_id: 'T1053', mitre_name: 'Scheduled Task/Job', tactic: 'Persistence', confidence: 82 },
  ];

  for (const attackType of attackTypes) {
    const matchedEvents: LogEvent[] = [];
    const allMatches: string[] = [];

    for (const evt of events) {
      const { matched, matches } = testPatterns(evt.raw_line, attackType.patterns);
      if (matched) {
        matchedEvents.push(evt);
        allMatches.push(...matches);
      }
    }

    if (matchedEvents.length > 0) {
      const ips = [...new Set(matchedEvents.map(e => e.source_ip).filter(Boolean))] as string[];
      const users = [...new Set(matchedEvents.map(e => e.username).filter(Boolean))] as string[];
      const timestamps = matchedEvents.map(e => e.timestamp.getTime());

      // Increase confidence based on number of matches
      const confidence = Math.min(99, attackType.confidence + Math.floor(matchedEvents.length / 3));

      results.push({
        triggered: true,
        severity: attackType.severity,
        confidence,
        title: `${attackType.name} Detected`,
        description: `${matchedEvents.length} log event(s) contain ${attackType.name} indicators. Unique signatures matched: ${[...new Set(allMatches)].slice(0, 5).join(', ')}`,
        mitre_technique_id: attackType.mitre_id,
        mitre_technique_name: attackType.mitre_name,
        mitre_tactic: attackType.tactic,
        evidence_event_ids: matchedEvents.map(e => e.id),
        source_ips: ips,
        targeted_users: users,
        details: {
          matched_count: matchedEvents.length,
          unique_signatures: [...new Set(allMatches)].slice(0, 10),
          first_seen: new Date(Math.min(...timestamps)).toISOString(),
          last_seen: new Date(Math.max(...timestamps)).toISOString(),
          sample_lines: matchedEvents.slice(0, 3).map(e => e.raw_line),
        },
      });
    }
  }

  return results;
}

export function detectPortScan(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];

  // Group events by source IP and look for multiple port connections
  const ipPortMap = new Map<string, Set<number>>();
  const ipEvents = new Map<string, LogEvent[]>();

  for (const evt of events) {
    if (!evt.source_ip) continue;
    const portMatch = evt.raw_line.match(/port\s+(\d+)/i);
    if (!portMatch) continue;
    const port = parseInt(portMatch[1], 10);
    if (port < 1 || port > 65535) continue;

    if (!ipPortMap.has(evt.source_ip)) {
      ipPortMap.set(evt.source_ip, new Set());
      ipEvents.set(evt.source_ip, []);
    }
    ipPortMap.get(evt.source_ip)!.add(port);
    ipEvents.get(evt.source_ip)!.push(evt);
  }

  for (const [ip, ports] of Array.from(ipPortMap.entries())) {
    if (ports.size >= 5) {
      const evts = ipEvents.get(ip) ?? [];
      const severity = ports.size >= 20 ? 'high' : 'medium';
      results.push({
        triggered: true,
        severity,
        confidence: Math.min(95, 60 + ports.size),
        title: `Port Scan Detected from ${ip}`,
        description: `Source IP ${ip} accessed ${ports.size} unique ports — consistent with automated port scanning.`,
        mitre_technique_id: 'T1046',
        mitre_technique_name: 'Network Service Discovery',
        mitre_tactic: 'Discovery',
        evidence_event_ids: evts.map(e => e.id),
        source_ips: [ip],
        targeted_users: [],
        details: {
          unique_ports: ports.size,
          ports_scanned: Array.from(ports).sort((a, b) => a - b).slice(0, 20),
        },
      });
    }
  }

  return results;
}
