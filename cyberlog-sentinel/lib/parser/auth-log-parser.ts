import type { EventType, LogEvent, Outcome, Severity } from '@/types/log-event';
import { DEFAULT_SEVERITY_MAP } from './event-types';

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

// Syslog header: "Jan 15 03:22:17 hostname service[pid]:"
const SYSLOG_RE = /^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$/;

// RFC5424 with year
const SYSLOG_YEAR_RE = /^(\d{4})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$/;

// journald JSON
interface JournaldEntry {
  __REALTIME_TIMESTAMP?: string;
  _HOSTNAME?: string;
  SYSLOG_IDENTIFIER?: string;
  _PID?: string;
  MESSAGE?: string;
}

function inferYear(month: number, now: Date): number {
  const currentMonth = now.getMonth();
  // If log month is December and current month is January, log is from last year
  if (month === 11 && currentMonth === 0) return now.getFullYear() - 1;
  return now.getFullYear();
}

export function parseTimestamp(
  month: string,
  day: string,
  time: string,
  now: Date = new Date()
): Date {
  const monthNum = MONTHS[month] ?? 0;
  const year = inferYear(monthNum, now);
  const [h, m, s] = time.split(':').map(Number);
  return new Date(year, monthNum, parseInt(day, 10), h, m, s);
}

function isInternalIP(ip: string): boolean {
  if (!ip) return false;
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('172.16.') ||
    ip.startsWith('172.17.') ||
    ip.startsWith('172.18.') ||
    ip.startsWith('172.19.') ||
    ip.startsWith('172.2') ||
    ip.startsWith('172.30.') ||
    ip.startsWith('172.31.') ||
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip === 'localhost'
  );
}

function parseMessage(
  service: string,
  message: string,
  raw_line: string,
  base: Omit<LogEvent, 'event_type' | 'username' | 'source_ip' | 'source_port' | 'auth_method' | 'outcome' | 'severity' | 'mitre_technique_id' | 'mitre_technique_name' | 'mitre_tactic' | 'threat_tags' | 'session_id' | 'geo_country' | 'geo_city' | 'is_internal_ip' | 'analyst_note' | 'is_false_positive'>
): LogEvent {
  const svc = service.toLowerCase().replace(/\d+/g, '');
  let event_type: EventType = 'unknown';
  let username: string | null = null;
  let source_ip: string | null = null;
  let source_port: number | null = null;
  let auth_method: string | null = null;
  let outcome: Outcome = 'unknown';
  let session_id: string | null = null;
  let sudo_command: string | null = null;

  let m: RegExpMatchArray | null;

  // SSH: Failed password
  if ((m = message.match(/Failed password for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+) port (\d+)/))) {
    event_type = 'ssh_failed_password';
    username = m[1];
    source_ip = m[2];
    source_port = parseInt(m[3], 10);
    auth_method = 'password';
    outcome = 'failure';
  }
  // SSH: Accepted password
  else if ((m = message.match(/Accepted password for (\S+) from ([\d.a-fA-F:]+) port (\d+)/))) {
    event_type = 'ssh_accepted_password';
    username = m[1];
    source_ip = m[2];
    source_port = parseInt(m[3], 10);
    auth_method = 'password';
    outcome = 'success';
  }
  // SSH: Accepted publickey
  else if ((m = message.match(/Accepted publickey for (\S+) from ([\d.a-fA-F:]+) port (\d+)/))) {
    event_type = 'ssh_accepted_publickey';
    username = m[1];
    source_ip = m[2];
    source_port = parseInt(m[3], 10);
    auth_method = 'publickey';
    outcome = 'success';
  }
  // SSH: Invalid user
  else if ((m = message.match(/Invalid user (\S+) from ([\d.a-fA-F:]+)(?:\s+port\s+(\d+))?/))) {
    event_type = 'ssh_invalid_user';
    username = m[1];
    source_ip = m[2];
    source_port = m[3] ? parseInt(m[3], 10) : null;
    outcome = 'failure';
  }
  // SSH: Invalid user (no username)
  else if ((m = message.match(/Invalid user from ([\d.a-fA-F:]+)/))) {
    event_type = 'ssh_invalid_user';
    source_ip = m[1];
    outcome = 'failure';
  }
  // SSH: Max attempts exceeded
  else if ((m = message.match(/maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+) port (\d+)/))) {
    event_type = 'ssh_max_attempts';
    username = m[1];
    source_ip = m[2];
    source_port = parseInt(m[3], 10);
    outcome = 'failure';
  }
  // SSH: Disconnected
  else if ((m = message.match(/Disconnected from (?:user (\S+) )?([\d.a-fA-F:]+) port (\d+)/))) {
    event_type = 'ssh_disconnect';
    username = m[1] || null;
    source_ip = m[2];
    source_port = parseInt(m[3], 10);
    outcome = 'unknown';
  }
  // SSH: Connection closed
  else if ((m = message.match(/Connection closed by (?:authenticating user (\S+) )?([\d.a-fA-F:]+) port (\d+)/))) {
    event_type = 'ssh_connection_closed';
    username = m[1] || null;
    source_ip = m[2];
    source_port = parseInt(m[3], 10);
    outcome = 'unknown';
  }
  // PAM: auth failure
  else if (message.includes('PAM') && message.includes('authentication failure')) {
    event_type = 'pam_auth_failure';
    outcome = 'failure';
    if ((m = message.match(/user=(\S+)/))) username = m[1];
    if ((m = message.match(/rhost=([\d.a-fA-F:]+)/))) source_ip = m[1];
  }
  // PAM: more authentication failures
  else if (message.includes('more authentication failures')) {
    event_type = 'pam_auth_failure';
    outcome = 'failure';
    if ((m = message.match(/user=(\S+)/))) username = m[1];
    if ((m = message.match(/rhost=([\d.a-fA-F:]+)/))) source_ip = m[1];
  }
  // PAM: session opened
  else if (message.match(/pam_unix\(.*session\):\s+session opened/)) {
    event_type = 'pam_session_opened';
    outcome = 'success';
    if ((m = message.match(/session opened for user (\S+)/))) username = m[1];
    // Extract session id from sshd PID (base.pid)
    session_id = base.pid ? `${base.hostname}:${base.pid}` : null;
  }
  // PAM: session closed
  else if (message.match(/pam_unix\(.*session\):\s+session closed/)) {
    event_type = 'pam_session_closed';
    outcome = 'success';
    if ((m = message.match(/session closed for user (\S+)/))) username = m[1];
    session_id = base.pid ? `${base.hostname}:${base.pid}` : null;
  }
  // Sudo command
  else if (svc === 'sudo' || message.match(/TTY=.*COMMAND=/)) {
    event_type = 'sudo_command';
    outcome = 'success';
    if ((m = message.match(/^(\S+)\s*:/))) username = m[1];
    if ((m = message.match(/USER=(\S+)/))) { /* run-as user */ }
    if ((m = message.match(/COMMAND=(.*)/))) sudo_command = m[1].trim();
    // Sudo shell escape detection is done in detection engine
  }
  // Su: successful
  else if ((m = message.match(/Successful su for (\S+) by (\S+)/))) {
    event_type = 'su_success';
    username = m[2]; // the user who ran su
    outcome = 'success';
  }
  // Su: failed
  else if ((m = message.match(/FAILED su for (\S+) by (\S+)/))) {
    event_type = 'su_failure';
    username = m[2];
    outcome = 'failure';
  }
  // systemd-logind: new session
  else if ((m = message.match(/New session (\S+) of user (\S+?)\.?$/))) {
    event_type = 'systemd_new_session';
    session_id = m[1];
    username = m[2];
    outcome = 'success';
  }
  // CRON
  else if (svc === 'cron' || message.includes('cron:session')) {
    event_type = 'cron_session';
    outcome = 'unknown';
    if ((m = message.match(/session opened for user (\S+)/))) username = m[1];
    else if ((m = message.match(/session closed for user (\S+)/))) username = m[1];
  }

  const is_internal_ip = source_ip ? isInternalIP(source_ip) : false;
  const severity: Severity = DEFAULT_SEVERITY_MAP[event_type] ?? 'info';

  const threat_tags: string[] = [];
  if (sudo_command) {
    // Tag on raw_line for detection engine to pick up
    (raw_line as string);
  }

  return {
    ...base,
    event_type,
    username,
    source_ip,
    source_port,
    auth_method,
    outcome,
    severity,
    mitre_technique_id: null,
    mitre_technique_name: null,
    mitre_tactic: null,
    threat_tags,
    session_id,
    geo_country: null,
    geo_city: null,
    is_internal_ip,
    analyst_note: null,
    is_false_positive: false,
  };
}

let _idCounter = 0;
function newId(): string {
  return `evt_${Date.now()}_${++_idCounter}_${Math.random().toString(36).slice(2, 7)}`;
}

export function parseLine(line: string, now: Date = new Date()): LogEvent | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;

  // Try journald JSON
  if (trimmed.startsWith('{')) {
    try {
      const j: JournaldEntry = JSON.parse(trimmed);
      const ts = j.__REALTIME_TIMESTAMP
        ? new Date(parseInt(j.__REALTIME_TIMESTAMP, 10) / 1000)
        : now;
      const base = {
        id: newId(),
        timestamp: ts,
        hostname: j._HOSTNAME ?? 'unknown',
        service: j.SYSLOG_IDENTIFIER ?? 'unknown',
        pid: j._PID ? parseInt(j._PID, 10) : null,
        raw_line: line,
      };
      return parseMessage(base.service, j.MESSAGE ?? '', line, base);
    } catch {
      // fall through
    }
  }

  // Try syslog with year prefix
  let m = trimmed.match(SYSLOG_YEAR_RE);
  if (m) {
    const [, yearStr, mon, day, time, host, svc, pid, msg] = m;
    const ts = new Date(
      parseInt(yearStr, 10),
      MONTHS[mon] ?? 0,
      parseInt(day, 10),
      ...time.split(':').map(Number) as [number, number, number]
    );
    const base = { id: newId(), timestamp: ts, hostname: host, service: svc, pid: pid ? parseInt(pid, 10) : null, raw_line: line };
    return parseMessage(svc, msg, line, base);
  }

  // Standard syslog
  m = trimmed.match(SYSLOG_RE);
  if (m) {
    const [, mon, day, time, host, svc, pid, msg] = m;
    const ts = parseTimestamp(mon, day, time, now);
    const base = { id: newId(), timestamp: ts, hostname: host, service: svc, pid: pid ? parseInt(pid, 10) : null, raw_line: line };
    return parseMessage(svc, msg, line, base);
  }

  // Unrecognized line — return as unknown event
  return {
    id: newId(),
    timestamp: now,
    hostname: 'unknown',
    service: 'unknown',
    pid: null,
    event_type: 'unknown',
    username: null,
    source_ip: null,
    source_port: null,
    auth_method: null,
    outcome: 'unknown',
    raw_line: line,
    severity: 'info',
    mitre_technique_id: null,
    mitre_technique_name: null,
    mitre_tactic: null,
    threat_tags: [],
    session_id: null,
    geo_country: null,
    geo_city: null,
    is_internal_ip: false,
    analyst_note: null,
    is_false_positive: false,
  };
}

export function parseLogContent(content: string): LogEvent[] {
  const now = new Date();
  const lines = content.split('\n');
  const events: LogEvent[] = [];
  for (const line of lines) {
    const evt = parseLine(line, now);
    if (evt) events.push(evt);
  }
  return events;
}
