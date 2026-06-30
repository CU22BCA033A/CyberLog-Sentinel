import type { LogEvent } from '@/types/log-event';
import type { DetectionResult } from '@/types/detection';

export function detectOffHoursAuth(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];

  const offHours = events.filter(e => {
    if (e.outcome !== 'success') return false;
    if (e.event_type !== 'ssh_accepted_password' && e.event_type !== 'ssh_accepted_publickey') return false;
    const hour = e.timestamp.getHours();
    return hour >= 22 || hour < 6;
  });

  if (offHours.length > 0) {
    const users = [...new Set(offHours.map(e => e.username).filter(Boolean))] as string[];
    const ips = [...new Set(offHours.map(e => e.source_ip).filter(Boolean))] as string[];
    results.push({
      triggered: true,
      severity: 'medium',
      confidence: 65,
      title: `Off-Hours Authentication Detected`,
      description: `${offHours.length} successful login(s) between 22:00–06:00 server local time.`,
      mitre_technique_id: 'T1078',
      mitre_technique_name: 'Valid Accounts',
      mitre_tactic: 'Initial Access',
      evidence_event_ids: offHours.map(e => e.id),
      source_ips: ips,
      targeted_users: users,
      details: { login_count: offHours.length, users, hours: offHours.map(e => e.timestamp.getHours()) },
    });
  }

  return results;
}

export function detectGlobalFailureFlood(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];

  const failures = events.filter(
    e => e.outcome === 'failure' &&
    (e.event_type === 'ssh_failed_password' || e.event_type === 'ssh_invalid_user')
  ).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  for (let i = 0; i < failures.length; i++) {
    const windowStart = failures[i].timestamp.getTime();
    const windowEnd = windowStart + 300_000; // 5 min
    const window = failures.filter(e => e.timestamp.getTime() >= windowStart && e.timestamp.getTime() <= windowEnd);

    if (window.length > 100) {
      const ips = [...new Set(window.map(e => e.source_ip).filter(Boolean))] as string[];
      const users = [...new Set(window.map(e => e.username).filter(Boolean))] as string[];
      results.push({
        triggered: true,
        severity: 'critical',
        confidence: 98,
        title: `Coordinated Attack — ${window.length} Failures in 5 Minutes`,
        description: `${window.length} failed auth events from ${ips.length} unique IPs in a 5-minute window — indicates coordinated attack.`,
        mitre_technique_id: 'T1110',
        mitre_technique_name: 'Brute Force',
        mitre_tactic: 'Credential Access',
        evidence_event_ids: window.slice(0, 50).map(e => e.id),
        source_ips: ips.slice(0, 20),
        targeted_users: users.slice(0, 20),
        details: { failure_count: window.length, unique_ips: ips.length, window_minutes: 5 },
      });
      break;
    }
  }

  return results;
}

export function detectInvalidUserAttempts(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];
  const invalidEvents = events.filter(e => e.event_type === 'ssh_invalid_user');

  if (invalidEvents.length === 0) return results;

  const byIp = new Map<string, LogEvent[]>();
  for (const evt of Array.from(invalidEvents)) {
    const ip = evt.source_ip ?? 'unknown';
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip)!.push(evt);
  }

  for (const [ip, ipEvents] of Array.from(byIp)) {
    if (ipEvents.length >= 3) {
      const users = [...new Set(ipEvents.map(e => e.username).filter(Boolean))] as string[];
      results.push({
        triggered: true,
        severity: 'medium',
        confidence: 70,
        title: `Invalid User Enumeration from ${ip}`,
        description: `${ipEvents.length} attempts to non-existent usernames from ${ip} — indicates user enumeration.`,
        mitre_technique_id: 'T1110.001',
        mitre_technique_name: 'Brute Force: Password Guessing',
        mitre_tactic: 'Credential Access',
        evidence_event_ids: ipEvents.map(e => e.id),
        source_ips: [ip],
        targeted_users: users,
        details: { invalid_user_count: ipEvents.length, usernames: users },
      });
    }
  }

  return results;
}

export function detectRepeatedPAMFailures(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];
  const pamEvents = events.filter(e => e.event_type === 'pam_auth_failure');

  const byUser = new Map<string, LogEvent[]>();
  for (const evt of Array.from(pamEvents)) {
    const u = evt.username ?? '__unknown__';
    if (!byUser.has(u)) byUser.set(u, []);
    byUser.get(u)!.push(evt);
  }

  for (const [user, userEvents] of Array.from(byUser)) {
    if (user === '__unknown__') continue;
    if (userEvents.length >= 3) {
      results.push({
        triggered: true,
        severity: 'medium',
        confidence: 72,
        title: `Repeated PAM Failures for ${user}`,
        description: `${userEvents.length} PAM authentication failures for user ${user}.`,
        mitre_technique_id: 'T1110',
        mitre_technique_name: 'Brute Force',
        mitre_tactic: 'Credential Access',
        evidence_event_ids: userEvents.map(e => e.id),
        source_ips: [...new Set(userEvents.map(e => e.source_ip).filter(Boolean))] as string[],
        targeted_users: [user],
        details: { failure_count: userEvents.length },
      });
    }
  }

  return results;
}

export function detectNonStandardPort(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];
  const suspicious = events.filter(e => e.source_port !== null && e.source_port < 1024 && e.source_port > 0 && e.source_ip !== null);

  if (suspicious.length > 0) {
    const ips = [...new Set(suspicious.map(e => e.source_ip))] as string[];
    results.push({
      triggered: true,
      severity: 'low',
      confidence: 55,
      title: `SSH Connections from Privileged Source Ports`,
      description: `${suspicious.length} SSH connections sourced from ports < 1024, which may indicate non-standard tooling.`,
      mitre_technique_id: 'T1571',
      mitre_technique_name: 'Non-Standard Port',
      mitre_tactic: 'Command and Control',
      evidence_event_ids: suspicious.map(e => e.id),
      source_ips: ips,
      targeted_users: [],
      details: { event_count: suspicious.length, ports: [...new Set(suspicious.map(e => e.source_port))] },
    });
  }

  return results;
}
