import type { LogEvent } from '@/types/log-event';
import type { DetectionResult } from '@/types/detection';

export function detectRootLogin(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];

  const rootLogins = events.filter(
    e =>
      e.username === 'root' &&
      (e.event_type === 'ssh_accepted_password' || e.event_type === 'ssh_accepted_publickey') &&
      e.outcome === 'success'
  );

  for (const evt of rootLogins) {
    const isExternal = evt.source_ip ? !evt.is_internal_ip : false;
    results.push({
      triggered: true,
      severity: isExternal ? 'critical' : 'high',
      confidence: 90,
      title: `Direct Root Login via SSH from ${evt.source_ip ?? 'unknown'}`,
      description: `Direct root login detected from ${isExternal ? 'external' : 'internal'} IP ${evt.source_ip}. This bypasses privilege escalation audit trails.`,
      mitre_technique_id: 'T1078.003',
      mitre_technique_name: 'Valid Accounts: Local Accounts',
      mitre_tactic: 'Privilege Escalation',
      evidence_event_ids: [evt.id],
      source_ips: evt.source_ip ? [evt.source_ip] : [],
      targeted_users: ['root'],
      details: {
        login_time: evt.timestamp.toISOString(),
        source_ip: evt.source_ip,
        is_external: isExternal,
        auth_method: evt.auth_method,
      },
    });
  }

  return results;
}

export function detectSuccessAfterBruteForce(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];

  // Build failed counts per IP
  const failuresByIp = new Map<string, LogEvent[]>();
  for (const evt of events) {
    if (evt.source_ip && evt.outcome === 'failure' && evt.event_type !== 'pam_session_closed') {
      if (!failuresByIp.has(evt.source_ip)) failuresByIp.set(evt.source_ip, []);
      failuresByIp.get(evt.source_ip)!.push(evt);
    }
  }

  // Find successes from IPs with >= 3 prior failures
  const successEvents = events.filter(
    e => e.source_ip && e.outcome === 'success' &&
    (e.event_type === 'ssh_accepted_password' || e.event_type === 'ssh_accepted_publickey')
  );

  for (const evt of successEvents) {
    const ip = evt.source_ip!;
    const priorFailures = (failuresByIp.get(ip) ?? []).filter(
      f => f.timestamp.getTime() < evt.timestamp.getTime()
    );
    if (priorFailures.length >= 3) {
      results.push({
        triggered: true,
        severity: 'critical',
        confidence: 95,
        title: `Successful Login After Brute Force — ${ip}`,
        description: `Successful authentication from ${ip} (user: ${evt.username}) after ${priorFailures.length} prior failures. Possible account compromise.`,
        mitre_technique_id: 'T1078',
        mitre_technique_name: 'Valid Accounts',
        mitre_tactic: 'Initial Access',
        evidence_event_ids: [...priorFailures.slice(-10).map(e => e.id), evt.id],
        source_ips: [ip],
        targeted_users: evt.username ? [evt.username] : [],
        details: {
          prior_failure_count: priorFailures.length,
          successful_user: evt.username,
          success_time: evt.timestamp.toISOString(),
        },
      });
    }
  }

  return results;
}
