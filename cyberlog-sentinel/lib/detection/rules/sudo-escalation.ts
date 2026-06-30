import type { LogEvent } from '@/types/log-event';
import type { DetectionResult } from '@/types/detection';

const SHELL_ESCAPE_PATTERNS = [
  /COMMAND=.*(?:^|\s|\/)(?:-i|-s)(?:\s|$)/,
  /COMMAND=\s*\/bin\/bash/,
  /COMMAND=\s*\/bin\/sh\b/,
  /COMMAND=\s*\/usr\/bin\/bash/,
  /COMMAND=\s*\/bin\/su\b/,
  /COMMAND=\s*\/usr\/bin\/su\b/,
];

export function detectSudoEscalation(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];
  const sudoEvents = events.filter(e => e.event_type === 'sudo_command');

  for (const evt of Array.from(sudoEvents)) {
    const isShellEscape = SHELL_ESCAPE_PATTERNS.some(p => p.test(evt.raw_line));

    if (isShellEscape) {
      results.push({
        triggered: true,
        severity: 'high',
        confidence: 88,
        title: `Sudo Shell Escape — ${evt.username ?? 'unknown'}`,
        description: `User ${evt.username} obtained an interactive root shell via sudo, bypassing command-level audit logging.`,
        mitre_technique_id: 'T1548.003',
        mitre_technique_name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
        mitre_tactic: 'Privilege Escalation',
        evidence_event_ids: [evt.id],
        source_ips: evt.source_ip ? [evt.source_ip] : [],
        targeted_users: evt.username ? [evt.username] : [],
        details: {
          raw_command: evt.raw_line,
          timestamp: evt.timestamp.toISOString(),
        },
      });
    }
  }

  return results;
}

export function detectSudoPrivEsc(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];
  const sudoEvents = events.filter(e => e.event_type === 'sudo_command');

  // Group by user
  const byUser = new Map<string, LogEvent[]>();
  for (const evt of Array.from(sudoEvents)) {
    const u = evt.username ?? '__unknown__';
    if (!byUser.has(u)) byUser.set(u, []);
    byUser.get(u)!.push(evt);
  }

  for (const [user, userEvents] of Array.from(byUser)) {
    if (user === '__unknown__') continue;
    results.push({
      triggered: true,
      severity: 'low',
      confidence: 50,
      title: `Sudo Usage — ${user}`,
      description: `User ${user} executed ${userEvents.length} privileged command(s) via sudo.`,
      mitre_technique_id: 'T1548.003',
      mitre_technique_name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
      mitre_tactic: 'Privilege Escalation',
      evidence_event_ids: userEvents.map(e => e.id),
      source_ips: [],
      targeted_users: [user],
      details: { command_count: userEvents.length },
    });
  }

  return results;
}
