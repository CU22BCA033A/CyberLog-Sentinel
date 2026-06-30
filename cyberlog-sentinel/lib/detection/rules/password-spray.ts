import type { LogEvent } from '@/types/log-event';
import type { DetectionResult } from '@/types/detection';

export function detectPasswordSpray(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];
  const failedByIp = new Map<string, LogEvent[]>();

  for (const evt of Array.from(events)) {
    if (
      evt.source_ip &&
      (evt.event_type === 'ssh_failed_password' || evt.event_type === 'ssh_invalid_user')
    ) {
      if (!failedByIp.has(evt.source_ip)) failedByIp.set(evt.source_ip, []);
      failedByIp.get(evt.source_ip)!.push(evt);
    }
  }

  for (const [ip, ipEvents] of Array.from(failedByIp)) {
    const sorted = [...ipEvents].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    // Sliding 2-minute window, look for 3+ distinct usernames
    for (let i = 0; i < sorted.length; i++) {
      const windowStart = sorted[i].timestamp.getTime();
      const windowEnd = windowStart + 120_000;
      const window = sorted.filter(e => e.timestamp.getTime() >= windowStart && e.timestamp.getTime() <= windowEnd);
      const distinctUsers = new Set(window.map(e => e.username).filter(Boolean));

      if (distinctUsers.size >= 3) {
        results.push({
          triggered: true,
          severity: 'high',
          confidence: 85,
          title: `Password Spray from ${ip}`,
          description: `${ip} attempted ${distinctUsers.size} different usernames within 2 minutes — indicates password spraying.`,
          mitre_technique_id: 'T1110.003',
          mitre_technique_name: 'Brute Force: Password Spraying',
          mitre_tactic: 'Credential Access',
          evidence_event_ids: window.map(e => e.id),
          source_ips: [ip],
          targeted_users: [...distinctUsers] as string[],
          details: {
            distinct_usernames: distinctUsers.size,
            usernames: [...distinctUsers],
            window_minutes: 2,
          },
        });
        break;
      }
    }
  }

  return results;
}
