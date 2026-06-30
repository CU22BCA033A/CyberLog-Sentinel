import type { LogEvent } from '@/types/log-event';
import type { DetectionResult } from '@/types/detection';

export function detectBruteForce(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];
  const failedByIp = new Map<string, LogEvent[]>();

  for (const evt of Array.from(events)) {
    if (
      evt.source_ip &&
      (evt.event_type === 'ssh_failed_password' ||
        evt.event_type === 'ssh_invalid_user' ||
        evt.event_type === 'ssh_max_attempts')
    ) {
      if (!failedByIp.has(evt.source_ip)) failedByIp.set(evt.source_ip, []);
      failedByIp.get(evt.source_ip)!.push(evt);
    }
  }

  for (const [ip, ipEvents] of Array.from(failedByIp)) {
    // Sort by time
    const sorted = [...ipEvents].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    // Sliding 60-second window
    for (let i = 0; i < sorted.length; i++) {
      const windowStart = sorted[i].timestamp.getTime();
      const windowEnd = windowStart + 60_000;
      const window = sorted.filter(e => e.timestamp.getTime() >= windowStart && e.timestamp.getTime() <= windowEnd);

      if (window.length >= 5) {
        const isCritical = window.length >= 10;
        const users = [...new Set(window.map(e => e.username).filter(Boolean))] as string[];

        results.push({
          triggered: true,
          severity: isCritical ? 'critical' : 'high',
          confidence: Math.min(100, 60 + window.length * 4),
          title: `SSH Brute Force from ${ip}`,
          description: `${window.length} failed SSH authentication attempts from ${ip} within 60 seconds.`,
          mitre_technique_id: 'T1110.001',
          mitre_technique_name: 'Brute Force: Password Guessing',
          mitre_tactic: 'Credential Access',
          evidence_event_ids: window.map(e => e.id),
          source_ips: [ip],
          targeted_users: users,
          details: {
            attempt_count: window.length,
            window_seconds: 60,
            window_start: new Date(windowStart).toISOString(),
            window_end: new Date(windowEnd).toISOString(),
          },
        });
        break; // one incident per IP
      }
    }
  }

  return results;
}

export function detectLowAndSlowBruteForce(events: LogEvent[]): DetectionResult[] {
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
    if (sorted.length < 10) continue;

    const span = sorted[sorted.length - 1].timestamp.getTime() - sorted[0].timestamp.getTime();
    if (span < 600_000) continue; // at least 10 minutes span

    // Check low rate: < 5 per minute in any window
    let isLowAndSlow = true;
    for (let i = 0; i < sorted.length; i++) {
      const w = sorted[i].timestamp.getTime();
      const inMinute = sorted.filter(e => e.timestamp.getTime() >= w && e.timestamp.getTime() <= w + 60_000);
      if (inMinute.length >= 5) { isLowAndSlow = false; break; }
    }

    if (isLowAndSlow && sorted.length >= 10) {
      const users = [...new Set(sorted.map(e => e.username).filter(Boolean))] as string[];
      results.push({
        triggered: true,
        severity: 'high',
        confidence: 75,
        title: `Low-and-Slow Brute Force from ${ip}`,
        description: `${sorted.length} failed attempts from ${ip} over ${Math.round(span / 60000)} minutes, evading rate-based detection.`,
        mitre_technique_id: 'T1110.003',
        mitre_technique_name: 'Brute Force: Password Spraying',
        mitre_tactic: 'Credential Access',
        evidence_event_ids: sorted.map(e => e.id),
        source_ips: [ip],
        targeted_users: users,
        details: { attempt_count: sorted.length, span_minutes: Math.round(span / 60000) },
      });
    }
  }

  return results;
}
