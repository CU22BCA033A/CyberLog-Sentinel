import { parseLogContent } from '@/lib/parser';
import { detectBruteForce } from '@/lib/detection/rules/brute-force';
import { detectPasswordSpray } from '@/lib/detection/rules/password-spray';
import { detectRootLogin, detectSuccessAfterBruteForce } from '@/lib/detection/rules/root-login';
import type { LogEvent } from '@/types/log-event';

function makeEvent(overrides: Partial<LogEvent>): LogEvent {
  return {
    id: `evt_${Math.random()}`,
    timestamp: new Date(2024, 0, 15, 3, 0, 0),
    hostname: 'test-host',
    service: 'sshd',
    pid: 1000,
    event_type: 'ssh_failed_password',
    username: 'root',
    source_ip: '192.168.1.100',
    source_port: 12345,
    auth_method: 'password',
    outcome: 'failure',
    raw_line: 'test line',
    severity: 'low',
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
    ...overrides,
  };
}

describe('detectBruteForce', () => {
  it('does NOT trigger with 4 failures', () => {
    const base = new Date(2024, 0, 15, 3, 0, 0).getTime();
    const events = Array.from({ length: 4 }).map((_, i) =>
      makeEvent({ timestamp: new Date(base + i * 5000), source_ip: '10.0.0.1' })
    );
    const results = detectBruteForce(events);
    expect(results.length).toBe(0);
  });

  it('triggers (high) with exactly 5 failures within 60s', () => {
    const base = new Date(2024, 0, 15, 3, 0, 0).getTime();
    const events = Array.from({ length: 5 }).map((_, i) =>
      makeEvent({ timestamp: new Date(base + i * 5000), source_ip: '10.0.0.2' })
    );
    const results = detectBruteForce(events);
    expect(results.length).toBe(1);
    expect(results[0].severity).toBe('high');
    expect(results[0].triggered).toBe(true);
  });

  it('triggers (critical) with 10+ failures within 60s', () => {
    const base = new Date(2024, 0, 15, 3, 0, 0).getTime();
    const events = Array.from({ length: 10 }).map((_, i) =>
      makeEvent({ timestamp: new Date(base + i * 5000), source_ip: '10.0.0.3' })
    );
    const results = detectBruteForce(events);
    expect(results.length).toBe(1);
    expect(results[0].severity).toBe('critical');
  });

  it('does not flag failures spread far beyond the 60s window', () => {
    const base = new Date(2024, 0, 15, 3, 0, 0).getTime();
    const events = Array.from({ length: 5 }).map((_, i) =>
      makeEvent({ timestamp: new Date(base + i * 30 * 60 * 1000), source_ip: '10.0.0.4' })
    );
    const results = detectBruteForce(events);
    expect(results.length).toBe(0);
  });
});

describe('detectPasswordSpray', () => {
  it('does NOT trigger with only 2 distinct usernames', () => {
    const base = new Date(2024, 0, 15, 3, 0, 0).getTime();
    const events = [
      makeEvent({ timestamp: new Date(base), username: 'alice', source_ip: '10.0.0.5' }),
      makeEvent({ timestamp: new Date(base + 1000), username: 'bob', source_ip: '10.0.0.5' }),
    ];
    const results = detectPasswordSpray(events);
    expect(results.length).toBe(0);
  });

  it('triggers with 3 distinct usernames within 2 minutes', () => {
    const base = new Date(2024, 0, 15, 3, 0, 0).getTime();
    const events = [
      makeEvent({ timestamp: new Date(base), username: 'alice', source_ip: '10.0.0.6' }),
      makeEvent({ timestamp: new Date(base + 1000), username: 'bob', source_ip: '10.0.0.6' }),
      makeEvent({ timestamp: new Date(base + 2000), username: 'carol', source_ip: '10.0.0.6' }),
    ];
    const results = detectPasswordSpray(events);
    expect(results.length).toBe(1);
    expect(results[0].targeted_users.sort()).toEqual(['alice', 'bob', 'carol']);
  });
});

describe('detectRootLogin', () => {
  it('flags internal IP root login as high severity', () => {
    const events = [
      makeEvent({ event_type: 'ssh_accepted_password', outcome: 'success', username: 'root', source_ip: '10.0.0.1', is_internal_ip: true }),
    ];
    const results = detectRootLogin(events);
    expect(results.length).toBe(1);
    expect(results[0].severity).toBe('high');
  });

  it('flags external IP root login as critical severity', () => {
    const events = [
      makeEvent({ event_type: 'ssh_accepted_password', outcome: 'success', username: 'root', source_ip: '203.0.113.5', is_internal_ip: false }),
    ];
    const results = detectRootLogin(events);
    expect(results.length).toBe(1);
    expect(results[0].severity).toBe('critical');
  });

  it('does not flag non-root logins', () => {
    const events = [
      makeEvent({ event_type: 'ssh_accepted_password', outcome: 'success', username: 'alice', source_ip: '10.0.0.1' }),
    ];
    const results = detectRootLogin(events);
    expect(results.length).toBe(0);
  });
});

describe('detectSuccessAfterBruteForce', () => {
  it('only triggers if same IP had >= 3 prior failures', () => {
    const base = new Date(2024, 0, 15, 3, 0, 0).getTime();
    const eventsInsufficient = [
      makeEvent({ timestamp: new Date(base), source_ip: '10.0.0.9', outcome: 'failure' }),
      makeEvent({ timestamp: new Date(base + 1000), source_ip: '10.0.0.9', outcome: 'failure' }),
      makeEvent({ timestamp: new Date(base + 60000), source_ip: '10.0.0.9', outcome: 'success', event_type: 'ssh_accepted_password', username: 'root' }),
    ];
    expect(detectSuccessAfterBruteForce(eventsInsufficient).length).toBe(0);

    const eventsSufficient = [
      makeEvent({ timestamp: new Date(base), source_ip: '10.0.0.10', outcome: 'failure' }),
      makeEvent({ timestamp: new Date(base + 1000), source_ip: '10.0.0.10', outcome: 'failure' }),
      makeEvent({ timestamp: new Date(base + 2000), source_ip: '10.0.0.10', outcome: 'failure' }),
      makeEvent({ timestamp: new Date(base + 60000), source_ip: '10.0.0.10', outcome: 'success', event_type: 'ssh_accepted_password', username: 'root' }),
    ];
    const results = detectSuccessAfterBruteForce(eventsSufficient);
    expect(results.length).toBe(1);
    expect(results[0].severity).toBe('critical');
  });
});

describe('end-to-end: parser + detection on seed-like content', () => {
  it('detects brute force from a realistic burst of failed logins', () => {
    const lines: string[] = [];
    const startHour = 3, startMin = 22;
    for (let i = 0; i < 12; i++) {
      const sec = i * 2;
      lines.push(`Jan 15 0${startHour}:${startMin}:${String(sec).padStart(2, '0')} ubuntu sshd[900${i}]: Failed password for root from 185.220.101.45 port ${54000 + i} ssh2`);
    }
    const content = lines.join('\n');
    const events = parseLogContent(content);
    expect(events.length).toBe(12);
    const detections = detectBruteForce(events);
    expect(detections.length).toBeGreaterThan(0);
    expect(detections[0].source_ips).toContain('185.220.101.45');
  });
});
