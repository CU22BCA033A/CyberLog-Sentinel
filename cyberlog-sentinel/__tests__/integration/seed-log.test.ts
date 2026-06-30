import * as fs from 'fs';
import * as path from 'path';
import { parseLogContent } from '@/lib/parser';
import { runAllDetections } from '@/lib/detection';

describe('seed log end-to-end verification', () => {
  const content = fs.readFileSync(path.join(__dirname, '../../supabase/seed-logs/realistic-attack.log'), 'utf-8');

  it('parses the seed log without crashing and produces few unknowns', () => {
    const events = parseLogContent(content);
    expect(events.length).toBeGreaterThan(50);
    const unknowns = events.filter(e => e.event_type === 'unknown');
    expect(unknowns.length).toBe(0);
  });

  it('detects the brute force campaign from 185.220.101.45', () => {
    const events = parseLogContent(content);
    const results = runAllDetections(events);
    const bruteForce = results.find(r => r.rule_id === 'brute_force_ssh');
    expect(bruteForce!.detections.length).toBeGreaterThan(0);
    expect(bruteForce!.detections.some(d => d.source_ips.includes('185.220.101.45'))).toBe(true);
  });

  it('detects the password spray from 203.0.113.77 and 198.51.100.88', () => {
    const events = parseLogContent(content);
    const results = runAllDetections(events);
    const spray = results.find(r => r.rule_id === 'password_spray');
    expect(spray!.detections.length).toBeGreaterThan(0);
  });

  it('detects the successful root compromise after brute force', () => {
    const events = parseLogContent(content);
    const results = runAllDetections(events);
    const compromise = results.find(r => r.rule_id === 'success_after_bruteforce');
    expect(compromise!.detections.length).toBeGreaterThan(0);
    expect(compromise!.detections[0].severity).toBe('critical');
  });

  it('detects direct root login as critical (external IP)', () => {
    const events = parseLogContent(content);
    const results = runAllDetections(events);
    const rootLogin = results.find(r => r.rule_id === 'root_login');
    expect(rootLogin!.detections.length).toBeGreaterThan(0);
    expect(rootLogin!.detections.some(d => d.severity === 'critical')).toBe(true);
  });

  it('detects sudo shell escape from the compromised root session', () => {
    const events = parseLogContent(content);
    const results = runAllDetections(events);
    const shellEscape = results.find(r => r.rule_id === 'sudo_shell_escape');
    expect(shellEscape!.detections.length).toBeGreaterThan(0);
  });

  it('detects off-hours authentication', () => {
    const events = parseLogContent(content);
    const results = runAllDetections(events);
    const offHours = results.find(r => r.rule_id === 'off_hours_auth');
    expect(offHours!.detections.length).toBeGreaterThan(0);
  });
});
