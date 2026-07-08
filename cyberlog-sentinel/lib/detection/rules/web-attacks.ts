import type { LogEvent } from '@/types/log-event';
import type { DetectionResult } from '@/types/detection';

export function detectWebAttacks(_events: LogEvent[]): DetectionResult[] {
  return [];
}

export function detectPortScan(_events: LogEvent[]): DetectionResult[] {
  return [];
}

export function detectTaggedAttacks(events: LogEvent[]): DetectionResult[] {
  const results: DetectionResult[] = [];

  const groups: Record<string, {
    events: LogEvent[];
    mitre_id: string;
    mitre_name: string;
    tactic: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
  }> = {
    sql_injection: { events: [], mitre_id: 'T1190', mitre_name: 'Exploit Public-Facing Application (SQLi)', tactic: 'Initial Access', severity: 'critical', title: 'SQL Injection Detected' },
    xss: { events: [], mitre_id: 'T1059.007', mitre_name: 'XSS / Script Injection', tactic: 'Execution', severity: 'high', title: 'Cross-Site Scripting (XSS) Detected' },
    command_injection: { events: [], mitre_id: 'T1059', mitre_name: 'Command Injection', tactic: 'Execution', severity: 'critical', title: 'Command Injection Detected' },
    directory_traversal: { events: [], mitre_id: 'T1083', mitre_name: 'Directory Traversal / Path Traversal', tactic: 'Discovery', severity: 'high', title: 'Directory Traversal Detected' },
    traversal: { events: [], mitre_id: 'T1083', mitre_name: 'Directory Traversal / Path Traversal', tactic: 'Discovery', severity: 'high', title: 'Directory Traversal Detected' },
    ransomware: { events: [], mitre_id: 'T1486', mitre_name: 'Data Encrypted for Impact (Ransomware)', tactic: 'Impact', severity: 'critical', title: 'Ransomware Activity Detected' },
    data_exfiltration: { events: [], mitre_id: 'T1041', mitre_name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', severity: 'critical', title: 'Data Exfiltration Detected' },
    reverse_shell: { events: [], mitre_id: 'T1059.004', mitre_name: 'Unix Shell / Reverse Shell', tactic: 'Execution', severity: 'critical', title: 'Reverse Shell Detected' },
    credential_dumping: { events: [], mitre_id: 'T1003', mitre_name: 'OS Credential Dumping', tactic: 'Credential Access', severity: 'critical', title: 'Credential Dumping Detected' },
    web_shell: { events: [], mitre_id: 'T1505.003', mitre_name: 'Web Shell', tactic: 'Persistence', severity: 'critical', title: 'Web Shell Detected' },
    port_scan: { events: [], mitre_id: 'T1046', mitre_name: 'Network Service Discovery (Port Scan)', tactic: 'Discovery', severity: 'medium', title: 'Port Scan Detected' },
    privesc: { events: [], mitre_id: 'T1548.003', mitre_name: 'Sudo and Sudo Caching', tactic: 'Privilege Escalation', severity: 'high', title: 'Privilege Escalation Detected' },
  };

  for (const evt of events) {
    for (const tag of evt.threat_tags) {
      if (groups[tag]) groups[tag].events.push(evt);
    }
    const typeKey = evt.event_type as string;
    if (groups[typeKey]) groups[typeKey].events.push(evt);
  }

  // Merge traversal aliases to avoid duplicates
  const traversalCombined = [...groups['traversal'].events, ...groups['directory_traversal'].events];
  groups['directory_traversal'].events = [...new Map(traversalCombined.map(e => [e.id, e])).values()];
  groups['traversal'].events = [];

  for (const [, group] of Object.entries(groups)) {
    const unique = [...new Map(group.events.map(e => [e.id, e])).values()];
    if (unique.length === 0) continue;

    const ips = [...new Set(unique.map(e => e.source_ip).filter(Boolean))] as string[];
    const users = [...new Set(unique.map(e => e.username).filter(Boolean))] as string[];
    const timestamps = unique.map(e => e.timestamp.getTime());
    const confidence = Math.min(99, 80 + unique.length * 2);

    results.push({
      triggered: true,
      severity: group.severity,
      confidence,
      title: group.title,
      description: `${unique.length} log event(s) matched ${group.title.replace(' Detected', '')} indicators. Source IPs: ${ips.slice(0, 3).join(', ') || 'unknown'}.`,
      mitre_technique_id: group.mitre_id,
      mitre_technique_name: group.mitre_name,
      mitre_tactic: group.tactic,
      evidence_event_ids: unique.map(e => e.id),
      source_ips: ips,
      targeted_users: users,
      details: {
        matched_count: unique.length,
        first_seen: new Date(Math.min(...timestamps)).toISOString(),
        last_seen: new Date(Math.max(...timestamps)).toISOString(),
        sample_lines: unique.slice(0, 3).map(e => e.raw_line),
      },
    });
  }

  return results;
}
