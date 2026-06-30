import type { LogEvent, Severity } from './log-event';

export interface DetectionResult {
  triggered: boolean;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  mitre_tactic: string;
  evidence_event_ids: string[];
  source_ips: string[];
  targeted_users: string[];
  details: Record<string, unknown>;
}

export type DetectionRule = (events: LogEvent[]) => DetectionResult[];

export interface Detection {
  id: string;
  job_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  confidence: number;
  source_ip: string | null;
  username: string | null;
  event_ids: string[];
  mitre_technique_id: string | null;
  details: Record<string, unknown>;
  created_at: string;
}
