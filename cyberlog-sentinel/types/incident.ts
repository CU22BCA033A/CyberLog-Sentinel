import type { Severity } from './log-event';

export interface Incident {
  id: string;
  job_id: string;
  incident_ref: string;
  title: string;
  description: string | null;
  severity: Severity;
  status: 'open' | 'investigating' | 'closed' | 'false_positive';
  mitre_technique_id: string | null;
  mitre_tactic: string | null;
  source_ips: string[];
  targeted_users: string[];
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  assigned_to: string | null;
  analyst_notes: string | null;
  is_false_positive: boolean;
  created_at: string;
  updated_at: string;
}

export interface SSHSession {
  id: string;
  job_id: string;
  session_key: string | null;
  username: string | null;
  source_ip: string | null;
  login_time: string | null;
  logout_time: string | null;
  duration_seconds: number | null;
  sudo_commands: string[];
  status: 'active' | 'closed';
  created_at: string;
}
