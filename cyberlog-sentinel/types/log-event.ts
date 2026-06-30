export type EventType =
  | 'ssh_failed_password'
  | 'ssh_accepted_password'
  | 'ssh_accepted_publickey'
  | 'ssh_invalid_user'
  | 'ssh_disconnect'
  | 'ssh_connection_closed'
  | 'ssh_max_attempts'
  | 'pam_auth_failure'
  | 'pam_session_opened'
  | 'pam_session_closed'
  | 'sudo_command'
  | 'su_success'
  | 'su_failure'
  | 'systemd_new_session'
  | 'cron_session'
  | 'unknown';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Outcome = 'success' | 'failure' | 'unknown';

export interface LogEvent {
  id: string;
  timestamp: Date;
  hostname: string;
  service: string;
  pid: number | null;
  event_type: EventType;
  username: string | null;
  source_ip: string | null;
  source_port: number | null;
  auth_method: string | null;
  outcome: Outcome;
  raw_line: string;
  severity: Severity;
  mitre_technique_id: string | null;
  mitre_technique_name: string | null;
  mitre_tactic: string | null;
  threat_tags: string[];
  session_id: string | null;
  geo_country: string | null;
  geo_city: string | null;
  is_internal_ip: boolean;
  analyst_note: string | null;
  is_false_positive: boolean;
}

export interface UploadJob {
  id: string;
  user_id: string;
  filename: string;
  file_size_bytes: number;
  storage_path: string | null;
  status: 'pending' | 'processing' | 'complete' | 'failed';
  total_lines: number | null;
  parsed_lines: number;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}
