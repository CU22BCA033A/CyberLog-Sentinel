import type { EventType, Severity } from '@/types/log-event';

export const EVENT_TYPE_LABELS: Record<EventType, string> = {
  ssh_failed_password: 'SSH Failed Password',
  ssh_accepted_password: 'SSH Login Success (Password)',
  ssh_accepted_publickey: 'SSH Login Success (Key)',
  ssh_invalid_user: 'SSH Invalid User',
  ssh_disconnect: 'SSH Disconnect',
  ssh_connection_closed: 'SSH Connection Closed',
  ssh_max_attempts: 'SSH Max Attempts Exceeded',
  pam_auth_failure: 'PAM Auth Failure',
  pam_session_opened: 'Session Opened',
  pam_session_closed: 'Session Closed',
  sudo_command: 'Sudo Command',
  su_success: 'Su Success',
  su_failure: 'Su Failure',
  systemd_new_session: 'New Session',
  cron_session: 'Cron Session',
  unknown: 'Unknown',
};

export const DEFAULT_SEVERITY_MAP: Record<EventType, Severity> = {
  ssh_failed_password: 'low',
  ssh_accepted_password: 'info',
  ssh_accepted_publickey: 'info',
  ssh_invalid_user: 'medium',
  ssh_disconnect: 'info',
  ssh_connection_closed: 'info',
  ssh_max_attempts: 'high',
  pam_auth_failure: 'medium',
  pam_session_opened: 'info',
  pam_session_closed: 'info',
  sudo_command: 'low',
  su_success: 'medium',
  su_failure: 'medium',
  systemd_new_session: 'info',
  cron_session: 'info',
  unknown: 'info',
};
