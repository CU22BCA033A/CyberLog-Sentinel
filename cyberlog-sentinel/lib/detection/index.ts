import type { LogEvent } from '@/types/log-event';
import type { DetectionResult } from '@/types/detection';
import { detectBruteForce, detectLowAndSlowBruteForce } from './rules/brute-force';
import { detectPasswordSpray } from './rules/password-spray';
import { detectRootLogin, detectSuccessAfterBruteForce } from './rules/root-login';
import { detectSudoEscalation } from './rules/sudo-escalation';
import {
  detectOffHoursAuth,
  detectGlobalFailureFlood,
  detectInvalidUserAttempts,
  detectRepeatedPAMFailures,
  detectNonStandardPort,
} from './rules/off-hours';
import { detectWebAttacks, detectPortScan } from './rules/web-attacks';

export interface RuleResult {
  rule_id: string;
  rule_name: string;
  detections: DetectionResult[];
}

const RULES: Array<{ id: string; name: string; fn: (events: LogEvent[]) => DetectionResult[] }> = [
  { id: 'brute_force_ssh', name: 'SSH Brute Force', fn: detectBruteForce },
  { id: 'low_slow_brute', name: 'Low-and-Slow Brute Force', fn: detectLowAndSlowBruteForce },
  { id: 'password_spray', name: 'Password Spray', fn: detectPasswordSpray },
  { id: 'root_login', name: 'Root Login Detection', fn: detectRootLogin },
  { id: 'success_after_bruteforce', name: 'Successful Login After Brute Force', fn: detectSuccessAfterBruteForce },
  { id: 'sudo_shell_escape', name: 'Sudo Shell Escape', fn: detectSudoEscalation },
  { id: 'off_hours_auth', name: 'Off-Hours Authentication', fn: detectOffHoursAuth },
  { id: 'global_failure_flood', name: 'Coordinated Attack', fn: detectGlobalFailureFlood },
  { id: 'invalid_user_enum', name: 'Invalid User Enumeration', fn: detectInvalidUserAttempts },
  { id: 'repeated_pam_failures', name: 'Repeated PAM Failures', fn: detectRepeatedPAMFailures },
  { id: 'non_standard_port', name: 'Non-Standard Source Port', fn: detectNonStandardPort },
  { id: 'web_attacks', name: 'Web Application Attacks', fn: detectWebAttacks },
  { id: 'port_scan', name: 'Port Scan Detection', fn: detectPortScan },
];

export function runAllDetections(events: LogEvent[]): RuleResult[] {
  return RULES.map(rule => ({
    rule_id: rule.id,
    rule_name: rule.name,
    detections: rule.fn(events).filter(d => d.triggered),
  }));
}

export { RULES };
