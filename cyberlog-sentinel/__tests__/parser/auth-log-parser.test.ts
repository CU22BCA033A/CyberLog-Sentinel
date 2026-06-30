import { parseLine, parseLogContent, parseTimestamp } from '@/lib/parser/auth-log-parser';

describe('auth-log-parser', () => {
  const fixedNow = new Date(2024, 0, 20); // Jan 20 2024, so "Jan 15" infers same year

  describe('parseTimestamp', () => {
    it('parses a standard syslog timestamp', () => {
      const ts = parseTimestamp('Jan', '15', '03:22:17', fixedNow);
      expect(ts.getMonth()).toBe(0);
      expect(ts.getDate()).toBe(15);
      expect(ts.getHours()).toBe(3);
      expect(ts.getMinutes()).toBe(22);
      expect(ts.getSeconds()).toBe(17);
    });

    it('infers previous year for December logs when current month is January', () => {
      const now = new Date(2024, 0, 5); // Jan 5 2024
      const ts = parseTimestamp('Dec', '28', '10:00:00', now);
      expect(ts.getFullYear()).toBe(2023);
    });

    it('uses current year for non-rollover cases', () => {
      const now = new Date(2024, 5, 15); // June 2024
      const ts = parseTimestamp('Jan', '15', '03:22:17', now);
      expect(ts.getFullYear()).toBe(2024);
    });
  });

  describe('parseLine - Failed password', () => {
    it('extracts IP, user, and port correctly', () => {
      const line = 'Jan 15 03:22:17 ubuntu sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2';
      const evt = parseLine(line, fixedNow);
      expect(evt).not.toBeNull();
      expect(evt!.event_type).toBe('ssh_failed_password');
      expect(evt!.username).toBe('root');
      expect(evt!.source_ip).toBe('192.168.1.100');
      expect(evt!.source_port).toBe(54321);
      expect(evt!.outcome).toBe('failure');
      expect(evt!.hostname).toBe('ubuntu');
      expect(evt!.service).toBe('sshd');
      expect(evt!.pid).toBe(1234);
    });

    it('handles invalid user prefix in failed password line', () => {
      const line = 'Jan 15 03:22:17 ubuntu sshd[1234]: Failed password for invalid user bob from 10.0.0.1 port 1234 ssh2';
      const evt = parseLine(line, fixedNow);
      expect(evt!.username).toBe('bob');
      expect(evt!.source_ip).toBe('10.0.0.1');
    });
  });

  describe('parseLine - Accepted password', () => {
    it('extracts correct fields for successful login', () => {
      const line = 'Jan 15 03:25:01 ubuntu sshd[1235]: Accepted password for john from 10.0.0.5 port 22 ssh2';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('ssh_accepted_password');
      expect(evt!.username).toBe('john');
      expect(evt!.source_ip).toBe('10.0.0.5');
      expect(evt!.outcome).toBe('success');
      expect(evt!.auth_method).toBe('password');
    });
  });

  describe('parseLine - Invalid user', () => {
    it('extracts username = the invalid username', () => {
      const line = 'Jan 15 03:22:18 ubuntu sshd[1236]: Invalid user admin from 192.168.1.100 port 54322';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('ssh_invalid_user');
      expect(evt!.username).toBe('admin');
      expect(evt!.source_ip).toBe('192.168.1.100');
      expect(evt!.outcome).toBe('failure');
    });
  });

  describe('parseLine - PAM failure', () => {
    it('extracts user and rhost from PAM failure message', () => {
      const line = 'Jan 15 03:22:19 ubuntu sshd[1237]: PAM 3 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.100 user=root';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('pam_auth_failure');
      expect(evt!.username).toBe('root');
      expect(evt!.source_ip).toBe('192.168.1.100');
    });
  });

  describe('parseLine - Sudo command', () => {
    it('extracts user, working dir, and command', () => {
      const line = 'Jan 15 09:15:33 ubuntu sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('sudo_command');
      expect(evt!.username).toBe('john');
      expect(evt!.raw_line).toContain('COMMAND=/bin/bash');
    });
  });

  describe('parseLine - Su attempt', () => {
    it('parses successful su', () => {
      const line = 'Jan 15 09:16:01 ubuntu su[1238]: Successful su for root by john';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('su_success');
      expect(evt!.username).toBe('john');
    });
  });

  describe('parseLine - no IP', () => {
    it('sets source_ip to null when no IP present', () => {
      const line = 'Jan 15 09:15:35 ubuntu sshd[1235]: pam_unix(sshd:session): session opened for user john by (uid=0)';
      const evt = parseLine(line, fixedNow);
      expect(evt!.source_ip).toBeNull();
      expect(evt!.event_type).toBe('pam_session_opened');
      expect(evt!.username).toBe('john');
    });
  });

  describe('parseLine - IPv6', () => {
    it('parses IPv6 addresses in failed password line', () => {
      const line = 'Jan 15 03:22:17 ubuntu sshd[1234]: Failed password for root from 2001:db8::1 port 54321 ssh2';
      const evt = parseLine(line, fixedNow);
      expect(evt!.source_ip).toBe('2001:db8::1');
    });
  });

  describe('parseLine - malformed lines', () => {
    it('does not crash on garbage input and returns unknown event', () => {
      const line = 'this is not a valid syslog line at all !!!';
      const evt = parseLine(line, fixedNow);
      expect(evt).not.toBeNull();
      expect(evt!.event_type).toBe('unknown');
    });

    it('handles empty lines by returning null', () => {
      expect(parseLine('', fixedNow)).toBeNull();
      expect(parseLine('   ', fixedNow)).toBeNull();
    });

    it('handles truncated lines gracefully', () => {
      const line = 'Jan 15 03:22';
      const evt = parseLine(line, fixedNow);
      expect(evt).not.toBeNull();
      expect(evt!.event_type).toBe('unknown');
    });
  });

  describe('parseLine - max authentication attempts', () => {
    it('parses port scan / max attempts exceeded line', () => {
      const line = 'Jan 15 03:22:20 ubuntu sshd[1239]: error: maximum authentication attempts exceeded for root from 192.168.1.100 port 54323 ssh2';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('ssh_max_attempts');
      expect(evt!.username).toBe('root');
      expect(evt!.source_ip).toBe('192.168.1.100');
    });
  });

  describe('parseLine - disconnected/connection closed', () => {
    it('parses disconnect line', () => {
      const line = 'Jan 15 03:30:00 ubuntu sshd[1235]: Disconnected from user john 10.0.0.5 port 22';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('ssh_disconnect');
      expect(evt!.username).toBe('john');
      expect(evt!.source_ip).toBe('10.0.0.5');
    });

    it('parses connection closed line', () => {
      const line = 'Jan 15 03:30:01 ubuntu sshd[1235]: Connection closed by 10.0.0.5 port 22';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('ssh_connection_closed');
      expect(evt!.source_ip).toBe('10.0.0.5');
    });
  });

  describe('parseLine - CRON session', () => {
    it('parses cron session opened', () => {
      const line = 'Jan 15 09:00:01 ubuntu CRON[2100]: pam_unix(cron:session): session opened for user root by (uid=0)';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('pam_session_opened');
      expect(evt!.username).toBe('root');
    });
  });

  describe('parseLine - new session (systemd-logind)', () => {
    it('extracts session id and username', () => {
      const line = 'Jan 15 09:15:34 ubuntu systemd-logind[800]: New session 42 of user john.';
      const evt = parseLine(line, fixedNow);
      expect(evt!.event_type).toBe('systemd_new_session');
      expect(evt!.session_id).toBe('42');
      expect(evt!.username).toBe('john');
    });
  });

  describe('parseLogContent', () => {
    it('parses multiple lines and skips blanks', () => {
      const content = [
        'Jan 15 03:22:17 ubuntu sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2',
        '',
        'Jan 15 03:25:01 ubuntu sshd[1235]: Accepted password for john from 10.0.0.5 port 22 ssh2',
      ].join('\n');
      const events = parseLogContent(content);
      expect(events.length).toBe(2);
      expect(events[0].event_type).toBe('ssh_failed_password');
      expect(events[1].event_type).toBe('ssh_accepted_password');
    });

    it('never throws on a batch with mixed valid/invalid lines', () => {
      const content = [
        'garbage line one',
        'Jan 15 03:22:17 ubuntu sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2',
        '{{not json or syslog}}',
      ].join('\n');
      expect(() => parseLogContent(content)).not.toThrow();
      const events = parseLogContent(content);
      expect(events.length).toBe(3);
    });
  });
});
