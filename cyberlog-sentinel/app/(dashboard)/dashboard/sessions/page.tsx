'use client';
import { useState, useEffect } from 'react';
import { getSupabaseClient } from '@/lib/supabase/client';
import { Terminal, AlertTriangle } from 'lucide-react';
import { format } from 'date-fns';

interface Session {
  id: string;
  username: string | null;
  source_ip: string | null;
  login_time: string | null;
  logout_time: string | null;
  duration_seconds: number | null;
  sudo_commands: string[];
  status: string;
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return '—';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [jobId, setJobId] = useState<string | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    const supabase = getSupabaseClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;
    const { data: jobs } = await supabase.from('upload_jobs').select('id').eq('user_id', user.id).eq('status', 'complete').order('created_at', { ascending: false }).limit(1);
    const jid = jobs?.[0]?.id ?? null;
    setJobId(jid);
    if (!jid) { setLoading(false); return; }
    const { data } = await supabase.from('ssh_sessions').select('*').eq('job_id', jid).order('login_time', { ascending: false });
    setSessions((data ?? []) as Session[]);
    setLoading(false);
  }

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>SSH Sessions</h1>
        <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>{sessions.length} reconstructed sessions from login/logout pairs</p>
      </div>

      <div className="glass-card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                {['User', 'Source IP', 'Login', 'Logout', 'Duration', 'Sudo Commands', 'Status'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '0.75rem 1rem', fontSize: '0.7rem', fontWeight: 600, color: '#8892A4', letterSpacing: '0.05em', textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  {Array.from({ length: 7 }).map((_, j) => <td key={j} style={{ padding: '0.75rem 1rem' }}><div className="skeleton" style={{ height: 16 }} /></td>)}
                </tr>
              )) : sessions.length === 0 ? (
                <tr><td colSpan={7} style={{ textAlign: 'center', padding: '3rem', color: '#8892A4' }}>{jobId ? 'No sessions reconstructed.' : 'Upload a log file to see SSH sessions.'}</td></tr>
              ) : sessions.map(s => {
                const suspicious = s.sudo_commands && s.sudo_commands.length > 0;
                return (
                  <tr key={s.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', background: s.status === 'active' ? 'rgba(255,184,0,0.04)' : 'transparent' }}>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: '#00D4FF' }}>{s.username ?? '—'}</td>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: '#00FF88' }}>{s.source_ip ?? '—'}</td>
                    <td style={{ padding: '0.75rem 1rem', color: '#8892A4', whiteSpace: 'nowrap' }}>{s.login_time ? format(new Date(s.login_time), 'MMM dd HH:mm:ss') : '—'}</td>
                    <td style={{ padding: '0.75rem 1rem', color: '#8892A4', whiteSpace: 'nowrap' }}>{s.logout_time ? format(new Date(s.logout_time), 'MMM dd HH:mm:ss') : '—'}</td>
                    <td style={{ padding: '0.75rem 1rem', color: '#E8EDF5' }}>{formatDuration(s.duration_seconds)}</td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      {suspicious ? (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.75rem', color: '#FFB800' }}>
                          <AlertTriangle size={12} /> {s.sudo_commands.length} command{s.sudo_commands.length !== 1 ? 's' : ''}
                        </span>
                      ) : <span style={{ color: '#4A5568', fontSize: '0.75rem' }}>None</span>}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem', fontWeight: 600, color: s.status === 'active' ? '#FFB800' : '#34C759' }}>
                        <Terminal size={12} /> {s.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
