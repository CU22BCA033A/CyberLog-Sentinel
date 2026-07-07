'use client';
import { useState, useEffect } from 'react';
import { getSupabaseClient } from '@/lib/supabase/client';
import { getLatestJobId } from '@/lib/utils/get-job';
import { Terminal, AlertTriangle, Clock, Globe, User } from 'lucide-react';
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

function formatDuration(s: number | null): string {
  if (s === null) return '—';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [jobId, setJobId] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      setLoading(true);
      const jid = await getLatestJobId();
      setJobId(jid);
      if (!jid) { setLoading(false); return; }
      const supabase = getSupabaseClient();
      const { data } = await supabase
        .from('ssh_sessions')
        .select('*')
        .eq('job_id', jid)
        .order('login_time', { ascending: false });
      setSessions((data ?? []) as Session[]);
      setLoading(false);
    }
    load();
  }, []);

  const activeSessions = sessions.filter(s => s.status === 'active');
  const suspiciousSessions = sessions.filter(s => s.sudo_commands && s.sudo_commands.length > 0);

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>SSH Sessions</h1>
        <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>
          {sessions.length} reconstructed sessions from login/logout pairs
        </p>
      </div>

      {sessions.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '0.75rem', marginBottom: '1.5rem' }}>
          {[
            { label: 'Total Sessions', value: sessions.length, color: '#00D4FF' },
            { label: 'Active Now', value: activeSessions.length, color: '#FFB800' },
            { label: 'With Sudo', value: suspiciousSessions.length, color: '#FF6B35' },
            { label: 'Unique Users', value: new Set(sessions.map(s => s.username).filter(Boolean)).size, color: '#00FF88' },
          ].map(m => (
            <div key={m.label} className="glass-card" style={{ padding: '1rem', borderTop: `2px solid ${m.color}` }}>
              <div style={{ fontSize: '1.75rem', fontWeight: 800, color: m.color, fontFamily: 'JetBrains Mono, monospace', lineHeight: 1 }}>{m.value}</div>
              <div style={{ fontSize: '0.75rem', color: '#8892A4', marginTop: '0.25rem' }}>{m.label}</div>
            </div>
          ))}
        </div>
      )}

      <div className="glass-card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                {['User', 'Source IP', 'Login Time', 'Logout Time', 'Duration', 'Sudo Commands', 'Status'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '0.75rem 1rem', fontSize: '0.7rem', fontWeight: 600, color: '#8892A4', letterSpacing: '0.05em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 6 }).map((_, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    {Array.from({ length: 7 }).map((_, j) => (
                      <td key={j} style={{ padding: '0.75rem 1rem' }}>
                        <div className="skeleton" style={{ height: 16, width: '80%' }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : sessions.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '3rem', color: '#8892A4' }}>
                    {jobId
                      ? 'No SSH sessions found. Sessions are reconstructed from pam_unix session opened/closed log pairs.'
                      : 'Upload a log file to see SSH sessions.'}
                  </td>
                </tr>
              ) : (
                sessions.map(s => {
                  const suspicious = s.sudo_commands && s.sudo_commands.length > 0;
                  const isActive = s.status === 'active';
                  return (
                    <>
                      <tr
                        key={s.id}
                        onClick={() => suspicious && setExpandedId(expandedId === s.id ? null : s.id)}
                        style={{
                          borderBottom: '1px solid rgba(255,255,255,0.04)',
                          background: isActive ? 'rgba(255,184,0,0.04)' : suspicious ? 'rgba(255,107,53,0.04)' : 'transparent',
                          cursor: suspicious ? 'pointer' : 'default',
                        }}
                      >
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: '#00D4FF' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                            <User size={12} />{s.username ?? '—'}
                          </div>
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: '#00FF88' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                            <Globe size={12} />{s.source_ip ?? '—'}
                          </div>
                        </td>
                        <td style={{ padding: '0.75rem 1rem', color: '#8892A4', whiteSpace: 'nowrap' }}>
                          {s.login_time ? format(new Date(s.login_time), 'MMM dd HH:mm:ss') : '—'}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', color: '#8892A4', whiteSpace: 'nowrap' }}>
                          {s.logout_time ? format(new Date(s.logout_time), 'MMM dd HH:mm:ss') : (
                            <span style={{ color: '#FFB800', fontSize: '0.75rem' }}>Still active</span>
                          )}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', color: '#E8EDF5', fontFamily: 'JetBrains Mono, monospace' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                            <Clock size={12} color="#4A5568" />{formatDuration(s.duration_seconds)}
                          </div>
                        </td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          {suspicious ? (
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem', color: '#FF6B35', background: 'rgba(255,107,53,0.1)', padding: '2px 8px', borderRadius: 4 }}>
                              <AlertTriangle size={11} /> {s.sudo_commands.length} command{s.sudo_commands.length !== 1 ? 's' : ''}
