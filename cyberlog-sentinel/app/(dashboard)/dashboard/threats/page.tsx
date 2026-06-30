'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { getSupabaseClient } from '@/lib/supabase/client';
import { AlertTriangle, Globe, Users, Clock } from 'lucide-react';
import { format } from 'date-fns';

interface Incident {
  id: string;
  incident_ref: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  mitre_technique_id: string | null;
  mitre_tactic: string | null;
  source_ips: string[];
  targeted_users: string[];
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATUS_COLORS: Record<string, string> = {
  open: '#FF3B30',
  investigating: '#FFB800',
  closed: '#34C759',
  false_positive: '#4A5568',
};

export default function ThreatsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
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

    const { data } = await supabase.from('incidents').select('*').eq('job_id', jid).order('severity', { ascending: true }).order('last_seen', { ascending: false });
    const sorted = (data ?? []).sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
    setIncidents(sorted as Incident[]);
    setLoading(false);
  }

  async function updateStatus(id: string, status: string) {
    const supabase = getSupabaseClient();
    await supabase.from('incidents').update({ status, updated_at: new Date().toISOString() }).eq('id', id);
    setIncidents(prev => prev.map(i => i.id === id ? { ...i, status } : i));
  }

  const filtered = statusFilter ? incidents.filter(i => i.status === statusFilter) : incidents;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Threat Incidents</h1>
          <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>{incidents.length} detected incidents from latest analysis</p>
        </div>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem', cursor: 'pointer' }}>
          <option value="">All Statuses</option>
          {['open', 'investigating', 'closed', 'false_positive'].map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
        </select>
      </div>

      {loading ? (
        <div style={{ display: 'grid', gap: '1rem' }}>
          {Array.from({ length: 4 }).map((_, i) => <div key={i} className="glass-card skeleton" style={{ height: 140 }} />)}
        </div>
      ) : !jobId ? (
        <div className="glass-card" style={{ padding: '3rem', textAlign: 'center', color: '#8892A4' }}>
          Upload a log file to detect threats and generate incidents.
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass-card" style={{ padding: '3rem', textAlign: 'center', color: '#8892A4' }}>No incidents match this filter.</div>
      ) : (
        <div style={{ display: 'grid', gap: '1rem' }}>
          {filtered.map(inc => (
            <div key={inc.id} className="glass-card" style={{ padding: '1.25rem', borderLeft: `3px solid ${inc.severity === 'critical' ? '#FF3B30' : inc.severity === 'high' ? '#FF6B35' : inc.severity === 'medium' ? '#FFB800' : '#4DC9FF'}` }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ flex: 1, minWidth: 250 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontSize: '0.7rem', fontFamily: 'JetBrains Mono, monospace', color: '#4A5568' }}>{inc.incident_ref}</span>
                    <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>
                    {inc.mitre_technique_id && (
                      <span style={{ fontSize: '0.7rem', fontFamily: 'JetBrains Mono, monospace', color: '#FFB800', background: 'rgba(255,184,0,0.1)', padding: '2px 6px', borderRadius: 4 }}>{inc.mitre_technique_id}</span>
                    )}
                  </div>
                  <Link href={`/dashboard/threats/${inc.id}`} style={{ textDecoration: 'none' }}>
                    <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#E8EDF5', margin: 0 }}>{inc.title}</h3>
                  </Link>
                  {inc.description && <p style={{ fontSize: '0.8125rem', color: '#8892A4', margin: '0.375rem 0 0' }}>{inc.description}</p>}
                </div>
                <select value={inc.status} onChange={e => updateStatus(inc.id, e.target.value)}
                  style={{ padding: '0.375rem 0.625rem', background: `${STATUS_COLORS[inc.status]}15`, border: `1px solid ${STATUS_COLORS[inc.status]}40`, borderRadius: '6px', color: STATUS_COLORS[inc.status], fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}>
                  {['open', 'investigating', 'closed', 'false_positive'].map(s => <option key={s} value={s} style={{ background: '#0F1520', color: '#E8EDF5' }}>{s.replace('_', ' ')}</option>)}
                </select>
              </div>

              <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', fontSize: '0.8125rem', color: '#8892A4' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                  <AlertTriangle size={14} /> {inc.event_count} events
                </div>
                {inc.source_ips.length > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                    <Globe size={14} />
                    <span className="mono" style={{ color: '#00FF88' }}>{inc.source_ips.slice(0, 3).join(', ')}</span>
                    {inc.source_ips.length > 3 && ` +${inc.source_ips.length - 3} more`}
                  </div>
                )}
                {inc.targeted_users.length > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                    <Users size={14} />
                    <span className="mono" style={{ color: '#00D4FF' }}>{inc.targeted_users.slice(0, 3).join(', ')}</span>
                    {inc.targeted_users.length > 3 && ` +${inc.targeted_users.length - 3} more`}
                  </div>
                )}
                {inc.first_seen && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                    <Clock size={14} /> {format(new Date(inc.first_seen), 'MMM dd HH:mm')} → {inc.last_seen ? format(new Date(inc.last_seen), 'HH:mm') : '?'}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
