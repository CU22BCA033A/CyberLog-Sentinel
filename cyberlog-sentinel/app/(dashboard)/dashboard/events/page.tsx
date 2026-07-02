'use client';
import { useState, useEffect } from 'react';
import { getSupabaseClient } from '@/lib/supabase/client';
import { getLatestJobId } from '@/lib/utils/get-job';
import { Search, Download, ChevronLeft, ChevronRight, ChevronDown, ChevronUp } from 'lucide-react';
import { format } from 'date-fns';

interface LogEvent {
  id: string; timestamp: string; event_type: string; username: string | null;
  source_ip: string | null; source_port: number | null; service: string;
  outcome: string; severity: string; mitre_technique_id: string | null;
  mitre_technique_name: string | null; raw_line: string;
}

const PAGE_SIZE = 50;

export default function EventsPage() {
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [jobId, setJobId] = useState<string | null>(null);
  const [sortAsc, setSortAsc] = useState(false);

  useEffect(() => {
    getLatestJobId().then(id => setJobId(id));
  }, []);

  useEffect(() => {
    if (jobId !== undefined) loadEvents();
  }, [jobId, page, severityFilter, outcomeFilter, sortAsc]);

  async function loadEvents() {
    if (!jobId) { setLoading(false); return; }
    setLoading(true);
    const supabase = getSupabaseClient();
    let query = supabase
      .from('log_events')
      .select('id,timestamp,event_type,username,source_ip,source_port,service,outcome,severity,mitre_technique_id,mitre_technique_name,raw_line', { count: 'exact' })
      .eq('job_id', jobId)
      .order('timestamp', { ascending: sortAsc })
      .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1);

    if (severityFilter) query = query.eq('severity', severityFilter);
    if (outcomeFilter) query = query.eq('outcome', outcomeFilter);
    if (search) query = query.ilike('raw_line', `%${search}%`);

    const { data, count } = await query;
    setEvents((data ?? []) as LogEvent[]);
    setTotal(count ?? 0);
    setLoading(false);
  }

  async function exportCSV() {
    if (!jobId) return;
    const supabase = getSupabaseClient();
    const { data } = await supabase.from('log_events').select('*').eq('job_id', jobId).limit(10000);
    if (!data || data.length === 0) return;
    const headers = Object.keys(data[0]);
    const csv = [headers.join(','), ...data.map(r => headers.map(h => JSON.stringify((r as Record<string, unknown>)[h] ?? '')).join(','))].join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = 'events.csv'; a.click();
  }

  const totalPages = Math.ceil(total / PAGE_SIZE);
  const COLS = ['Timestamp', 'Severity', 'Event Type', 'Username', 'Source IP', 'Service', 'Outcome', 'MITRE'];

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Events</h1>
          <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>{total.toLocaleString()} parsed log events</p>
        </div>
        <button onClick={exportCSV} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.625rem 1rem', background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#8892A4', cursor: 'pointer', fontSize: '0.8125rem' }}>
          <Download size={14} /> Export CSV
        </button>
      </div>

      <div className="glass-card" style={{ padding: '1rem', marginBottom: '1rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
          <Search size={14} style={{ position: 'absolute', left: '0.625rem', top: '50%', transform: 'translateY(-50%)', color: '#4A5568' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && loadEvents()}
            placeholder="Search raw log lines..." style={{ width: '100%', padding: '0.5rem 0.75rem 0.5rem 2rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem', outline: 'none', fontFamily: 'JetBrains Mono, monospace' }} />
        </div>
        <button onClick={() => { setPage(0); loadEvents(); }} style={{ padding: '0.5rem 1rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '6px', border: 'none', cursor: 'pointer', fontSize: '0.8125rem' }}>Search</button>
        <select value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(0); }}
          style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem', cursor: 'pointer' }}>
          <option value="">All Severity</option>
          {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={outcomeFilter} onChange={e => { setOutcomeFilter(e.target.value); setPage(0); }}
          style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem', cursor: 'pointer' }}>
          <option value="">All Outcomes</option>
          {['success', 'failure', 'unknown'].map(o => <option key={o} value={o}>{o}</option>)}
        </select>
        <button onClick={() => setSortAsc(a => !a)} style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#8892A4', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.8125rem' }}>
          Time {sortAsc ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>
      </div>

      <div className="glass-card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                {COLS.map(col => (
                  <th key={col} style={{ textAlign: 'left', padding: '0.75rem 1rem', fontSize: '0.7rem', fontWeight: 600, color: '#8892A4', letterSpacing: '0.05em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? Array.from({ length: 10 }).map((_, i) => (
                <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  {COLS.map(c => <td key={c} style={{ padding: '0.75rem 1rem' }}><div className="skeleton" style={{ height: 16 }} /></td>)}
                </tr>
              )) : events.length === 0 ? (
                <tr><td colSpan={COLS.length} style={{ textAlign: 'center', padding: '3rem', color: '#8892A4' }}>{jobId ? 'No events match your filters.' : 'Upload a log file to see events.'}</td></tr>
              ) : events.map(evt => (
                <>
                  <tr key={evt.id} onClick={() => setExpandedId(expandedId === evt.id ? null : evt.id)}
                    style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer', background: expandedId === evt.id ? 'rgba(255,255,255,0.03)' : 'transparent' }}>
                    <td style={{ padding: '0.75rem 1rem', whiteSpace: 'nowrap', fontFamily: 'JetBrains Mono, monospace', color: '#8892A4', fontSize: '0.7rem' }}>
                      {format(new Date(evt.timestamp), 'MMM dd HH:mm:ss')}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}><span className={`badge badge-${evt.severity}`}>{evt.severity}</span></td>
                    <td style={{ padding: '0.75rem 1rem', color: '#E8EDF5', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem', whiteSpace: 'nowrap' }}>{evt.event_type.replace(/_/g, ' ')}</td>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: evt.username ? '#00D4FF' : '#4A5568' }}>{evt.username ?? '—'}</td>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'JetBrains Mono, monospace', color: evt.source_ip ? '#00FF88' : '#4A5568', whiteSpace: 'nowrap' }}>{evt.source_ip ?? '—'}{evt.source_port ? `:${evt.source_port}` : ''}</td>
                    <td style={{ padding: '0.75rem 1rem', color: '#8892A4', fontFamily: 'JetBrains Mono, monospace' }}>{evt.service}</td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: evt.outcome === 'success' ? '#00FF88' : evt.outcome === 'failure' ? '#FF3B30' : '#8892A4', fontFamily: 'JetBrains Mono, monospace' }}>{evt.outcome}</span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      {evt.mitre_technique_id && <span style={{ fontSize: '0.7rem', fontFamily: 'JetBrains Mono, monospace', color: '#FFB800', background: 'rgba(255,184,0,0.1)', padding: '2px 6px', borderRadius: 4 }}>{evt.mitre_technique_id}</span>}
                    </td>
                  </tr>
                  {expandedId === evt.id && (
                    <tr key={`${evt.id}-exp`} style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.2)' }}>
                      <td colSpan={COLS.length} style={{ padding: '1rem 1.5rem' }}>
                        <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Raw Log Line</div>
                        <code style={{ display: 'block', padding: '0.75rem', background: 'rgba(0,0,0,0.4)', borderRadius: '6px', fontSize: '0.75rem', color: '#00FF88', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all', lineHeight: 1.6 }}>{evt.raw_line}</code>
                        <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap', marginTop: '0.75rem' }}>
                          {[['UTC', new Date(evt.timestamp).toUTCString()], ['Local', new Date(evt.timestamp).toLocaleString()], ['MITRE', evt.mitre_technique_id ? `${evt.mitre_technique_id} — ${evt.mitre_technique_name}` : 'None']].map(([l, v]) => (
                            <div key={l}>
                              <div style={{ fontSize: '0.65rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.25rem' }}>{l}</div>
                              <div style={{ fontSize: '0.8125rem', color: '#E8EDF5', fontFamily: 'JetBrains Mono, monospace' }}>{v}</div>
                            </div>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem 1rem', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <span style={{ fontSize: '0.8125rem', color: '#8892A4' }}>Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total.toLocaleString()}</span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
                style={{ width: 32, height: 32, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#8892A4', cursor: page === 0 ? 'not-allowed' : 'pointer', opacity: page === 0 ? 0.4 : 1 }}>
                <ChevronLeft size={14} />
              </button>
              <span style={{ display: 'flex', alignItems: 'center', padding: '0 0.75rem', fontSize: '0.8125rem', color: '#E8EDF5', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px' }}>{page + 1} / {totalPages}</span>
              <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
                style={{ width: 32, height: 32, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#8892A4', cursor: page >= totalPages - 1 ? 'not-allowed' : 'pointer', opacity: page >= totalPages - 1 ? 0.4 : 1 }}>
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
