'use client';
import { useState } from 'react';
import Link from 'next/link';
import { getSupabaseClient } from '@/lib/supabase/client';
import { Search as SearchIcon, Globe, User, FileText, Shield } from 'lucide-react';

interface SearchResults {
  ips: Array<{ source_ip: string; count: number }>;
  users: Array<{ username: string; count: number }>;
  rawLines: Array<{ id: string; raw_line: string; timestamp: string }>;
  incidents: Array<{ id: string; title: string; incident_ref: string; severity: string }>;
}

export default function SearchPage() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResults | null>(null);
  const [loading, setLoading] = useState(false);

  async function runSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    const supabase = getSupabaseClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) { setLoading(false); return; }

    const { data: jobs } = await supabase.from('upload_jobs').select('id').eq('user_id', user.id).eq('status', 'complete').order('created_at', { ascending: false }).limit(1);
    const jobId = jobs?.[0]?.id;
    if (!jobId) { setLoading(false); return; }

    const [ipRes, userRes, rawRes, incRes] = await Promise.all([
      supabase.from('log_events').select('source_ip').eq('job_id', jobId).ilike('source_ip', `%${query}%`).limit(20),
      supabase.from('log_events').select('username').eq('job_id', jobId).ilike('username', `%${query}%`).limit(20),
      supabase.from('log_events').select('id,raw_line,timestamp').eq('job_id', jobId).ilike('raw_line', `%${query}%`).limit(15),
      supabase.from('incidents').select('id,title,incident_ref,severity').eq('job_id', jobId).or(`title.ilike.%${query}%,mitre_technique_id.ilike.%${query}%`).limit(10),
    ]);

    const ipCounts = new Map<string, number>();
    (ipRes.data ?? []).forEach(r => { if (r.source_ip) ipCounts.set(r.source_ip, (ipCounts.get(r.source_ip) ?? 0) + 1); });
    const userCounts = new Map<string, number>();
    (userRes.data ?? []).forEach(r => { if (r.username) userCounts.set(r.username, (userCounts.get(r.username) ?? 0) + 1); });

    setResults({
      ips: Array.from(ipCounts.entries()).map(([source_ip, count]) => ({ source_ip, count })),
      users: Array.from(userCounts.entries()).map(([username, count]) => ({ username, count })),
      rawLines: (rawRes.data ?? []) as SearchResults['rawLines'],
      incidents: (incRes.data ?? []) as SearchResults['incidents'],
    });
    setLoading(false);
  }

  return (
    <div style={{ maxWidth: 800, margin: '0 auto' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Global Search</h1>
        <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>Search IPs, usernames, raw log lines, incidents, and MITRE techniques</p>
      </div>

      <form onSubmit={runSearch} style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
        <div style={{ position: 'relative', flex: 1 }}>
          <SearchIcon size={16} style={{ position: 'absolute', left: '0.875rem', top: '50%', transform: 'translateY(-50%)', color: '#4A5568' }} />
          <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search IP, username, log line, MITRE ID..."
            style={{ width: '100%', padding: '0.875rem 1rem 0.875rem 2.5rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '10px', color: '#E8EDF5', fontSize: '0.9375rem', outline: 'none' }} />
        </div>
        <button type="submit" style={{ padding: '0 1.5rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '10px', border: 'none', cursor: 'pointer', fontSize: '0.875rem' }}>Search</button>
      </form>

      {loading && <div className="glass-card skeleton" style={{ height: 200 }} />}

      {results && !loading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {results.ips.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}><Globe size={16} color="#00FF88" /> IP Addresses</h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {results.ips.map(r => (
                  <span key={r.source_ip} className="mono" style={{ fontSize: '0.8125rem', color: '#00FF88', background: 'rgba(0,255,136,0.08)', padding: '0.375rem 0.75rem', borderRadius: '6px' }}>{r.source_ip} ({r.count})</span>
                ))}
              </div>
            </div>
          )}
          {results.users.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}><User size={16} color="#00D4FF" /> Usernames</h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {results.users.map(r => (
                  <span key={r.username} className="mono" style={{ fontSize: '0.8125rem', color: '#00D4FF', background: 'rgba(0,212,255,0.08)', padding: '0.375rem 0.75rem', borderRadius: '6px' }}>{r.username} ({r.count})</span>
                ))}
              </div>
            </div>
          )}
          {results.incidents.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}><Shield size={16} color="#FFB800" /> Incidents</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {results.incidents.map(r => (
                  <Link key={r.id} href={`/dashboard/threats/${r.id}`} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem', borderRadius: '6px', textDecoration: 'none', background: 'rgba(255,255,255,0.03)' }}>
                    <span className={`badge badge-${r.severity}`}>{r.severity}</span>
                    <span style={{ color: '#E8EDF5', fontSize: '0.8125rem' }}>{r.title}</span>
                  </Link>
                ))}
              </div>
            </div>
          )}
          {results.rawLines.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}><FileText size={16} color="#8892A4" /> Raw Log Lines</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {results.rawLines.map(r => (
                  <code key={r.id} style={{ display: 'block', padding: '0.625rem', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', fontSize: '0.75rem', color: '#8892A4', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all' }}>{r.raw_line}</code>
                ))}
              </div>
            </div>
          )}
          {results.ips.length === 0 && results.users.length === 0 && results.incidents.length === 0 && results.rawLines.length === 0 && (
            <div className="glass-card" style={{ padding: '2rem', textAlign: 'center', color: '#8892A4' }}>No results found for "{query}"</div>
          )}
        </div>
      )}
    </div>
  );
}
