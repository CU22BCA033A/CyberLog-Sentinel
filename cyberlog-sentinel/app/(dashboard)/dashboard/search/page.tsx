'use client';
import { useState } from 'react';
import Link from 'next/link';
import { getSupabaseClient } from '@/lib/supabase/client';
import { Search as SearchIcon, Globe, User, FileText, Shield, Loader2 } from 'lucide-react';

interface SearchResults {
  ips: Array<{ ip: string; count: number }>;
  users: Array<{ username: string; count: number }>;
  rawLines: Array<{ id: string; raw_line: string; timestamp: string; severity: string }>;
  incidents: Array<{ id: string; title: string; incident_ref: string; severity: string }>;
}

export default function SearchPage() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResults | null>(null);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);

  async function getJobId(): Promise<string | null> {
    if (jobId) return jobId;
    const supabase = getSupabaseClient();
    const { data: { session } } = await supabase.auth.getSession();
    const userId = session?.user?.id;

    let jobs = null;
    if (userId) {
      const { data } = await supabase
        .from('upload_jobs')
        .select('id')
        .eq('user_id', userId)
        .eq('status', 'complete')
        .order('created_at', { ascending: false })
        .limit(1);
      jobs = data;
    }
    if (!jobs || jobs.length === 0) {
      const { data } = await supabase
        .from('upload_jobs')
        .select('id')
        .eq('status', 'complete')
        .order('created_at', { ascending: false })
        .limit(1);
      jobs = data;
    }
    const id = jobs?.[0]?.id ?? null;
    setJobId(id);
    return id;
  }

  async function runSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    setSearched(false);

    const supabase = getSupabaseClient();
    const jid = await getJobId();

    if (!jid) {
      setResults({ ips: [], users: [], rawLines: [], incidents: [] });
      setLoading(false);
      setSearched(true);
      return;
    }

    const q = query.trim();

    const [ipRes, userRes, rawRes, incRes] = await Promise.all([
      supabase
        .from('log_events')
        .select('source_ip')
        .eq('job_id', jid)
        .not('source_ip', 'is', null)
        .ilike('source_ip', `%${q}%`)
        .limit(500),

      supabase
        .from('log_events')
        .select('username')
        .eq('job_id', jid)
        .not('username', 'is', null)
        .ilike('username', `%${q}%`)
        .limit(500),

      supabase
        .from('log_events')
        .select('id, raw_line, timestamp, severity')
        .eq('job_id', jid)
        .ilike('raw_line', `%${q}%`)
        .order('timestamp', { ascending: false })
        .limit(20),

      supabase
        .from('incidents')
        .select('id, title, incident_ref, severity')
        .eq('job_id', jid)
        .or(`title.ilike.%${q}%,mitre_technique_id.ilike.%${q}%,description.ilike.%${q}%`)
        .limit(10),
    ]);

    // Aggregate IP counts
    const ipCounts = new Map<string, number>();
    for (const r of ipRes.data ?? []) {
      if (r.source_ip) ipCounts.set(r.source_ip, (ipCounts.get(r.source_ip) ?? 0) + 1);
    }

    // Aggregate username counts
    const userCounts = new Map<string, number>();
    for (const r of userRes.data ?? []) {
      if (r.username) userCounts.set(r.username, (userCounts.get(r.username) ?? 0) + 1);
    }

    setResults({
      ips: Array.from(ipCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([ip, count]) => ({ ip, count })),
      users: Array.from(userCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([username, count]) => ({ username, count })),
      rawLines: (rawRes.data ?? []) as SearchResults['rawLines'],
      incidents: (incRes.data ?? []) as SearchResults['incidents'],
    });

    setLoading(false);
    setSearched(true);
  }

  const totalResults = results
    ? results.ips.length + results.users.length + results.rawLines.length + results.incidents.length
    : 0;

  return (
    <div style={{ maxWidth: 800, margin: '0 auto' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Global Search</h1>
        <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>
          Search across IPs, usernames, raw log lines, incidents, and MITRE technique IDs
        </p>
      </div>

      {/* Search bar */}
      <form onSubmit={runSearch} style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
        <div style={{ position: 'relative', flex: 1 }}>
          <SearchIcon size={16} style={{ position: 'absolute', left: '0.875rem', top: '50%', transform: 'translateY(-50%)', color: '#4A5568' }} />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Try: 192.168.1.1 or root or T1110 or brute force..."
            autoFocus
            style={{ width: '100%', padding: '0.875rem 1rem 0.875rem 2.5rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', color: '#E8EDF5', fontSize: '0.9375rem', outline: 'none', fontFamily: 'JetBrains Mono, monospace' }}
          />
        </div>
        <button
          type="submit"
          disabled={loading || !query.trim()}
          style={{ padding: '0 1.5rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '10px', border: 'none', cursor: loading || !query.trim() ? 'not-allowed' : 'pointer', fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: '0.5rem', opacity: loading || !query.trim() ? 0.7 : 1 }}
        >
          {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <SearchIcon size={16} />}
          Search
        </button>
      </form>

      {/* Quick search suggestions */}
      {!searched && !loading && (
        <div className="glass-card" style={{ padding: '1.25rem' }}>
          <p style={{ color: '#4A5568', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', margin: '0 0 0.75rem' }}>Quick searches</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {['root', 'admin', 'Failed password', 'Invalid user', 'sudo', 'T1110', 'T1078', 'Accepted'].map(s => (
              <button
                key={s}
                onClick={() => { setQuery(s); }}
                className="mono"
                style={{ fontSize: '0.8125rem', color: '#00FF88', background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.15)', padding: '0.375rem 0.75rem', borderRadius: '6px', cursor: 'pointer' }}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {[200, 150, 300, 120].map((w, i) => (
            <div key={i} className="glass-card skeleton" style={{ height: 80 }} />
          ))}
        </div>
      )}

      {/* Results */}
      {searched && !loading && results && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Summary */}
          <div style={{ fontSize: '0.8125rem', color: '#8892A4' }}>
            {totalResults === 0
              ? `No results found for "${query}"`
              : `Found ${totalResults} result${totalResults !== 1 ? 's' : ''} for "${query}"`
            }
          </div>

          {/* IP Results */}
          {results.ips.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}>
                <Globe size={16} color="#00FF88" /> IP Addresses
                <span style={{ fontSize: '0.75rem', color: '#4A5568', fontWeight: 400 }}>({results.ips.length})</span>
              </h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {results.ips.map(r => (
                  <div key={r.ip} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0,255,136,0.06)', border: '1px solid rgba(0,255,136,0.15)', borderRadius: '8px', padding: '0.5rem 0.875rem' }}>
                    <span className="mono" style={{ fontSize: '0.875rem', color: '#00FF88' }}>{r.ip}</span>
                    <span style={{ fontSize: '0.7rem', color: '#4A5568', background: 'rgba(0,0,0,0.3)', padding: '1px 6px', borderRadius: 4 }}>{r.count} events</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Username Results */}
          {results.users.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}>
                <User size={16} color="#00D4FF" /> Usernames
                <span style={{ fontSize: '0.75rem', color: '#4A5568', fontWeight: 400 }}>({results.users.length})</span>
              </h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {results.users.map(r => (
                  <div key={r.username} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.15)', borderRadius: '8px', padding: '0.5rem 0.875rem' }}>
                    <span className="mono" style={{ fontSize: '0.875rem', color: '#00D4FF' }}>{r.username}</span>
                    <span style={{ fontSize: '0.7rem', color: '#4A5568', background: 'rgba(0,0,0,0.3)', padding: '1px 6px', borderRadius: 4 }}>{r.count} events</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Incident Results */}
          {results.incidents.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}>
                <Shield size={16} color="#FFB800" /> Incidents
                <span style={{ fontSize: '0.75rem', color: '#4A5568', fontWeight: 400 }}>({results.incidents.length})</span>
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {results.incidents.map(r => (
                  <Link
                    key={r.id}
                    href={`/dashboard/threats/${r.id}`}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem', borderRadius: '8px', textDecoration: 'none', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', transition: 'background 0.15s' }}
                  >
                    <span className={`badge badge-${r.severity}`}>{r.severity}</span>
                    <span style={{ fontSize: '0.75rem', color: '#4A5568', fontFamily: 'JetBrains Mono, monospace' }}>{r.incident_ref}</span>
                    <span style={{ color: '#E8EDF5', fontSize: '0.875rem', flex: 1 }}>{r.title}</span>
                    <span style={{ color: '#4A5568', fontSize: '0.75rem' }}>→</span>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Raw Log Lines */}
          {results.rawLines.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}>
                <FileText size={16} color="#8892A4" /> Raw Log Lines
                <span style={{ fontSize: '0.75rem', color: '#4A5568', fontWeight: 400 }}>({results.rawLines.length} shown)</span>
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {results.rawLines.map(r => (
                  <div key={r.id} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start', padding: '0.625rem', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', borderLeft: `3px solid ${SEVERITY_COLORS[r.severity] ?? '#4A5568'}` }}>
                    <span style={{ fontSize: '0.7rem', color: '#4A5568', fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap', flexShrink: 0, paddingTop: 1 }}>
                      {new Date(r.timestamp).toLocaleTimeString()}
                    </span>
                    <code style={{ fontSize: '0.75rem', color: '#8892A4', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all', lineHeight: 1.6 }}>
                      {highlightMatch(r.raw_line, query)}
                    </code>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* No results */}
          {totalResults === 0 && (
            <div className="glass-card" style={{ padding: '3rem', textAlign: 'center' }}>
              <SearchIcon size={32} color="#4A5568" style={{ marginBottom: '1rem' }} />
              <p style={{ color: '#8892A4', fontSize: '0.875rem', margin: 0 }}>
                No results found for <span className="mono" style={{ color: '#E8EDF5' }}>"{query}"</span>
              </p>
              <p style={{ color: '#4A5568', fontSize: '0.8125rem', marginTop: '0.5rem' }}>
                Try searching for an IP address, username, log keyword, or MITRE technique ID like T1110
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#FF3B30', high: '#FF6B35', medium: '#FFB800', low: '#4DC9FF', info: '#4A5568',
};

// Highlight matching text in log lines
function highlightMatch(text: string, query: string): React.ReactNode {
  if (!query) return text;
  const idx = text.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return text;
  return (
    <>
      {text.slice(0, idx)}
      <span style={{ background: 'rgba(255,184,0,0.3)', color: '#FFB800', borderRadius: 2, padding: '0 2px' }}>
        {text.slice(idx, idx + query.length)}
      </span>
      {text.slice(idx + query.length)}
    </>
  );
}
