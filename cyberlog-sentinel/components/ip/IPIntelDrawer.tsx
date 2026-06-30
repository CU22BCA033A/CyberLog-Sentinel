'use client';
import { useState, useEffect } from 'react';
import { X, Globe, Shield, AlertTriangle, Clock } from 'lucide-react';

interface IPIntelData {
  ip: string;
  is_internal: boolean;
  geo_country: string | null;
  geo_city: string | null;
  total_events: number;
  total_failures: number;
  total_successes: number;
  targeted_users: string[];
  first_seen: string | null;
  last_seen: string | null;
  classification: string;
}

export function IPIntelDrawer({ ip, jobId, onClose }: { ip: string | null; jobId: string | null; onClose: () => void }) {
  const [data, setData] = useState<IPIntelData | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!ip) return;
    setLoading(true);
    setData(null);
    const params = new URLSearchParams({ ip });
    if (jobId) params.set('job_id', jobId);
    fetch(`/api/ip-intel?${params}`)
      .then(r => r.json())
      .then(d => setData(d))
      .finally(() => setLoading(false));
  }, [ip, jobId]);

  if (!ip) return null;

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 100, display: 'flex', justifyContent: 'flex-end' }}>
      <div onClick={onClose} style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.6)' }} />
      <div style={{ position: 'relative', width: 420, maxWidth: '100%', height: '100%', background: '#0F1520', borderLeft: '1px solid rgba(255,255,255,0.1)', overflowY: 'auto', padding: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
          <h2 style={{ fontSize: '1.125rem', fontWeight: 800, color: '#E8EDF5', margin: 0, fontFamily: 'JetBrains Mono, monospace' }}>{ip}</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#8892A4', cursor: 'pointer', display: 'flex' }}><X size={20} /></button>
        </div>

        {loading && <div className="skeleton" style={{ height: 300 }} />}

        {data && !loading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <span className={`badge ${data.is_internal ? 'badge-low' : 'badge-high'}`}>{data.is_internal ? 'Internal' : 'External'}</span>
              <span style={{ marginLeft: '0.5rem' }} className="badge badge-medium">{data.classification}</span>
            </div>

            {(data.geo_country || data.geo_city) && (
              <div className="glass-card" style={{ padding: '0.875rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Globe size={16} color="#00D4FF" />
                <span style={{ color: '#E8EDF5', fontSize: '0.875rem' }}>{[data.geo_city, data.geo_country].filter(Boolean).join(', ')}</span>
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
              <div className="glass-card" style={{ padding: '0.875rem' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#FF3B30', fontFamily: 'JetBrains Mono, monospace' }}>{data.total_failures}</div>
                <div style={{ fontSize: '0.75rem', color: '#8892A4' }}>Failed Attempts</div>
              </div>
              <div className="glass-card" style={{ padding: '0.875rem' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#00FF88', fontFamily: 'JetBrains Mono, monospace' }}>{data.total_successes}</div>
                <div style={{ fontSize: '0.75rem', color: '#8892A4' }}>Successful Logins</div>
              </div>
            </div>

            <div className="glass-card" style={{ padding: '0.875rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <Shield size={14} color="#FFB800" />
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#E8EDF5' }}>Targeted Usernames</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
                {data.targeted_users.length === 0 ? <span style={{ color: '#4A5568', fontSize: '0.8125rem' }}>None</span> :
                  data.targeted_users.map(u => <span key={u} className="mono" style={{ fontSize: '0.75rem', color: '#00D4FF', background: 'rgba(0,212,255,0.08)', padding: '2px 8px', borderRadius: 4 }}>{u}</span>)}
              </div>
            </div>

            <div className="glass-card" style={{ padding: '0.875rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <Clock size={14} color="#8892A4" />
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#E8EDF5' }}>Activity Window</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#8892A4' }}>
                First: {data.first_seen ? new Date(data.first_seen).toLocaleString() : '—'}<br />
                Last: {data.last_seen ? new Date(data.last_seen).toLocaleString() : '—'}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button style={{ flex: 1, padding: '0.625rem', background: 'rgba(255,59,48,0.1)', border: '1px solid rgba(255,59,48,0.3)', borderRadius: '8px', color: '#FF3B30', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.375rem' }}>
                <AlertTriangle size={14} /> Mark Known Bad
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
