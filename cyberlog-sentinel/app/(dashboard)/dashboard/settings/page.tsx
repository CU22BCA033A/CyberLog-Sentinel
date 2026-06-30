'use client';
import { useState, useEffect } from 'react';
import { getSupabaseClient } from '@/lib/supabase/client';
import { Trash2, Plus, Key, Copy } from 'lucide-react';

interface WatchlistEntry { id: string; ip_address: string; label: string | null; is_whitelist: boolean }

export default function SettingsPage() {
  const [thresholds, setThresholds] = useState({ bruteForceAttempts: 5, bruteForceWindow: 60, offHoursStart: 22, offHoursEnd: 6 });
  const [watchlist, setWatchlist] = useState<WatchlistEntry[]>([]);
  const [newIp, setNewIp] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [isWhitelist, setIsWhitelist] = useState(true);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [apiKey, setApiKey] = useState<string | null>(null);

  useEffect(() => { loadWatchlist(); }, []);

  async function loadWatchlist() {
    const supabase = getSupabaseClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;
    const { data } = await supabase.from('ip_watchlist').select('*').eq('user_id', user.id);
    setWatchlist((data ?? []) as WatchlistEntry[]);
  }

  async function addToWatchlist() {
    if (!newIp.trim()) return;
    const supabase = getSupabaseClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;
    const { data } = await supabase.from('ip_watchlist').insert({ user_id: user.id, ip_address: newIp, label: newLabel || null, is_whitelist: isWhitelist }).select().single();
    if (data) setWatchlist(prev => [...prev, data as WatchlistEntry]);
    setNewIp(''); setNewLabel('');
  }

  async function removeFromWatchlist(id: string) {
    const supabase = getSupabaseClient();
    await supabase.from('ip_watchlist').delete().eq('id', id);
    setWatchlist(prev => prev.filter(w => w.id !== id));
  }

  function generateApiKey() {
    const key = 'cls_' + Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b => b.toString(16).padStart(2, '0')).join('');
    setApiKey(key);
  }

  return (
    <div style={{ maxWidth: 700, margin: '0 auto' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Settings</h1>
        <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>Configure detection thresholds and platform preferences</p>
      </div>

      {/* Detection Thresholds */}
      <div className="glass-card" style={{ padding: '1.25rem', marginBottom: '1rem' }}>
        <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem' }}>Detection Thresholds</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#8892A4', marginBottom: '0.5rem' }}>Brute Force Attempts</label>
            <input type="number" value={thresholds.bruteForceAttempts} onChange={e => setThresholds(p => ({ ...p, bruteForceAttempts: +e.target.value }))}
              style={{ width: '100%', padding: '0.625rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.875rem' }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#8892A4', marginBottom: '0.5rem' }}>Time Window (seconds)</label>
            <input type="number" value={thresholds.bruteForceWindow} onChange={e => setThresholds(p => ({ ...p, bruteForceWindow: +e.target.value }))}
              style={{ width: '100%', padding: '0.625rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.875rem' }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#8892A4', marginBottom: '0.5rem' }}>Off-Hours Start</label>
            <input type="number" min={0} max={23} value={thresholds.offHoursStart} onChange={e => setThresholds(p => ({ ...p, offHoursStart: +e.target.value }))}
              style={{ width: '100%', padding: '0.625rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.875rem' }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#8892A4', marginBottom: '0.5rem' }}>Off-Hours End</label>
            <input type="number" min={0} max={23} value={thresholds.offHoursEnd} onChange={e => setThresholds(p => ({ ...p, offHoursEnd: +e.target.value }))}
              style={{ width: '100%', padding: '0.625rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.875rem' }} />
          </div>
        </div>
        <p style={{ fontSize: '0.75rem', color: '#4A5568', marginTop: '0.75rem' }}>Note: threshold changes apply to new uploads only.</p>
      </div>

      {/* IP Watchlist */}
      <div className="glass-card" style={{ padding: '1.25rem', marginBottom: '1rem' }}>
        <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem' }}>IP Watchlist</h3>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
          <input value={newIp} onChange={e => setNewIp(e.target.value)} placeholder="192.168.1.1" className="mono"
            style={{ flex: 1, minWidth: 140, padding: '0.625rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem' }} />
          <input value={newLabel} onChange={e => setNewLabel(e.target.value)} placeholder="Label (optional)"
            style={{ flex: 1, minWidth: 140, padding: '0.625rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem' }} />
          <select value={isWhitelist ? 'whitelist' : 'badlist'} onChange={e => setIsWhitelist(e.target.value === 'whitelist')}
            style={{ padding: '0.625rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem' }}>
            <option value="whitelist">Whitelist</option>
            <option value="badlist">Known Bad</option>
          </select>
          <button onClick={addToWatchlist} style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', padding: '0.625rem 0.875rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '6px', border: 'none', cursor: 'pointer', fontSize: '0.8125rem' }}>
            <Plus size={14} /> Add
          </button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {watchlist.length === 0 ? <p style={{ color: '#4A5568', fontSize: '0.8125rem' }}>No IPs in watchlist.</p> : watchlist.map(w => (
            <div key={w.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.625rem', background: 'rgba(255,255,255,0.03)', borderRadius: '6px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span className="mono" style={{ color: w.is_whitelist ? '#00FF88' : '#FF3B30', fontSize: '0.8125rem' }}>{w.ip_address}</span>
                {w.label && <span style={{ color: '#8892A4', fontSize: '0.75rem' }}>{w.label}</span>}
                <span className={`badge badge-${w.is_whitelist ? 'low' : 'critical'}`}>{w.is_whitelist ? 'whitelist' : 'known bad'}</span>
              </div>
              <button onClick={() => removeFromWatchlist(w.id)} style={{ background: 'none', border: 'none', color: '#8892A4', cursor: 'pointer', display: 'flex' }}><Trash2 size={14} /></button>
            </div>
          ))}
        </div>
      </div>

      {/* Webhook */}
      <div className="glass-card" style={{ padding: '1.25rem', marginBottom: '1rem' }}>
        <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}>Alert Webhook</h3>
        <p style={{ fontSize: '0.8125rem', color: '#8892A4', marginBottom: '0.75rem' }}>POST a JSON payload to this URL whenever a critical threat is detected.</p>
        <input value={webhookUrl} onChange={e => setWebhookUrl(e.target.value)} placeholder="https://hooks.slack.com/services/..."
          style={{ width: '100%', padding: '0.625rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem', fontFamily: 'JetBrains Mono, monospace' }} />
      </div>

      {/* API Keys */}
      <div className="glass-card" style={{ padding: '1.25rem' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}>
          <Key size={16} color="#FFB800" /> API Key Management
        </h3>
        <p style={{ fontSize: '0.8125rem', color: '#8892A4', marginBottom: '0.75rem' }}>Generate keys for programmatic log submission via the API.</p>
        {apiKey ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem', background: 'rgba(0,0,0,0.3)', borderRadius: '6px' }}>
            <code style={{ flex: 1, fontSize: '0.8125rem', color: '#00FF88', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all' }}>{apiKey}</code>
            <button onClick={() => navigator.clipboard.writeText(apiKey)} style={{ background: 'none', border: 'none', color: '#8892A4', cursor: 'pointer', display: 'flex' }}><Copy size={14} /></button>
          </div>
        ) : (
          <button onClick={generateApiKey} style={{ padding: '0.625rem 1rem', background: 'transparent', border: '1px solid rgba(255,184,0,0.3)', borderRadius: '6px', color: '#FFB800', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600 }}>
            Generate New API Key
          </button>
        )}
      </div>
    </div>
  );
}
