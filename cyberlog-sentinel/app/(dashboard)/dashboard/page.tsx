'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { getSupabaseClient } from '@/lib/supabase/client';
import { Activity, AlertTriangle, Flame, Globe, Shield, Users, Upload } from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, Legend,
} from 'recharts';

interface DashboardStats {
  totalEvents: number;
  threatsDetected: number;
  criticalAlerts: number;
  uniqueIPs: number;
  bruteForceIncidents: number;
  compromisedAccounts: number;
  recentJobs: Array<{ id: string; filename: string; status: string; created_at: string }>;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#FF3B30', high: '#FF6B35', medium: '#FFB800', low: '#4DC9FF', info: '#4A5568',
};

function MetricCard({ label, value, icon: Icon, color }: {
  label: string; value: number | string; icon: React.ElementType; color: string;
}) {
  return (
    <div className="glass-card" style={{ padding: '1.25rem', borderLeft: `3px solid ${color}` }}>
      <div style={{ width: 36, height: 36, borderRadius: '8px', background: `${color}15`, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '0.75rem' }}>
        <Icon size={18} color={color} />
      </div>
      <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#E8EDF5', fontFamily: 'JetBrains Mono, monospace', lineHeight: 1 }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      <div style={{ fontSize: '0.8125rem', color: '#8892A4', marginTop: '0.375rem' }}>{label}</div>
    </div>
  );
}

function SkeletonCard() {
  return (
    <div className="glass-card" style={{ padding: '1.25rem' }}>
      <div className="skeleton" style={{ height: 36, width: 36, borderRadius: 8, marginBottom: '0.75rem' }} />
      <div className="skeleton" style={{ height: 28, width: '60%', marginBottom: '0.375rem' }} />
      <div className="skeleton" style={{ height: 16, width: '80%' }} />
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [severityData, setSeverityData] = useState<Array<{ name: string; value: number; color: string }>>([]);
  const [timelineData, setTimelineData] = useState<Array<{ hour: string; success: number; failure: number }>>([]);
  const [topIPs, setTopIPs] = useState<Array<{ ip: string; failures: number; successes: number }>>([]);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);

  useEffect(() => { loadDashboard(); }, []);

  async function loadDashboard() {
    setLoading(true);
    const supabase = getSupabaseClient();

    // Get most recent completed job — try by user first, then any
    const { data: { session } } = await supabase.auth.getSession();
    const userId = session?.user?.id;

    let jobs = null;

    if (userId) {
      const { data } = await supabase
        .from('upload_jobs')
        .select('id, filename, status, created_at')
        .eq('user_id', userId)
        .eq('status', 'complete')
        .order('created_at', { ascending: false })
        .limit(5);
      jobs = data;
    }

    // Fallback: show any completed job (handles uploads before login was working)
    if (!jobs || jobs.length === 0) {
      const { data } = await supabase
        .from('upload_jobs')
        .select('id, filename, status, created_at')
        .eq('status', 'complete')
        .order('created_at', { ascending: false })
        .limit(5);
      jobs = data;
    }

    const jobId = jobs?.[0]?.id ?? null;
    setSelectedJobId(jobId);

    if (!jobId) {
      setStats({
        totalEvents: 0, threatsDetected: 0, criticalAlerts: 0,
        uniqueIPs: 0, bruteForceIncidents: 0, compromisedAccounts: 0,
        recentJobs: jobs ?? [],
      });
      setLoading(false);
      return;
    }

    const [eventsRes, incidentsRes, detectionsRes] = await Promise.all([
      supabase.from('log_events').select('severity, outcome, source_ip, timestamp', { count: 'exact' }).eq('job_id', jobId).limit(5000),
      supabase.from('incidents').select('severity, status', { count: 'exact' }).eq('job_id', jobId),
      supabase.from('detections').select('rule_id, severity', { count: 'exact' }).eq('job_id', jobId),
    ]);

    const events = eventsRes.data ?? [];
    const incidents = incidentsRes.data ?? [];

    // Severity breakdown
    const sevCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const e of events) { sevCounts[e.severity] = (sevCounts[e.severity] ?? 0) + 1; }
    setSeverityData(
      Object.entries(sevCounts)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => ({ name: k, value: v, color: SEVERITY_COLORS[k] }))
    );

    // Timeline by hour
    const hourMap: Record<string, { success: number; failure: number }> = {};
    for (const e of events) {
      const h = new Date(e.timestamp).toISOString().slice(11, 13) + ':00';
      if (!hourMap[h]) hourMap[h] = { success: 0, failure: 0 };
      if (e.outcome === 'success') hourMap[h].success++;
      else if (e.outcome === 'failure') hourMap[h].failure++;
    }
    setTimelineData(
      Object.entries(hourMap).sort().map(([h, v]) => ({ hour: h, ...v }))
    );

    // Top IPs
    const ipMap: Record<string, { failures: number; successes: number }> = {};
    for (const e of events) {
      if (!e.source_ip) continue;
      if (!ipMap[e.source_ip]) ipMap[e.source_ip] = { failures: 0, successes: 0 };
      if (e.outcome === 'failure') ipMap[e.source_ip].failures++;
      else if (e.outcome === 'success') ipMap[e.source_ip].successes++;
    }
    setTopIPs(
      Object.entries(ipMap)
        .sort((a, b) => b[1].failures - a[1].failures)
        .slice(0, 10)
        .map(([ip, v]) => ({ ip, ...v }))
    );

    const uniqueIPs = new Set(events.map(e => e.source_ip).filter(Boolean)).size;
    const criticalAlerts = incidents.filter(i => i.severity === 'critical').length;

    setStats({
      totalEvents: eventsRes.count ?? events.length,
      threatsDetected: incidentsRes.count ?? incidents.length,
      criticalAlerts,
      uniqueIPs,
      bruteForceIncidents: incidents.length,
      compromisedAccounts: (detectionsRes.data ?? []).filter(d => d.rule_id === 'success_after_bruteforce').length,
      recentJobs: jobs ?? [],
    });
    setLoading(false);
  }

  const METRICS = stats ? [
    { label: 'Total Events', value: stats.totalEvents, icon: Activity, color: '#00D4FF' },
    { label: 'Threats Detected', value: stats.threatsDetected, icon: AlertTriangle, color: '#FFB800' },
    { label: 'Critical Alerts', value: stats.criticalAlerts, icon: Flame, color: '#FF3B30' },
    { label: 'Unique Source IPs', value: stats.uniqueIPs, icon: Globe, color: '#00FF88' },
    { label: 'Brute Force Incidents', value: stats.bruteForceIncidents, icon: Shield, color: '#FF6B35' },
    { label: 'Compromised Accounts', value: stats.compromisedAccounts, icon: Users, color: '#FF3B30' },
  ] : [];

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Security Dashboard</h1>
          <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>Linux Authentication Log Analysis</p>
        </div>
        <Link href="/upload" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', padding: '0.625rem 1rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '8px', textDecoration: 'none', fontSize: '0.875rem' }}>
          <Upload size={14} /> Upload Logs
        </Link>
      </div>

      {!loading && !selectedJobId && (
        <div className="glass-card" style={{ padding: '3rem', textAlign: 'center' }}>
          <div style={{ width: 64, height: 64, borderRadius: '50%', background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 1.5rem' }}>
            <Upload size={28} color="#00FF88" />
          </div>
          <h2 style={{ color: '#E8EDF5', fontSize: '1.25rem', fontWeight: 700, margin: '0 0 0.5rem' }}>No logs analyzed yet</h2>
          <p style={{ color: '#8892A4', fontSize: '0.875rem', marginBottom: '1.5rem' }}>Upload a Linux auth.log file to start detecting threats.</p>
          <Link href="/upload" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem 1.5rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '8px', textDecoration: 'none' }}>
            <Upload size={16} /> Upload Your First Log File
          </Link>
        </div>
      )}

      {(loading || selectedJobId) && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            {loading
              ? Array.from({ length: 6 }).map((_, i) => <SkeletonCard key={i} />)
              : METRICS.map(m => <MetricCard key={m.label} {...m} />)
            }
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem' }}>Authentication Timeline</h3>
              {loading ? <div className="skeleton" style={{ height: 200 }} /> : (
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={timelineData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="hour" stroke="#4A5568" tick={{ fontSize: 11, fill: '#8892A4' }} />
                    <YAxis stroke="#4A5568" tick={{ fontSize: 11, fill: '#8892A4' }} />
                    <Tooltip contentStyle={{ background: '#0F1520', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
                    <Area type="monotone" dataKey="failure" stackId="1" stroke="#FF3B30" fill="rgba(255,59,48,0.2)" name="Failures" />
                    <Area type="monotone" dataKey="success" stackId="1" stroke="#00FF88" fill="rgba(0,255,136,0.2)" name="Successes" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem' }}>Severity Distribution</h3>
              {loading ? <div className="skeleton" style={{ height: 200 }} /> : (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={severityData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                      {severityData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#0F1520', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
                    <Legend formatter={v => <span style={{ color: '#8892A4', fontSize: 12, textTransform: 'capitalize' }}>{v}</span>} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {topIPs.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem', marginBottom: '1rem' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem' }}>Top Attacking IPs</h3>
              {loading ? <div className="skeleton" style={{ height: 200 }} /> : (
                <ResponsiveContainer width="100%" height={Math.max(200, topIPs.length * 40)}>
                  <BarChart data={topIPs} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis type="number" stroke="#4A5568" tick={{ fontSize: 11, fill: '#8892A4' }} />
                    <YAxis type="category" dataKey="ip" width={140} tick={{ fontSize: 11, fill: '#8892A4', fontFamily: 'JetBrains Mono, monospace' }} />
                    <Tooltip contentStyle={{ background: '#0F1520', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="failures" fill="#FF3B30" name="Failures" radius={[0, 4, 4, 0]} />
                    <Bar dataKey="successes" fill="#00FF88" name="Successes" radius={[0, 4, 4, 0]} />
                    <Legend formatter={v => <span style={{ color: '#8892A4', fontSize: 12 }}>{v}</span>} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          )}

          {stats?.recentJobs && stats.recentJobs.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: 0 }}>Recent Uploads</h3>
                <Link href="/upload" style={{ color: '#00FF88', fontSize: '0.8125rem', textDecoration: 'none' }}>Upload new →</Link>
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                    {['File', 'Status', 'Date'].map(h => (
                      <th key={h} style={{ textAlign: 'left', padding: '0.5rem', fontSize: '0.75rem', fontWeight: 600, color: '#8892A4', letterSpacing: '0.05em', textTransform: 'uppercase' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {stats.recentJobs.map(job => (
                    <tr key={job.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <td style={{ padding: '0.625rem 0.5rem', fontSize: '0.875rem', color: '#E8EDF5', fontFamily: 'JetBrains Mono, monospace' }}>{job.filename}</td>
                      <td style={{ padding: '0.625rem 0.5rem' }}>
                        <span className={`badge badge-${job.status === 'complete' ? 'low' : job.status === 'failed' ? 'critical' : 'medium'}`}>{job.status}</span>
                      </td>
                      <td style={{ padding: '0.625rem 0.5rem', fontSize: '0.8125rem', color: '#8892A4' }}>{new Date(job.created_at).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
