'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { getSupabaseClient } from '@/lib/supabase/client';
import { AlertTriangle, Globe, Users, Clock, Shield, TrendingUp, FileText } from 'lucide-react';
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

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const STATUS_COLORS: Record<string, string> = {
  open: '#FF3B30', investigating: '#FFB800', closed: '#34C759', false_positive: '#4A5568',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#FF3B30', high: '#FF6B35', medium: '#FFB800', low: '#4DC9FF', info: '#4A5568',
};

function RiskGauge({ score }: { score: number }) {
  const color = score >= 80 ? '#FF3B30' : score >= 60 ? '#FF6B35' : score >= 40 ? '#FFB800' : score >= 20 ? '#4DC9FF' : '#34C759';
  const circumference = 2 * Math.PI * 40;
  const offset = circumference - (score / 100) * circumference;
  return (
    <div style={{ position: 'relative', width: 100, height: 100, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width="100" height="100" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <circle cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circumference} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1s ease', strokeLinecap: 'round' }} />
      </svg>
      <div style={{ position: 'absolute', textAlign: 'center' }}>
        <div style={{ fontSize: '1.25rem', fontWeight: 800, color, fontFamily: 'JetBrains Mono, monospace' }}>{score}</div>
        <div style={{ fontSize: '0.6rem', color: '#4A5568', textTransform: 'uppercase' }}>Risk</div>
      </div>
    </div>
  );
}

export default function ThreatsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [activeTab, setActiveTab] = useState<'incidents' | 'report'>('incidents');
  const [jobId, setJobId] = useState<string | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    const supabase = getSupabaseClient();
    const { data: { session } } = await supabase.auth.getSession();
    const userId = session?.user?.id;

    let jobs = null;
    if (userId) {
      const { data } = await supabase.from('upload_jobs').select('id').eq('user_id', userId).eq('status', 'complete').order('created_at', { ascending: false }).limit(1);
      jobs = data;
    }
    if (!jobs || jobs.length === 0) {
      const { data } = await supabase.from('upload_jobs').select('id').eq('status', 'complete').order('created_at', { ascending: false }).limit(1);
      jobs = data;
    }

    const jid = jobs?.[0]?.id ?? null;
    setJobId(jid);
    if (!jid) { setLoading(false); return; }

    const { data } = await supabase.from('incidents').select('*').eq('job_id', jid).order('created_at', { ascending: false });
    const sorted = (data ?? []).sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
    setIncidents(sorted as Incident[]);
    setLoading(false);
  }

  async function updateStatus(id: string, status: string) {
    const supabase = getSupabaseClient();
    await supabase.from('incidents').update({ status, updated_at: new Date().toISOString() }).eq('id', id);
    setIncidents(prev => prev.map(i => i.id === id ? { ...i, status } : i));
  }

  const filtered = incidents.filter(i => {
    if (statusFilter && i.status !== statusFilter) return false;
    if (severityFilter && i.severity !== severityFilter) return false;
    return true;
  });

  // Calculate risk score
  const riskScore = incidents.length === 0 ? 0 : Math.min(100, Math.round(
    incidents.reduce((acc, i) => {
      const weight = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
      return acc + (weight[i.severity as keyof typeof weight] ?? 1);
    }, 0)
  ));

  const overallStatus = riskScore >= 70 ? 'Critical' : riskScore >= 40 ? 'High Risk' : riskScore >= 20 ? 'Suspicious' : riskScore > 0 ? 'Low Risk' : 'Clean';
  const statusColor = riskScore >= 70 ? '#FF3B30' : riskScore >= 40 ? '#FF6B35' : riskScore >= 20 ? '#FFB800' : riskScore > 0 ? '#4DC9FF' : '#34C759';

  const allIPs = [...new Set(incidents.flatMap(i => i.source_ips))];
  const allUsers = [...new Set(incidents.flatMap(i => i.targeted_users))];
  const mitreTechniques = [...new Set(incidents.map(i => i.mitre_technique_id).filter(Boolean))];
  const tactics = [...new Set(incidents.map(i => i.mitre_tactic).filter(Boolean))];

  const criticalCount = incidents.filter(i => i.severity === 'critical').length;
  const highCount = incidents.filter(i => i.severity === 'high').length;

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Threat Analysis</h1>
          <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>{incidents.length} detected incidents</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button onClick={() => setActiveTab('incidents')}
            style={{ padding: '0.5rem 1rem', borderRadius: '8px', border: 'none', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600, background: activeTab === 'incidents' ? '#00FF88' : 'rgba(255,255,255,0.05)', color: activeTab === 'incidents' ? '#0A0E17' : '#8892A4' }}>
            Incidents
          </button>
          <button onClick={() => setActiveTab('report')}
            style={{ padding: '0.5rem 1rem', borderRadius: '8px', border: 'none', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600, background: activeTab === 'report' ? '#00FF88' : 'rgba(255,255,255,0.05)', color: activeTab === 'report' ? '#0A0E17' : '#8892A4', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <FileText size={14} /> Security Report
          </button>
        </div>
      </div>

      {/* Security Analysis Report Tab */}
      {activeTab === 'report' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>

          {/* Overall Status Banner */}
          <div className="glass-card" style={{ padding: '1.5rem', borderLeft: `4px solid ${statusColor}`, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.375rem' }}>Overall Security Status</div>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: statusColor }}>{overallStatus}</div>
              <div style={{ fontSize: '0.875rem', color: '#8892A4', marginTop: '0.25rem' }}>{incidents.length} threats detected across {allIPs.length} source IPs</div>
            </div>
            <RiskGauge score={riskScore} />
          </div>

          {/* Metrics row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '0.75rem' }}>
            {[
              { label: 'Critical Threats', value: criticalCount, color: '#FF3B30' },
              { label: 'High Severity', value: highCount, color: '#FF6B35' },
              { label: 'Source IPs', value: allIPs.length, color: '#00FF88' },
              { label: 'Affected Users', value: allUsers.length, color: '#00D4FF' },
              { label: 'MITRE Techniques', value: mitreTechniques.length, color: '#FFB800' },
              { label: 'Total Incidents', value: incidents.length, color: '#8892A4' },
            ].map(m => (
              <div key={m.label} className="glass-card" style={{ padding: '1rem', borderTop: `2px solid ${m.color}` }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: m.color, fontFamily: 'JetBrains Mono, monospace' }}>{m.value}</div>
                <div style={{ fontSize: '0.75rem', color: '#8892A4', marginTop: '0.25rem' }}>{m.label}</div>
              </div>
            ))}
          </div>

          {/* Detected Attacks */}
          {incidents.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertTriangle size={16} color="#FF3B30" /> Detected Attacks
              </h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {incidents.map(inc => (
                  <div key={inc.id} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.875rem', background: `${SEVERITY_COLORS[inc.severity]}15`, border: `1px solid ${SEVERITY_COLORS[inc.severity]}40`, borderRadius: '8px' }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: SEVERITY_COLORS[inc.severity], flexShrink: 0 }} />
                    <span style={{ fontSize: '0.8125rem', color: '#E8EDF5', fontWeight: 600 }}>{inc.title}</span>
                    <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IOCs */}
          {(allIPs.length > 0 || allUsers.length > 0) && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Globe size={16} color="#00FF88" /> Indicators of Compromise (IOCs)
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                {allIPs.length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Source IPs</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                      {allIPs.slice(0, 10).map(ip => (
                        <div key={ip} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.375rem 0.625rem', background: 'rgba(255,59,48,0.08)', borderRadius: '6px' }}>
                          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#FF3B30', flexShrink: 0 }} />
                          <span className="mono" style={{ fontSize: '0.8125rem', color: '#FF3B30' }}>{ip}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {allUsers.length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Targeted Users</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                      {allUsers.slice(0, 10).map(u => (
                        <div key={u} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.375rem 0.625rem', background: 'rgba(0,212,255,0.08)', borderRadius: '6px' }}>
                          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#00D4FF', flexShrink: 0 }} />
                          <span className="mono" style={{ fontSize: '0.8125rem', color: '#00D4FF' }}>{u}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* MITRE ATT&CK Mapping */}
          {mitreTechniques.length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Shield size={16} color="#FFB800" /> MITRE ATT&CK Mapping
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {incidents.filter(i => i.mitre_technique_id).map(inc => (
                  <div key={inc.id} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.625rem', background: 'rgba(255,184,0,0.06)', borderRadius: '6px', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', color: '#FFB800', background: 'rgba(255,184,0,0.15)', padding: '2px 8px', borderRadius: 4, flexShrink: 0 }}>{inc.mitre_technique_id}</span>
                    <span style={{ fontSize: '0.8125rem', color: '#E8EDF5', flex: 1 }}>{inc.title}</span>
                    <span style={{ fontSize: '0.75rem', color: '#8892A4' }}>{inc.mitre_tactic}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attack Timeline */}
          {incidents.filter(i => i.first_seen).length > 0 && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Clock size={16} color="#00D4FF" /> Attack Timeline
              </h3>
              <div style={{ position: 'relative', paddingLeft: '1.5rem' }}>
                <div style={{ position: 'absolute', left: '0.4375rem', top: 0, bottom: 0, width: 2, background: 'rgba(255,255,255,0.06)' }} />
                {incidents.filter(i => i.first_seen).sort((a, b) => new Date(a.first_seen!).getTime() - new Date(b.first_seen!).getTime()).map(inc => (
                  <div key={inc.id} style={{ position: 'relative', marginBottom: '1rem' }}>
                    <div style={{ position: 'absolute', left: '-1.125rem', top: 4, width: 10, height: 10, borderRadius: '50%', background: SEVERITY_COLORS[inc.severity], border: '2px solid #0A0E17' }} />
                    <div style={{ fontSize: '0.7rem', color: '#4A5568', fontFamily: 'JetBrains Mono, monospace', marginBottom: '0.25rem' }}>
                      {inc.first_seen ? format(new Date(inc.first_seen), 'MMM dd HH:mm:ss') : '—'}
                    </div>
                    <div style={{ fontSize: '0.875rem', color: '#E8EDF5', fontWeight: 600 }}>{inc.title}</div>
                    {inc.description && <div style={{ fontSize: '0.8125rem', color: '#8892A4', marginTop: '0.25rem' }}>{inc.description}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          <div
