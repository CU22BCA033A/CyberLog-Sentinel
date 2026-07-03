'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { getSupabaseClient } from '@/lib/supabase/client';
import { getLatestJobId } from '@/lib/utils/get-job';
import { AlertTriangle, Globe, Users, Clock, Shield, TrendingUp, FileText, ChevronDown, ChevronUp } from 'lucide-react';
import { format } from 'date-fns';

interface Incident {
  id: string; incident_ref: string; title: string; description: string | null;
  severity: string; status: string; mitre_technique_id: string | null;
  mitre_tactic: string | null; source_ips: string[]; targeted_users: string[];
  event_count: number; first_seen: string | null; last_seen: string | null;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_COLOR: Record<string, string> = { critical: '#FF3B30', high: '#FF6B35', medium: '#FFB800', low: '#4DC9FF', info: '#4A5568' };
const STATUS_COLOR: Record<string, string> = { open: '#FF3B30', investigating: '#FFB800', closed: '#34C759', false_positive: '#4A5568' };

function RiskGauge({ score }: { score: number }) {
  const color = score >= 80 ? '#FF3B30' : score >= 60 ? '#FF6B35' : score >= 40 ? '#FFB800' : score >= 20 ? '#4DC9FF' : '#34C759';
  const r = 40, circ = 2 * Math.PI * r, offset = circ - (score / 100) * circ;
  return (
    <div style={{ position: 'relative', width: 110, height: 110, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
      <svg width="110" height="110" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="55" cy="55" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
        <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1.2s ease' }} />
      </svg>
      <div style={{ position: 'absolute', textAlign: 'center' }}>
        <div style={{ fontSize: '1.5rem', fontWeight: 800, color, fontFamily: 'JetBrains Mono, monospace', lineHeight: 1 }}>{score}</div>
        <div style={{ fontSize: '0.6rem', color: '#4A5568', textTransform: 'uppercase', letterSpacing: '0.05em' }}>/ 100</div>
      </div>
    </div>
  );
}

export default function ThreatsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'incidents' | 'report'>('report');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const jid = await getLatestJobId();
      setJobId(jid);
      if (!jid) { setLoading(false); return; }
      const supabase = getSupabaseClient();
      const { data, error: err } = await supabase.from('incidents').select('*').eq('job_id', jid).order('created_at', { ascending: false });
      if (err) throw new Error(err.message);
      const sorted = (data ?? []).sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
      setIncidents(sorted as Incident[]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    }
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

  // Risk score calculation
  const riskScore = Math.min(100, incidents.reduce((acc, i) => {
    return acc + ({ critical: 20, high: 12, medium: 6, low: 2, info: 0 }[i.severity] ?? 0);
  }, 0));

  const overallStatus = riskScore >= 75 ? 'CRITICAL THREAT' : riskScore >= 50 ? 'HIGH RISK' : riskScore >= 25 ? 'SUSPICIOUS' : riskScore > 0 ? 'LOW RISK' : 'NO THREAT DETECTED';
  const statusColor = riskScore >= 75 ? '#FF3B30' : riskScore >= 50 ? '#FF6B35' : riskScore >= 25 ? '#FFB800' : riskScore > 0 ? '#4DC9FF' : '#34C759';

  const criticalCount = incidents.filter(i => i.severity === 'critical').length;
  const highCount = incidents.filter(i => i.severity === 'high').length;
  const allIPs = [...new Set(incidents.flatMap(i => i.source_ips))];
  const allUsers = [...new Set(incidents.flatMap(i => i.targeted_users))];
  const mitreTechniques = [...new Set(incidents.filter(i => i.mitre_technique_id).map(i => ({ id: i.mitre_technique_id!, tactic: i.mitre_tactic ?? '', title: i.title })))];
  const attackTypes = [...new Set(incidents.map(i => i.title.replace(' Detected', '').replace(' from ' + (i.source_ips[0] ?? ''), '')))];

  const RECS: Array<{ cond: boolean; priority: string; color: string; text: string }> = [
    { cond: criticalCount > 0, priority: 'IMMEDIATE', color: '#FF3B30', text: 'Isolate affected systems NOW. Block all flagged IPs at the firewall. Rotate credentials for all compromised accounts immediately.' },
    { cond: incidents.some(i => i.mitre_technique_id?.startsWith('T1110')), priority: 'CRITICAL', color: '#FF3B30', text: 'Implement account lockout after 5 failed attempts. Deploy fail2ban. Enable MFA on all SSH and web authentication endpoints.' },
    { cond: incidents.some(i => i.mitre_technique_id === 'T1078.003'), priority: 'HIGH', color: '#FF6B35', text: 'Disable direct root SSH login (PermitRootLogin no in /etc/ssh/sshd_config). Require sudo with logging for all privileged operations.' },
    { cond: incidents.some(i => i.mitre_technique_id === 'T1190'), priority: 'HIGH', color: '#FF6B35', text: 'SQL Injection detected. Immediately audit all database queries. Use parameterized queries. Deploy WAF rules for SQLi patterns.' },
    { cond: incidents.some(i => i.mitre_technique_id === 'T1059'), priority: 'CRITICAL', color: '#FF3B30', text: 'Command injection detected. Audit all user-controlled inputs that reach system commands. Apply strict input validation and sandboxing.' },
    { cond: incidents.some(i => i.mitre_technique_id === 'T1059.007'), priority: 'HIGH', color: '#FF6B35', text: 'XSS detected. Implement Content Security Policy (CSP) headers. Sanitize all user-supplied HTML/JS output. Use HttpOnly cookies.' },
    { cond: incidents.some(i => i.mitre_technique_id === 'T1083'), priority: 'HIGH', color: '#FF6B35', text: 'Directory traversal detected. Validate all file path inputs. Use chroot jails. Deny access to sensitive paths via web server config.' },
    { cond: incidents.some(i => i.mitre_technique_id === 'T1046'), priority: 'MEDIUM', color: '#FFB800', text: 'Port scanning detected. Review firewall rules. Close unnecessary ports. Set up IDS/IPS rules to detect and block scan patterns.' },
    { cond: incidents.some(i => i.mitre_technique_id === 'T1486'), priority: 'CRITICAL', color: '#FF3B30', text: 'Ransomware activity detected. Disconnect affected systems immediately. Restore from clean backups. Do not pay ransom.' },
    { cond: true, priority: 'ONGOING', color: '#8892A4', text: 'Enable centralised log aggregation (SIEM). Set up real-time alerts. Conduct quarterly penetration testing. Patch all systems within 48 hours of CVE publication.' },
  ];

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, flexDirection: 'column', gap: '1rem' }}>
      <div style={{ width: 40, height: 40, border: '3px solid rgba(0,255,136,0.2)', borderTop: '3px solid #00FF88', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
      <p style={{ color: '#8892A4' }}>Loading threat data...</p>
    </div>
  );

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Threat Analysis</h1>
          <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>{incidents.length} incidents detected</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button onClick={() => setActiveTab('report')} style={{ padding: '0.5rem 1rem', borderRadius: '8px', border: 'none', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.375rem', background: activeTab === 'report' ? '#00FF88' : 'rgba(255,255,255,0.05)', color: activeTab === 'report' ? '#0A0E17' : '#8892A4' }}>
            <FileText size={14} /> Security Report
          </button>
          <button onClick={() => setActiveTab('incidents')} style={{ padding: '0.5rem 1rem', borderRadius: '8px', border: 'none', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600, background: activeTab === 'incidents' ? '#00FF88' : 'rgba(255,255,255,0.05)', color: activeTab === 'incidents' ? '#0A0E17' : '#8892A4' }}>
            Incidents List
          </button>
        </div>
      </div>

      {error && <div style={{ padding: '1rem', background: 'rgba(255,59,48,0.1)', border: '1px solid rgba(255,59,48,0.3)', borderRadius: '8px', color: '#FF3B30', marginBottom: '1rem' }}>{error}</div>}

      {!jobId && !loading && (
        <div className="glass-card" style={{ padding: '3rem', textAlign: 'center', color: '#8892A4' }}>
          <AlertTriangle size={40} color="#4A5568" style={{ marginBottom: '1rem' }} />
          <p>Upload a log file to detect threats and generate the security report.</p>
          <Link href="/upload" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', marginTop: '1rem', padding: '0.75rem 1.5rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '8px', textDecoration: 'none' }}>Upload Log File</Link>
        </div>
      )}

      {/* ===== SECURITY ANALYSIS REPORT TAB ===== */}
      {activeTab === 'report' && jobId && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>

          {/* Overall Status */}
          <div className="glass-card" style={{ padding: '1.5rem', borderLeft: `4px solid ${statusColor}` }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.7rem', color: '#4A5568', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Security Analysis Report</div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: statusColor, letterSpacing: '-0.02em' }}>{overallStatus}</div>
                <div style={{ fontSize: '0.875rem', color: '#8892A4', marginTop: '0.375rem' }}>
                  {incidents.length === 0 ? 'No malicious activity detected in this log file.' : `${incidents.length} threat${incidents.length !== 1 ? 's' : ''} detected — ${criticalCount} critical, ${highCount} high severity`}
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.7rem', color: '#4A5568', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Risk Score</div>
                <RiskGauge score={riskScore} />
              </div>
            </div>
          </div>

          {/* Metric cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: '0.75rem' }}>
            {[
              { label: 'Critical', value: criticalCount, color: '#FF3B30' },
              { label: 'High', value: highCount, color: '#FF6B35' },
              { label: 'Source IPs', value: allIPs.length, color: '#00FF88' },
              { label: 'Users Targeted', value: allUsers.length, color: '#00D4FF' },
              { label: 'MITRE Techniques', value: mitreTechniques.length, color: '#FFB800' },
              { label: 'Attack Types', value: attackTypes.length, color: '#8892A4' },
            ].map(m => (
              <div key={m.label} className="glass-card" style={{ padding: '1rem', borderTop: `2px solid ${m.color}` }}>
                <div style={{ fontSize: '1.75rem', fontWeight: 800, color: m.color, fontFamily: 'JetBrains Mono, monospace', lineHeight: 1 }}>{m.value}</div>
                <div style={{ fontSize: '0.75rem', color: '#8892A4', marginTop: '0.25rem' }}>{m.label}</div>
              </div>
            ))}
          </div>

          {incidents.length > 0 && (
            <>
              {/* Detected Attacks */}
              <div className="glass-card" style={{ padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <AlertTriangle size={16} color="#FF3B30" /> Detected Attacks
                </h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                  {incidents.map(inc => (
                    <div key={inc.id} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.875rem', background: `${SEV_COLOR[inc.severity]}12`, border: `1px solid ${SEV_COLOR[inc.severity]}35`, borderRadius: '8px' }}>
                      <div style={{ width: 8, height: 8, borderRadius: '50%', background: SEV_COLOR[inc.severity], boxShadow: `0 0 6px ${SEV_COLOR[inc.severity]}`, flexShrink: 0 }} />
                      <span style={{ fontSize: '0.8125rem', color: '#E8EDF5', fontWeight: 600 }}>{inc.title}</span>
                      <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* IOCs */}
              <div className="glass-card" style={{ padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Globe size={16} color="#00FF88" /> Indicators of Compromise (IOCs)
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: allUsers.length > 0 ? '1fr 1fr' : '1fr', gap: '1rem' }}>
                  {allIPs.length > 0 && (
                    <div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Attacker IPs ({allIPs.length})</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem', maxHeight: 200, overflowY: 'auto' }}>
                        {allIPs.map(ip => (
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
                      <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Targeted Accounts ({allUsers.length})</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem', maxHeight: 200, overflowY: 'auto' }}>
                        {allUsers.map(u => (
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

              {/* Attack Timeline */}
              <div className="glass-card" style={{ padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Clock size={16} color="#00D4FF" /> Attack Timeline
                </h3>
                <div style={{ position: 'relative', paddingLeft: '1.5rem' }}>
                  <div style={{ position: 'absolute', left: '0.4375rem', top: 0, bottom: 0, width: 2, background: 'rgba(255,255,255,0.06)' }} />
                  {incidents.filter(i => i.first_seen).sort((a, b) => new Date(a.first_seen!).getTime() - new Date(b.first_seen!).getTime()).map(inc => (
                    <div key={inc.id} style={{ position: 'relative', marginBottom: '1rem' }}>
                      <div style={{ position: 'absolute', left: '-1.125rem', top: 4, width: 10, height: 10, borderRadius: '50%', background: SEV_COLOR[inc.severity], border: '2px solid #0A0E17', boxShadow: `0 0 8px ${SEV_COLOR[inc.severity]}` }} />
                      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
                        <span className="mono" style={{ fontSize: '0.7rem', color: '#4A5568', whiteSpace: 'nowrap', flexShrink: 0, paddingTop: 2 }}>
                          {inc.first_seen ? format(new Date(inc.first_seen), 'MMM dd HH:mm:ss') : '—'}
                        </span>
                        <div>
                          <span className={`badge badge-${inc.severity}`} style={{ marginRight: '0.5rem' }}>{inc.severity}</span>
                          <span style={{ fontSize: '0.875rem', color: '#E8EDF5', fontWeight: 600 }}>{inc.title}</span>
                          {inc.description && <div style={{ fontSize: '0.8125rem', color: '#8892A4', marginTop: '0.25rem', lineHeight: 1.5 }}>{inc.description}</div>}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* MITRE ATT&CK */}
              <div className="glass-card" style={{ padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Shield size={16} color="#FFB800" /> MITRE ATT&CK Mapping
                </h3>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                      {['Technique ID', 'Name', 'Tactic', 'Severity'].map(h => (
                        <th key={h} style={{ textAlign: 'left', padding: '0.5rem', fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {incidents.filter(i => i.mitre_technique_id).map(inc => (
                      <tr key={inc.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <td style={{ padding: '0.625rem 0.5rem' }}>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8125rem', color: '#FFB800', background: 'rgba(255,184,0,0.1)', padding: '2px 8px', borderRadius: 4 }}>{inc.mitre_technique_id}</span>
                        </td>
                        <td style={{ padding: '0.625rem 0.5rem', color: '#E8EDF5' }}>{inc.title}</td>
                        <td style={{ padding: '0.625rem 0.5rem', color: '#8892A4' }}>{inc.mitre_tactic ?? '—'}</td>
                        <td style={{ padding: '0.625rem 0.5rem' }}><span className={`badge badge-${inc.severity}`}>{inc.severity}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Business Impact */}
              <div className="glass-card" style={{ padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <TrendingUp size={16} color="#FF6B35" /> Business Impact Assessment
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.875rem', color: '#8892A4', lineHeight: 1.7 }}>
                  {criticalCount > 0 && <p style={{ margin: 0, padding: '0.75rem', background: 'rgba(255,59,48,0.08)', borderRadius: '8px', borderLeft: '3px solid #FF3B30' }}><strong style={{ color: '#FF3B30' }}>Critical:</strong> Active system compromise detected. Data exfiltration, service disruption, and lateral movement are immediate risks. Estimated breach cost: HIGH.</p>}
                  {highCount > 0 && <p style={{ margin: 0, padding: '0.75rem', background: 'rgba(255,107,53,0.08)', borderRadius: '8px', borderLeft: '3px solid #FF6B35' }}><strong style={{ color: '#FF6B35' }}>High:</strong> Significant attack activity detected. Authentication systems under stress. Credential theft and unauthorized access are likely if not contained.</p>}
                  {incidents.some(i => i.mitre_technique_id === 'T1190') && <p style={{ margin: 0, padding: '0.75rem', background: 'rgba(255,184,0,0.08)', borderRadius: '8px', borderLeft: '3px solid #FFB800' }}><strong style={{ color: '#FFB800' }}>Data Risk:</strong> SQL injection attempts may expose sensitive database records, PII, financial data, or authentication credentials.</p>}
                  {incidents.some(i => i.mitre_technique_id === 'T1486') && <p style={{ margin: 0, padding: '0.75rem', background: 'rgba(255,59,48,0.08)', borderRadius: '8px', borderLeft: '3px solid #FF3B30' }}><strong style={{ color: '#FF3B30' }}>Ransomware:</strong> File encryption ransomware detected. Business continuity is at immediate risk. All operations may be disrupted.</p>}
                </div>
              </div>

              {/* Confidence & False Positive */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="glass-card" style={{ padding: '1.25rem' }}>
                  <h3 style={{ fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem' }}>Detection Confidence</h3>
                  {incidents.slice(0, 6).map(inc => {
                    const conf = inc.severity === 'critical' ? 95 : inc.severity === 'high' ? 88 : 75;
                    return (
                      <div key={inc.id} style={{ marginBottom: '0.75rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                          <span style={{ fontSize: '0.75rem', color: '#8892A4', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '75%' }}>{inc.title}</span>
                          <span style={{ fontSize: '0.75rem', color: '#00FF88', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>{conf}%</span>
                        </div>
                        <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                          <div style={{ height: '100%', width: `${conf}%`, background: SEV_COLOR[inc.severity], borderRadius: 2, transition: 'width 1s ease' }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div className="glass-card" style={{ padding: '1.25rem' }}>
                  <h3 style={{ fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem' }}>False Positive Risk</h3>
                  {incidents.slice(0, 6).map(inc => {
                    const fpLabel = inc.severity === 'critical' ? 'Very Low' : inc.severity === 'high' ? 'Low' : 'Medium';
                    const fpColor = fpLabel === 'Very Low' ? '#34C759' : fpLabel === 'Low' ? '#00D4FF' : '#FFB800';
                    return (
                      <div key={inc.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.625rem' }}>
                        <span style={{ fontSize: '0.75rem', color: '#8892A4', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '65%' }}>{inc.title}</span>
                        <span style={{ fontSize: '0.7rem', fontWeight: 600, color: fpColor, background: `${fpColor}15`, padding: '2px 8px', borderRadius: 4, flexShrink: 0 }}>{fpLabel} FP</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {/* Recommendations */}
          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <TrendingUp size={16} color="#00FF88" /> Recommendations
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
              {RECS.filter(r => r.cond).map((rec, i) => (
                <div key={i} style={{ display: 'flex', gap: '0.75rem', padding: '0.75rem', background: `${rec.color}08`, border: `1px solid ${rec.color}20`, borderRadius: '8px' }}>
                  <span style={{ fontSize: '0.65rem', fontWeight: 700, color: rec.color, background: `${rec.color}20`, padding: '3px 7px', borderRadius: 4, letterSpacing: '0.05em', flexShrink: 0, height: 'fit-content', marginTop: 1 }}>{rec.priority}</span>
                  <span style={{ fontSize: '0.875rem', color: '#E8EDF5', lineHeight: 1.6 }}>{rec.text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ===== INCIDENTS LIST TAB ===== */}
      {activeTab === 'incidents' && jobId && (
        <>
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
              style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem', cursor: 'pointer' }}>
              <option value="">All Statuses</option>
              {['open', 'investigating', 'closed', 'false_positive'].map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
            <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
              style={{ padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#E8EDF5', fontSize: '0.8125rem', cursor: 'pointer' }}>
              <option value="">All Severities</option>
              {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <span style={{ fontSize: '0.8125rem', color: '#8892A4', display: 'flex', alignItems: 'center' }}>{filtered.length} incident{filtered.length !== 1 ? 's' : ''}</span>
          </div>

          {filtered.length === 0 ? (
            <div className="glass-card" style={{ padding: '3rem', textAlign: 'center', color: '#8892A4' }}>No incidents match your current filters.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {filtered.map(inc => (
                <div key={inc.id} className="glass-card" style={{ borderLeft: `3px solid ${SEV_COLOR[inc.severity] ?? '#4A5568'}` }}>
                  <div style={{ padding: '1.25rem', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: 250 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '0.7rem', fontFamily: 'JetBrains Mono, monospace', color: '#4A5568' }}>{inc.incident_ref}</span>
                        <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>
                        {inc.mitre_technique_id && <span style={{ fontSize: '0.7rem', fontFamily: 'JetBrains Mono, monospace', color: '#FFB800', background: 'rgba(255,184,0,0.1)', padding: '2px 6px', borderRadius: 4 }}>{inc.mitre_technique_id}</span>}
                        {inc.mitre_tactic && <span style={{ fontSize: '0.7rem', color: '#8892A4', background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: 4 }}>{inc.mitre_tactic}</span>}
                      </div>
                      <Link href={`/dashboard/threats/${inc.id}`} style={{ textDecoration: 'none' }}>
                        <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#E8EDF5', margin: 0 }}>{inc.title}</h3>
                      </Link>
                      {inc.description && <p style={{ fontSize: '0.8125rem', color: '#8892A4', margin: '0.375rem 0 0', lineHeight: 1.5 }}>{inc.description}</p>}
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexShrink: 0 }}>
                      <select value={inc.status} onChange={e => updateStatus(inc.id, e.target.value)}
                        style={{ padding: '0.375rem 0.625rem', background: `${STATUS_COLOR[inc.status]}15`, border: `1px solid ${STATUS_COLOR[inc.status]}40`, borderRadius: '6px', color: STATUS_COLOR[inc.status], fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}>
                        {['open', 'investigating', 'closed', 'false_positive'].map(s => <option key={s} value={s} style={{ background: '#0F1520', color: '#E8EDF5' }}>{s.replace('_', ' ')}</option>)}
                      </select>
                      <button onClick={() => setExpandedId(expandedId === inc.id ? null : inc.id)}
                        style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#8892A4', cursor: 'pointer', width: 32, height: 32, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        {expandedId === inc.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                    </div>
                  </div>

                  {/* Meta row */}
                  <div style={{ padding: '0 1.25rem 1rem', display: 'flex', gap: '1.5rem', flexWrap: 'wrap', fontSize: '0.8125rem', color: '#8892A4' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}><AlertTriangle size={13} /> {inc.event_count} events</span>
                    {inc.source_ips.length > 0 && <span style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}><Globe size={13} /><span className="mono" style={{ color: '#00FF88' }}>{inc.source_ips.slice(0, 2).join(', ')}{inc.source_ips.length > 2 ? ` +${inc.source_ips.length - 2}` : ''}</span></span>}
                    {inc.targeted_users.length > 0 && <span style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}><Users size={13} /><span className="mono" style={{ color: '#00D4FF' }}>{inc.targeted_users.slice(0, 2).join(', ')}{inc.targeted_users.length > 2 ? ` +${inc.targeted_users.length - 2}` : ''}</span></span>}
                    {inc.first_seen && <span style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}><Clock size={13} />{format(new Date(inc.first_seen), 'MMM dd HH:mm')}{inc.last_seen ? ` → ${format(new Date(inc.last_seen), 'HH:mm')}` : ''}</span>}
                  </div>

                  {/* Expanded detail */}
                  {expandedId === inc.id && (
                    <div style={{ padding: '1rem 1.25rem', borderTop: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.2)' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Detection Logic</div>
                      <p style={{ fontSize: '0.875rem', color: '#8892A4', margin: 0, lineHeight: 1.6 }}>{inc.description}</p>
                      <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                        <Link href={`/dashboard/threats/${inc.id}`} style={{ fontSize: '0.8125rem', color: '#00FF88', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>View Full Evidence →</Link>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
