'use client';
import { useState, useEffect } from 'react';
import { getSupabaseClient } from '@/lib/supabase/client';
import { FileText, Download, Loader2 } from 'lucide-react';

interface JobSummary { id: string; filename: string; created_at: string }

export default function ReportsPage() {
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [selectedJob, setSelectedJob] = useState<string>('');
  const [generating, setGenerating] = useState<string | null>(null);

  useEffect(() => { loadJobs(); }, []);

  async function loadJobs() {
    const supabase = getSupabaseClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;
    const { data } = await supabase.from('upload_jobs').select('id,filename,created_at').eq('user_id', user.id).eq('status', 'complete').order('created_at', { ascending: false });
    setJobs((data ?? []) as JobSummary[]);
    if (data && data.length > 0) setSelectedJob(data[0].id);
  }

  async function generateReport(format: 'pdf' | 'csv' | 'json' | 'stix') {
    if (!selectedJob) return;
    setGenerating(format);
    try {
      const res = await fetch(`/api/reports/generate?jobId=${selectedJob}&format=${format}`);
      if (!res.ok) throw new Error('Report generation failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cyberlog-report-${selectedJob.slice(0, 8)}.${format === 'pdf' ? 'pdf' : format === 'stix' ? 'json' : format}`;
      a.click();
    } catch (err) {
      alert('Failed to generate report: ' + (err instanceof Error ? err.message : 'Unknown error'));
    } finally {
      setGenerating(null);
    }
  }

  const FORMATS = [
    { id: 'pdf', label: 'Full PDF Report', desc: 'Executive summary, threat tables, charts, MITRE coverage, recommendations' },
    { id: 'csv', label: 'CSV Export', desc: 'Raw event data for spreadsheet analysis' },
    { id: 'json', label: 'JSON Export', desc: 'All incidents and detections in structured JSON' },
    { id: 'stix', label: 'STIX 2.1 Bundle', desc: 'Threat intelligence sharing format' },
  ] as const;

  return (
    <div style={{ maxWidth: 700, margin: '0 auto' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Reports</h1>
        <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>Generate security reports for analysis sessions</p>
      </div>

      {jobs.length === 0 ? (
        <div className="glass-card" style={{ padding: '3rem', textAlign: 'center', color: '#8892A4' }}>
          No completed analyses available. Upload a log file first.
        </div>
      ) : (
        <>
          <div className="glass-card" style={{ padding: '1.25rem', marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#8892A4', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Analysis Session</label>
            <select value={selectedJob} onChange={e => setSelectedJob(e.target.value)}
              style={{ width: '100%', padding: '0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', color: '#E8EDF5', fontSize: '0.875rem', cursor: 'pointer' }}>
              {jobs.map(j => <option key={j.id} value={j.id}>{j.filename} — {new Date(j.created_at).toLocaleDateString()}</option>)}
            </select>
          </div>

          <div style={{ display: 'grid', gap: '1rem' }}>
            {FORMATS.map(f => (
              <div key={f.id} className="glass-card" style={{ padding: '1.25rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div style={{ width: 40, height: 40, borderRadius: '8px', background: 'rgba(0,255,136,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <FileText size={18} color="#00FF88" />
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, color: '#E8EDF5', fontSize: '0.9375rem' }}>{f.label}</div>
                    <div style={{ fontSize: '0.8125rem', color: '#8892A4' }}>{f.desc}</div>
                  </div>
                </div>
                <button onClick={() => generateReport(f.id)} disabled={generating !== null}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.625rem 1rem', background: 'transparent', border: '1px solid rgba(0,255,136,0.3)', borderRadius: '8px', color: '#00FF88', cursor: generating ? 'not-allowed' : 'pointer', fontSize: '0.8125rem', fontWeight: 600, flexShrink: 0 }}>
                  {generating === f.id ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Download size={14} />}
                  {generating === f.id ? 'Generating...' : 'Download'}
                </button>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
