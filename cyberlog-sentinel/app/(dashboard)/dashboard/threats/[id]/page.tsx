'use client';
import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { getSupabaseClient } from '@/lib/supabase/client';
import { getTechnique } from '@/lib/mitre';
import { ArrowLeft, ExternalLink, Shield } from 'lucide-react';
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
  analyst_notes: string | null;
}

interface Detection {
  id: string;
  rule_name: string;
  event_ids: string[];
}

interface RawEvent {
  id: string;
  timestamp: string;
  raw_line: string;
  severity: string;
}

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [events, setEvents] = useState<RawEvent[]>([]);
  const [notes, setNotes] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => { load(); }, [params.id]);

  async function load() {
    setLoading(true);
    const supabase = getSupabaseClient();
    const { data: inc } = await supabase.from('incidents').select('*').eq('id', params.id).single();
    if (!inc) { setLoading(false); return; }
    setIncident(inc as Incident);
    setNotes(inc.analyst_notes ?? '');

    // Get related detection's event ids
    const { data: det } = await supabase.from('detections').select('event_ids').eq('job_id', inc.job_id).contains('details', {});
    const allEventIds = new Set<string>();
    (det ?? []).forEach((d: { event_ids: string[] }) => d.event_ids?.forEach(id => allEventIds.add(id)));

    if (allEventIds.size > 0) {
      const { data: evts } = await supabase.from('log_events').select('id,timestamp,raw_line,severity').in('id', Array.from(allEventIds)).order('timestamp');
      setEvents((evts ?? []) as RawEvent[]);
    }
    setLoading(false);
  }

  async function saveNotes() {
    if (!incident) return;
    const supabase = getSupabaseClient();
    await supabase.from('incidents').update({ analyst_notes: notes, updated_at: new Date().toISOString() }).eq('id', incident.id);
  }

  if (loading) return <div className="glass-card skeleton" style={{ height: 400 }} />;
  if (!incident) return <div className="glass-card" style={{ padding: '2rem', textAlign: 'center', color: '#8892A4' }}>Incident not found.</div>;

  const technique = incident.mitre_technique_id ? getTechnique(incident.mitre_technique_id) : undefined;

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      <button onClick={() => router.back()} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'none', border: 'none', color: '#8892A4', cursor: 'pointer', fontSize: '0.875rem', marginBottom: '1rem' }}>
        <ArrowLeft size={16} /> Back to Threats
      </button>

      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1.5rem', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', color: '#4A5568' }}>{incident.incident_ref}</span>
            <span className={`badge badge-${incident.severity}`}>{incident.severity}</span>
          </div>
          <h1 style={{ fontSize: '1.375rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>{incident.title}</h1>
          {incident.description && <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.5rem' }}>{incident.description}</p>}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Evidence */}
          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem' }}>Evidence Log ({events.length} events)</h3>
            <div className="scrollbar-thin" style={{ maxHeight: 400, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {events.length === 0 ? (
                <p style={{ color: '#4A5568', fontSize: '0.8125rem' }}>No detailed event evidence linked.</p>
              ) : events.map(evt => (
                <div key={evt.id} style={{ padding: '0.625rem', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ fontSize: '0.7rem', color: '#4A5568', fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap', flexShrink: 0 }}>{format(new Date(evt.timestamp), 'HH:mm:ss')}</span>
                  <code style={{ fontSize: '0.75rem', color: '#00FF88', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all' }}>{evt.raw_line}</code>
                </div>
              ))}
            </div>
          </div>

          {/* Analyst notes */}
          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 1rem' }}>Analyst Notes</h3>
            <textarea value={notes} onChange={e => setNotes(e.target.value)} onBlur={saveNotes}
              placeholder="Add investigation notes..." rows={5}
              style={{ width: '100%', padding: '0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', color: '#E8EDF5', fontSize: '0.875rem', outline: 'none', resize: 'vertical', fontFamily: 'Inter, sans-serif' }} />
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* MITRE context */}
          {technique && (
            <div className="glass-card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <Shield size={16} color="#FFB800" />
                <h3 style={{ fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: 0 }}>{technique.id} — {technique.name}</h3>
              </div>
              <p style={{ fontSize: '0.75rem', color: '#8892A4', margin: '0 0 0.75rem', lineHeight: 1.6 }}>{technique.description}</p>
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Tactic</div>
                <div style={{ fontSize: '0.8125rem', color: '#FFB800' }}>{technique.tactic}</div>
              </div>
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Mitigation</div>
                <div style={{ fontSize: '0.8125rem', color: '#E8EDF5', lineHeight: 1.5 }}>{technique.mitigation}</div>
              </div>
              <a href={technique.external_url} target="_blank" rel="noopener noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem', color: '#00D4FF', textDecoration: 'none' }}>
                View on MITRE ATT&CK <ExternalLink size={12} />
              </a>
            </div>
          )}

          {/* Details */}
          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <h3 style={{ fontSize: '0.875rem', fontWeight: 700, color: '#E8EDF5', margin: '0 0 0.75rem' }}>Incident Details</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.8125rem' }}>
              <div>
                <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Source IPs</div>
                <div className="mono" style={{ color: '#00FF88' }}>{incident.source_ips.join(', ') || '—'}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Targeted Users</div>
                <div className="mono" style={{ color: '#00D4FF' }}>{incident.targeted_users.join(', ') || '—'}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Event Count</div>
                <div style={{ color: '#E8EDF5' }}>{incident.event_count}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.25rem' }}>First Seen</div>
                <div style={{ color: '#E8EDF5' }}>{incident.first_seen ? format(new Date(incident.first_seen), 'PPpp') : '—'}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4A5568', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Last Seen</div>
                <div style={{ color: '#E8EDF5' }}>{incident.last_seen ? format(new Date(incident.last_seen), 'PPpp') : '—'}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
