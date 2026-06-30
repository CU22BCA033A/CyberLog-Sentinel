import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient } from '@/lib/supabase/server';
import { getTechnique } from '@/lib/mitre';

export const runtime = 'nodejs';

interface IncidentRow {
  incident_ref: string;
  title: string;
  severity: string;
  status: string;
  mitre_technique_id: string | null;
  source_ips: string[];
  targeted_users: string[];
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const jobId = searchParams.get('jobId');
  const format = searchParams.get('format') ?? 'json';

  if (!jobId) return NextResponse.json({ error: 'jobId required' }, { status: 400 });

  const supabase = createServerSupabaseClient();

  const [jobRes, incidentsRes, eventsRes] = await Promise.all([
    supabase.from('upload_jobs').select('*').eq('id', jobId).single(),
    supabase.from('incidents').select('*').eq('job_id', jobId).order('severity'),
    supabase.from('log_events').select('severity,outcome,source_ip').eq('job_id', jobId).limit(20000),
  ]);

  const job = jobRes.data;
  const incidents = (incidentsRes.data ?? []) as IncidentRow[];
  const events = eventsRes.data ?? [];

  if (format === 'csv') {
    const { data: fullEvents } = await supabase.from('log_events').select('*').eq('job_id', jobId).limit(20000);
    const rows = fullEvents ?? [];
    if (rows.length === 0) {
      return new NextResponse('No data', { status: 200, headers: { 'Content-Type': 'text/csv' } });
    }
    const headers = Object.keys(rows[0]);
    const csv = [headers.join(','), ...rows.map(r => headers.map(h => JSON.stringify((r as Record<string, unknown>)[h] ?? '')).join(','))].join('\n');
    return new NextResponse(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="events.csv"' } });
  }

  if (format === 'json') {
    return NextResponse.json({ job, incidents, eventCount: events.length }, {
      headers: { 'Content-Disposition': 'attachment; filename="incidents.json"' },
    });
  }

  if (format === 'stix') {
    const bundle = {
      type: 'bundle',
      id: `bundle--${jobId}`,
      objects: incidents.map((inc, i) => ({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${jobId}-${i}`,
        created: inc.first_seen ?? new Date().toISOString(),
        modified: inc.last_seen ?? new Date().toISOString(),
        name: inc.title,
        description: `${inc.incident_ref}: ${inc.title}`,
        indicator_types: ['malicious-activity'],
        pattern: inc.source_ips.map(ip => `[ipv4-addr:value = '${ip}']`).join(' OR ') || "[x-incident:ref = 'unknown']",
        pattern_type: 'stix',
        valid_from: inc.first_seen ?? new Date().toISOString(),
        labels: [inc.severity, inc.mitre_technique_id ?? 'unclassified'],
      })),
    };
    return NextResponse.json(bundle, { headers: { 'Content-Disposition': 'attachment; filename="threat-intel.stix.json"' } });
  }

  // PDF (simple text-based rendering since this is server-side without a browser)
  if (format === 'pdf') {
    const pdfText = buildReportText(job, incidents, events);
    const pdfBytes = buildSimplePDF(pdfText);
    return new NextResponse(new Uint8Array(pdfBytes), {
      headers: { 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="security-report.pdf"' },
    });
  }

  return NextResponse.json({ error: 'Unsupported format' }, { status: 400 });
}

function buildReportText(
  job: { filename: string; created_at: string } | null,
  incidents: IncidentRow[],
  events: Array<{ severity: string; outcome: string; source_ip: string | null }>
): string[] {
  const lines: string[] = [];
  lines.push('CYBERLOG SENTINEL — SECURITY ANALYSIS REPORT');
  lines.push('='.repeat(50));
  lines.push('');
  lines.push(`Source File: ${job?.filename ?? 'Unknown'}`);
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');
  lines.push('EXECUTIVE SUMMARY');
  lines.push('-'.repeat(50));
  const critical = incidents.filter(i => i.severity === 'critical').length;
  const high = incidents.filter(i => i.severity === 'high').length;
  const uniqueIPs = new Set(events.map(e => e.source_ip).filter(Boolean)).size;
  const failures = events.filter(e => e.outcome === 'failure').length;
  lines.push(`Total events analyzed: ${events.length}`);
  lines.push(`Total incidents detected: ${incidents.length} (${critical} critical, ${high} high)`);
  lines.push(`Unique source IPs observed: ${uniqueIPs}`);
  lines.push(`Total authentication failures: ${failures}`);
  lines.push('');
  lines.push('THREAT SUMMARY');
  lines.push('-'.repeat(50));
  for (const inc of incidents.slice(0, 30)) {
    const technique = inc.mitre_technique_id ? getTechnique(inc.mitre_technique_id) : undefined;
    lines.push(`[${inc.severity.toUpperCase()}] ${inc.incident_ref}: ${inc.title}`);
    lines.push(`  MITRE: ${inc.mitre_technique_id ?? 'N/A'} ${technique ? '- ' + technique.name : ''}`);
    lines.push(`  Sources: ${inc.source_ips.join(', ') || 'N/A'}`);
    lines.push(`  Targeted users: ${inc.targeted_users.join(', ') || 'N/A'}`);
    lines.push(`  Events: ${inc.event_count}`);
    lines.push('');
  }
  lines.push('RECOMMENDATIONS');
  lines.push('-'.repeat(50));
  if (critical > 0) lines.push('- Immediately rotate credentials for any accounts flagged in critical incidents.');
  if (incidents.some(i => i.mitre_technique_id?.startsWith('T1110'))) lines.push('- Implement rate limiting and fail2ban on SSH endpoints.');
  if (incidents.some(i => i.mitre_technique_id === 'T1078.003')) lines.push('- Disable direct root SSH login (PermitRootLogin no).');
  lines.push('- Review all flagged sudo shell escapes for unauthorized privilege escalation.');
  lines.push('- Enable MFA for all remote access where not already enforced.');
  return lines;
}

// Minimal single-page PDF generator (no external deps) for plain text report content.
function buildSimplePDF(lines: string[]): Buffer {
  const escape = (s: string) => s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  const fontSize = 9;
  const lineHeight = 12;
  const pageHeight = 792;
  const marginTop = 750;
  const linesPerPage = Math.floor((marginTop - 40) / lineHeight);

  const pages: string[][] = [];
  for (let i = 0; i < lines.length; i += linesPerPage) {
    pages.push(lines.slice(i, i + linesPerPage));
  }
  if (pages.length === 0) pages.push(['No data']);

  const objects: string[] = [];
  const pageObjIds: number[] = [];
  let objCounter = 1;

  // Font object will be id 3, placed after pages; we pre-reserve ids
  const fontObjId = 2 + pages.length * 2 + 1;

  pages.forEach((pageLines, idx) => {
    const contentLines = pageLines.map((l, i) => {
      const y = marginTop - i * lineHeight;
      return `BT /F1 ${fontSize} Tf 40 ${y} Td (${escape(l.slice(0, 110))}) Tj ET`;
    }).join('\n');
    const stream = contentLines;
    const contentObjId = 3 + idx * 2;
    const pageObjId = 4 + idx * 2;
    pageObjIds.push(pageObjId);
    objects.push(`${contentObjId} 0 obj\n<< /Length ${stream.length} >>\nstream\n${stream}\nendstream\nendobj`);
    objects.push(`${pageObjId} 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 ${fontObjId} 0 R >> >> /MediaBox [0 0 612 ${pageHeight}] /Contents ${contentObjId} 0 R >>\nendobj`);
  });

  const catalogObj = `1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj`;
  const pagesObj = `2 0 obj\n<< /Type /Pages /Kids [${pageObjIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pageObjIds.length} >>\nendobj`;
  const fontObj = `${fontObjId} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj`;

  const allObjects = [catalogObj, pagesObj, ...objects, fontObj];

  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [];
  for (const obj of allObjects) {
    offsets.push(Buffer.byteLength(pdf, 'utf-8'));
    pdf += obj + '\n';
  }
  const xrefStart = Buffer.byteLength(pdf, 'utf-8');
  pdf += `xref\n0 ${allObjects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) {
    pdf += `${String(off).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${allObjects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;

  return Buffer.from(pdf, 'utf-8');
}
