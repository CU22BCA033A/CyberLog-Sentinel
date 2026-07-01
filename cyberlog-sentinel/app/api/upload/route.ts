import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient } from '@/lib/supabase/server';
import { parseLogContent } from '@/lib/parser';
import { runAllDetections } from '@/lib/detection';
import { isInternalIP } from '@/lib/utils/ip';
import type { LogEvent } from '@/types/log-event';

export const maxDuration = 60;
export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  try {
    const supabase = createServerSupabaseClient();

    const formData = await req.formData();
    const file = formData.get('file') as File | null;

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 });
    }

    const allowedExts = ['.log', '.txt', '.gz'];
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!allowedExts.includes(ext)) {
      return NextResponse.json({ error: `Invalid file type: ${ext}` }, { status: 400 });
    }

    if (file.size > 100 * 1024 * 1024) {
      return NextResponse.json({ error: 'File too large (max 100MB)' }, { status: 400 });
    }

    // Read file content
    let content: string;
    if (ext === '.gz') {
      const zlib = await import('zlib');
      const buf = Buffer.from(await file.arrayBuffer());
      content = zlib.gunzipSync(buf).toString('utf-8');
    } else {
      content = await file.text();
    }

    // LIMIT: only process first 5000 lines to stay within timeout
    const allLines = content.split('\n').filter(l => l.trim());
    const MAX_LINES = 5000;
    const lines = allLines.slice(0, MAX_LINES);
    const truncated = allLines.length > MAX_LINES;
    const processedContent = lines.join('\n');

    // Create job record
    const { data: job, error: jobErr } = await supabase
      .from('upload_jobs')
      .insert({
        user_id: null,
        filename: file.name,
        file_size_bytes: file.size,
        status: 'processing',
        total_lines: allLines.length,
        parsed_lines: 0,
      })
      .select()
      .single();

    if (jobErr || !job) {
      return NextResponse.json(
        { error: 'Failed to create job: ' + (jobErr?.message ?? 'unknown') },
        { status: 500 }
      );
    }

    const jobId = job.id as string;

    // Parse events
    const events: LogEvent[] = parseLogContent(processedContent);

    // Batch insert events in chunks of 200
    const CHUNK = 200;
    const insertedIds = new Map<string, string>(); // localId -> dbId

    for (let i = 0; i < events.length; i += CHUNK) {
      const chunk = events.slice(i, i + CHUNK);
      const rows = chunk.map(e => ({
        job_id: jobId,
        timestamp: e.timestamp.toISOString(),
        hostname: e.hostname,
        service: e.service,
        pid: e.pid,
        event_type: e.event_type,
        username: e.username,
        source_ip: e.source_ip,
        source_port: e.source_port,
        auth_method: e.auth_method,
        outcome: e.outcome,
        raw_line: e.raw_line.slice(0, 1000),
        severity: e.severity,
        mitre_technique_id: e.mitre_technique_id,
        mitre_technique_name: e.mitre_technique_name,
        mitre_tactic: e.mitre_tactic,
        threat_tags: e.threat_tags,
        session_id: e.session_id,
        is_internal_ip: e.source_ip ? isInternalIP(e.source_ip) : false,
        is_false_positive: false,
      }));

      const { data: inserted } = await supabase
        .from('log_events')
        .insert(rows)
        .select('id');

      (inserted ?? []).forEach((row, idx) => {
        insertedIds.set(chunk[idx].id, row.id);
      });

      await supabase
        .from('upload_jobs')
        .update({ parsed_lines: Math.min(i + CHUNK, events.length) })
        .eq('id', jobId);
    }

    // Run detections
    const ruleResults = runAllDetections(events);
    const now = new Date();
    let incidentCounter = 1;

    for (const ruleResult of ruleResults) {
      for (const detection of ruleResult.detections) {
        const incidentRef = `INC-${now.getFullYear()}-${String(incidentCounter).padStart(4, '0')}`;
        incidentCounter++;

        const evidenceEvents = events.filter(e =>
          detection.evidence_event_ids.includes(e.id)
        );
        const timestamps = evidenceEvents.map(e => e.timestamp.getTime());
        const firstSeen = timestamps.length
          ? new Date(Math.min(...timestamps)).toISOString()
          : null;
        const lastSeen = timestamps.length
          ? new Date(Math.max(...timestamps)).toISOString()
          : null;

        // Insert detection
        await supabase.from('detections').insert({
          job_id: jobId,
          rule_id: ruleResult.rule_id,
          rule_name: ruleResult.rule_name,
          severity: detection.severity,
          confidence: detection.confidence,
          source_ip: detection.source_ips[0] ?? null,
          username: detection.targeted_users[0] ?? null,
          mitre_technique_id: detection.mitre_technique_id,
          details: {
            ...detection.details,
            title: detection.title,
            description: detection.description,
            source_ips: detection.source_ips,
            targeted_users: detection.targeted_users,
          },
        });

        // Insert incident
        await supabase.from('incidents').insert({
          job_id: jobId,
          incident_ref: incidentRef,
          title: detection.title,
          description: detection.description,
          severity: detection.severity,
          status: 'open',
          mitre_technique_id: detection.mitre_technique_id,
          mitre_tactic: detection.mitre_tactic,
          source_ips: detection.source_ips,
          targeted_users: detection.targeted_users,
          event_count: detection.evidence_event_ids.length,
          first_seen: firstSeen,
          last_seen: lastSeen,
          is_false_positive: false,
        });
      }
    }

    // Reconstruct SSH sessions
    const sessionOpened = events.filter(e => e.event_type === 'pam_session_opened');
    const sessionClosed = events.filter(e => e.event_type === 'pam_session_closed');

    for (const open of sessionOpened) {
      const close = sessionClosed.find(
        c => c.session_id === open.session_id && c.username === open.username
      );
      const sudoInSession = events
        .filter(e =>
          e.event_type === 'sudo_command' &&
          e.username === open.username &&
          e.timestamp.getTime() >= open.timestamp.getTime() &&
          (!close || e.timestamp.getTime() <= close.timestamp.getTime())
        )
        .map(e => e.raw_line.slice(0, 200));

      await supabase.from('ssh_sessions').insert({
        job_id: jobId,
        session_key: open.session_id,
        username: open.username,
        source_ip: open.source_ip,
        login_time: open.timestamp.toISOString(),
        logout_time: close?.timestamp.toISOString() ?? null,
        duration_seconds: close
          ? Math.round((close.timestamp.getTime() - open.timestamp.getTime()) / 1000)
          : null,
        sudo_commands: sudoInSession,
        status: close ? 'closed' : 'active',
      });
    }

    // Mark complete
    await supabase
      .from('upload_jobs')
      .update({
        status: 'complete',
        parsed_lines: events.length,
        completed_at: new Date().toISOString(),
      })
      .eq('id', jobId);

    return NextResponse.json({
      jobId,
      eventCount: events.length,
      incidentCount: incidentCounter - 1,
      truncated,
      totalLines: allLines.length,
      processedLines: lines.length,
      message: truncated
        ? `Processed first ${MAX_LINES} of ${allLines.length} lines (Vercel free tier limit). Upgrade to Pro or run locally for full file processing.`
        : 'All lines processed successfully.',
    });

  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    console.error('Upload error:', err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
