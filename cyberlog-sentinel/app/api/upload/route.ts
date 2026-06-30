import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient } from '@/lib/supabase/server';
import { parseLogContent } from '@/lib/parser';
import { runAllDetections } from '@/lib/detection';
import { isInternalIP } from '@/lib/utils/ip';
import type { LogEvent } from '@/types/log-event';

export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const supabase = createServerSupabaseClient();

    // Auth check via Bearer token or cookie
    const authHeader = req.headers.get('authorization');
    let userId: string | null = null;

    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      const { data } = await supabase.auth.getUser(token);
      userId = data.user?.id ?? null;
    }

    if (!userId) {
      // Try reading from cookie (Supabase sets cookies)
      const cookieHeader = req.headers.get('cookie') ?? '';
      // Fallback: skip auth check for now, use service role
      // In production you'd parse the Supabase session cookie properly
      userId = 'service'; // placeholder
    }

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

    // Create upload job record
    const { data: job, error: jobErr } = await supabase
      .from('upload_jobs')
      .insert({
        user_id: userId === 'service' ? null : userId,
        filename: file.name,
        file_size_bytes: file.size,
        status: 'processing',
      })
      .select()
      .single();

    if (jobErr || !job) {
      return NextResponse.json({ error: 'Failed to create job: ' + jobErr?.message }, { status: 500 });
    }

    const jobId = job.id as string;

    // Process file content
    const content = await file.text();
    const lines = content.split('\n').filter(l => l.trim());

    await supabase.from('upload_jobs').update({ total_lines: lines.length, status: 'processing' }).eq('id', jobId);

    // Parse events
    const events: LogEvent[] = parseLogContent(content);

    // Batch insert events (chunks of 500)
    const CHUNK = 500;
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
        raw_line: e.raw_line.slice(0, 2000),
        severity: e.severity,
        mitre_technique_id: e.mitre_technique_id,
        mitre_technique_name: e.mitre_technique_name,
        mitre_tactic: e.mitre_tactic,
        threat_tags: e.threat_tags,
        session_id: e.session_id,
        is_internal_ip: e.source_ip ? isInternalIP(e.source_ip) : false,
        is_false_positive: false,
      }));
      await supabase.from('log_events').insert(rows);
      await supabase.from('upload_jobs').update({ parsed_lines: Math.min(i + CHUNK, events.length) }).eq('id', jobId);
    }

    // Run detection engine
    const ruleResults = runAllDetections(events);

    // Build incidents from detections
    let incidentCounter = 1;
    const now = new Date();
    const yearStr = now.getFullYear();

    for (const ruleResult of ruleResults) {
      for (const detection of ruleResult.detections) {
        const incidentRef = `INC-${yearStr}-${String(incidentCounter).padStart(4, '0')}`;
        incidentCounter++;

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
          details: detection.details,
        });

        // Insert incident
        const evidenceEvents = events.filter(e => detection.evidence_event_ids.includes(e.id));
        const timestamps = evidenceEvents.map(e => e.timestamp.getTime()).filter(Boolean);
        const firstSeen = timestamps.length ? new Date(Math.min(...timestamps)).toISOString() : null;
        const lastSeen = timestamps.length ? new Date(Math.max(...timestamps)).toISOString() : null;

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
      const sessionKey = open.session_id;
      const close = sessionClosed.find(c => c.session_id === sessionKey && c.username === open.username);
      const loginTime = open.timestamp.toISOString();
      const logoutTime = close?.timestamp.toISOString() ?? null;
      const duration = close ? Math.round((close.timestamp.getTime() - open.timestamp.getTime()) / 1000) : null;

      // Find sudo commands during this session
      const sudoInSession = events.filter(e =>
        e.event_type === 'sudo_command' &&
        e.username === open.username &&
        e.timestamp.getTime() >= open.timestamp.getTime() &&
        (!close || e.timestamp.getTime() <= close.timestamp.getTime())
      ).map(e => e.raw_line.slice(0, 200));

      await supabase.from('ssh_sessions').insert({
        job_id: jobId,
        session_key: sessionKey,
        username: open.username,
        source_ip: open.source_ip,
        login_time: loginTime,
        logout_time: logoutTime,
        duration_seconds: duration,
        sudo_commands: sudoInSession,
        status: close ? 'closed' : 'active',
      });
    }

    // Mark job complete
    await supabase.from('upload_jobs').update({
      status: 'complete',
      parsed_lines: events.length,
      completed_at: new Date().toISOString(),
    }).eq('id', jobId);

    return NextResponse.json({ jobId, eventCount: events.length, incidentCount: incidentCounter - 1 });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    console.error('Upload error:', err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
