'use client';
import { useState, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Upload, FileText, X, CheckCircle, Loader2, AlertCircle, AlertTriangle } from 'lucide-react';

interface UploadFile {
  file: File;
  id: string;
  progress: number;
  status: 'pending' | 'uploading' | 'processing' | 'complete' | 'error';
  error?: string;
  jobId?: string;
  truncated?: boolean;
  processedLines?: number;
  totalLines?: number;
}

const ACCEPTED_TYPES = ['.log', '.txt', '.gz'];
const MAX_SIZE = 100 * 1024 * 1024; // 100MB

export default function UploadPage() {
  const [files, setFiles] = useState<UploadFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  function validateFile(file: File): string | null {
    if (file.size > MAX_SIZE) return `File too large (max 100MB). Size: ${(file.size / 1024 / 1024).toFixed(1)}MB`;
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!ACCEPTED_TYPES.includes(ext)) return `Invalid file type. Accepted: ${ACCEPTED_TYPES.join(', ')}`;
    return null;
  }

  function addFiles(newFiles: File[]) {
    const uploads: UploadFile[] = newFiles.map(file => {
      const error = validateFile(file);
      return {
        file,
        id: `${file.name}-${Date.now()}-${Math.random()}`,
        progress: 0,
        status: error ? 'error' : 'pending',
        error: error ?? undefined,
      };
    });
    setFiles(prev => [...prev, ...uploads]);
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    addFiles(Array.from(e.dataTransfer.files));
  }, []);

  async function uploadFile(upload: UploadFile) {
    setFiles(prev => prev.map(f =>
      f.id === upload.id ? { ...f, status: 'uploading', progress: 10 } : f
    ));

    const formData = new FormData();
    formData.append('file', upload.file);

    try {
      // Use a 110 second timeout — just under Vercel's 120s max
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 110_000);

      let res: Response;
      try {
        res = await fetch('/api/upload', {
          method: 'POST',
          body: formData,
          signal: controller.signal,
        });
        clearTimeout(timeout);
      } catch (fetchErr) {
        clearTimeout(timeout);
        if (fetchErr instanceof Error && fetchErr.name === 'AbortError') {
          throw new Error('Upload timed out. Your file may be too large — try a smaller sample (first 10,000 lines).');
        }
        throw fetchErr;
      }

      // Always parse as text first, then try JSON — avoids "Unexpected token" error
      const rawText = await res.text();
      let data: {
        jobId?: string;
        error?: string;
        truncated?: boolean;
        processedLines?: number;
        totalLines?: number;
        message?: string;
      };

      try {
        data = JSON.parse(rawText);
      } catch {
        // Server returned non-JSON (e.g. HTML error page or plain text crash)
        throw new Error(
          res.status === 504
            ? 'Server timed out (504). Your file is too large for the free tier — try uploading a smaller slice (first 5000 lines).'
            : res.status === 500
            ? `Server error: ${rawText.slice(0, 200)}`
            : `Unexpected response (${res.status}): ${rawText.slice(0, 200)}`
        );
      }

      if (!res.ok || data.error) {
        throw new Error(data.error ?? `Upload failed with status ${res.status}`);
      }

      if (!data.jobId) {
        throw new Error('Server did not return a job ID. Check Supabase environment variables.');
      }

      const jobId = data.jobId;

      setFiles(prev => prev.map(f =>
        f.id === upload.id
          ? {
              ...f,
              status: 'processing',
              progress: 50,
              jobId,
              truncated: data.truncated,
              processedLines: data.processedLines,
              totalLines: data.totalLines,
            }
          : f
      ));

      // Poll for job completion
      let attempts = 0;
      while (attempts < 120) {
        await new Promise(r => setTimeout(r, 1000));

        let statusData: {
          status: string;
          parsed_lines: number;
          total_lines: number;
          error_message?: string;
        };

        try {
          const statusRes = await fetch(`/api/process/${jobId}`);
          const statusText = await statusRes.text();
          statusData = JSON.parse(statusText);
        } catch {
          attempts++;
          continue; // network glitch, keep polling
        }

        const progress = statusData.total_lines
          ? Math.min(95, 50 + (statusData.parsed_lines / statusData.total_lines) * 45)
          : 70;

        setFiles(prev => prev.map(f =>
          f.id === upload.id ? { ...f, progress } : f
        ));

        if (statusData.status === 'complete') {
          setFiles(prev => prev.map(f =>
            f.id === upload.id
              ? { ...f, status: 'complete', progress: 100, jobId }
              : f
          ));
          break;
        }

        if (statusData.status === 'failed') {
          throw new Error(statusData.error_message ?? 'Processing failed on server');
        }

        attempts++;
      }

      if (attempts >= 120) {
        throw new Error('Timed out waiting for processing to complete. Check the dashboard — results may still have been saved.');
      }

    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      setFiles(prev => prev.map(f =>
        f.id === upload.id ? { ...f, status: 'error', error: msg } : f
      ));
    }
  }

  async function startUploads() {
    const pendingFiles = files.filter(f => f.status === 'pending');
    await Promise.all(pendingFiles.map(uploadFile));
  }

  const hasComplete = files.some(f => f.status === 'complete');
  const hasPending = files.some(f => f.status === 'pending');
  const isUploading = files.some(f => f.status === 'uploading' || f.status === 'processing');

  return (
    <div style={{ maxWidth: 700, margin: '0 auto' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>Upload Log Files</h1>
        <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>
          Upload Linux authentication logs for threat analysis. Supports auth.log, secure, and syslog formats.
        </p>
        <p style={{ color: '#FFB800', fontSize: '0.8125rem', marginTop: '0.375rem' }}>
          ⚠ Free tier limit: first 5,000 lines are processed. For full files, run locally with <span className="mono">npm run dev</span>.
        </p>
      </div>

      {/* Drop zone */}
      <div
        className="glass-card"
        onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        style={{
          padding: '3rem',
          textAlign: 'center',
          cursor: 'pointer',
          border: isDragging ? '2px dashed #00FF88' : '2px dashed rgba(255,255,255,0.1)',
          background: isDragging ? 'rgba(0,255,136,0.05)' : undefined,
          transition: 'all 0.2s ease',
          marginBottom: '1rem',
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".log,.txt,.gz"
          onChange={e => addFiles(Array.from(e.target.files ?? []))}
          style={{ display: 'none' }}
        />
        <div style={{ width: 56, height: 56, borderRadius: '50%', background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 1rem' }}>
          <Upload size={24} color="#00FF88" />
        </div>
        <h3 style={{ color: '#E8EDF5', fontSize: '1rem', fontWeight: 700, margin: '0 0 0.5rem' }}>
          Drop log files here or click to browse
        </h3>
        <p style={{ color: '#8892A4', fontSize: '0.8125rem', margin: 0 }}>
          Supports{' '}
          <span className="mono" style={{ color: '#00FF88' }}>.log</span>,{' '}
          <span className="mono" style={{ color: '#00FF88' }}>.txt</span>,{' '}
          <span className="mono" style={{ color: '#00FF88' }}>.gz</span>{' '}
          — up to 100MB each
        </p>
      </div>

      {/* File list */}
      {files.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1rem' }}>
          {files.map(upload => (
            <div key={upload.id} className="glass-card" style={{ padding: '1rem', display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
              <FileText
                size={18}
                color={
                  upload.status === 'error' ? '#FF3B30' :
                  upload.status === 'complete' ? '#00FF88' :
                  '#8892A4'
                }
                style={{ marginTop: 2, flexShrink: 0 }}
              />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.375rem' }}>
                  <span style={{ fontSize: '0.875rem', color: '#E8EDF5', fontFamily: 'JetBrains Mono, monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {upload.file.name}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: '#8892A4', marginLeft: '0.5rem', flexShrink: 0 }}>
                    {(upload.file.size / 1024).toFixed(0)} KB
                  </span>
                </div>

                {(upload.status === 'uploading' || upload.status === 'processing') && (
                  <>
                    <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden', marginBottom: '0.375rem' }}>
                      <div style={{ height: '100%', width: `${upload.progress}%`, background: '#00FF88', borderRadius: 2, transition: 'width 0.5s ease' }} />
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#00D4FF' }}>
                      {upload.status === 'uploading' ? 'Uploading and parsing...' : 'Running detection rules... this may take up to 60 seconds'}
                    </div>
                  </>
                )}

                {upload.status === 'complete' && upload.truncated && (
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.375rem', marginTop: '0.375rem', padding: '0.5rem', background: 'rgba(255,184,0,0.08)', border: '1px solid rgba(255,184,0,0.2)', borderRadius: 6 }}>
                    <AlertTriangle size={13} color="#FFB800" style={{ flexShrink: 0, marginTop: 1 }} />
                    <span style={{ fontSize: '0.75rem', color: '#FFB800' }}>
                      Processed {upload.processedLines?.toLocaleString()} of {upload.totalLines?.toLocaleString()} lines (free tier limit).
                      Results are representative — run locally for full analysis.
                    </span>
                  </div>
                )}

                {upload.status === 'complete' && !upload.truncated && (
                  <div style={{ fontSize: '0.75rem', color: '#00FF88', marginTop: '0.375rem' }}>
                    ✓ All {upload.processedLines?.toLocaleString() ?? ''} lines processed successfully
                  </div>
                )}

                {upload.error && (
                  <div style={{ fontSize: '0.75rem', color: '#FF3B30', marginTop: '0.375rem', lineHeight: 1.5 }}>
                    {upload.error}
                  </div>
                )}
              </div>

              <div style={{ flexShrink: 0 }}>
                {upload.status === 'complete' && <CheckCircle size={18} color="#00FF88" />}
                {upload.status === 'error' && <AlertCircle size={18} color="#FF3B30" />}
                {(upload.status === 'uploading' || upload.status === 'processing') && (
                  <Loader2 size={18} color="#00D4FF" style={{ animation: 'spin 1s linear infinite' }} />
                )}
                {upload.status === 'pending' && (
                  <button
                    onClick={e => { e.stopPropagation(); setFiles(prev => prev.filter(f => f.id !== upload.id)); }}
                    style={{ background: 'none', border: 'none', color: '#8892A4', cursor: 'pointer', display: 'flex' }}
                  >
                    <X size={16} />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Actions */}
      <div style={{ display: 'flex', gap: '0.75rem' }}>
        {hasPending && (
          <button
            onClick={startUploads}
            disabled={isUploading}
            style={{ flex: 1, padding: '0.875rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '8px', border: 'none', cursor: isUploading ? 'not-allowed' : 'pointer', fontSize: '0.875rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', opacity: isUploading ? 0.7 : 1 }}
          >
            {isUploading
              ? <><Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> Analyzing — please wait...</>
              : <><Upload size={16} /> Analyze {files.filter(f => f.status === 'pending').length} File{files.filter(f => f.status === 'pending').length !== 1 ? 's' : ''}</>
            }
          </button>
        )}
        {hasComplete && (
          <button
            onClick={() => router.push('/dashboard')}
            style={{ flex: 1, padding: '0.875rem', background: 'transparent', color: '#00FF88', fontWeight: 700, borderRadius: '8px', border: '1px solid rgba(0,255,136,0.4)', cursor: 'pointer', fontSize: '0.875rem' }}
          >
            View Dashboard →
          </button>
        )}
      </div>

      {/* Supported sources */}
      <div className="glass-card" style={{ padding: '1rem', marginTop: '2rem' }}>
        <h4 style={{ color: '#8892A4', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', margin: '0 0 0.5rem' }}>
          Supported Log Sources
        </h4>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {['/var/log/auth.log', '/var/log/secure', '/var/log/syslog', 'journald JSON'].map(s => (
            <span key={s} className="mono" style={{ fontSize: '0.75rem', color: '#00FF88', background: 'rgba(0,255,136,0.08)', padding: '2px 8px', borderRadius: 4 }}>
              {s}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
