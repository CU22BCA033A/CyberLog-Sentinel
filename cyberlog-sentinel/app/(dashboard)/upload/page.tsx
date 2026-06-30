'use client';
import { useState, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Upload, FileText, X, CheckCircle, Loader2, AlertCircle } from 'lucide-react';

interface UploadFile {
  file: File;
  id: string;
  progress: number;
  status: 'pending' | 'uploading' | 'processing' | 'complete' | 'error';
  error?: string;
  jobId?: string;
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
      return { file, id: `${file.name}-${Date.now()}-${Math.random()}`, progress: 0, status: error ? 'error' : 'pending', error: error ?? undefined };
    });
    setFiles(prev => [...prev, ...uploads]);
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    addFiles(Array.from(e.dataTransfer.files));
  }, []);

  async function uploadFile(upload: UploadFile) {
    setFiles(prev => prev.map(f => f.id === upload.id ? { ...f, status: 'uploading', progress: 10 } : f));

    const formData = new FormData();
    formData.append('file', upload.file);

    try {
      const res = await fetch('/api/upload', { method: 'POST', body: formData });
      if (!res.ok) {
        const err = await res.json() as { error?: string };
        throw new Error(err.error ?? 'Upload failed');
      }
      const data = await res.json() as { jobId: string };
      const jobId = data.jobId;
      setFiles(prev => prev.map(f => f.id === upload.id ? { ...f, status: 'processing', progress: 50, jobId } : f));

      // Poll for completion
      let attempts = 0;
      while (attempts < 120) {
        await new Promise(r => setTimeout(r, 1000));
        const statusRes = await fetch(`/api/process/${jobId}`);
        const statusData = await statusRes.json() as { status: string; parsed_lines: number; total_lines: number; error_message?: string };
        const progress = statusData.total_lines ? Math.min(95, 50 + (statusData.parsed_lines / statusData.total_lines) * 45) : 70;
        setFiles(prev => prev.map(f => f.id === upload.id ? { ...f, progress } : f));
        if (statusData.status === 'complete') {
          setFiles(prev => prev.map(f => f.id === upload.id ? { ...f, status: 'complete', progress: 100, jobId } : f));
          break;
        }
        if (statusData.status === 'failed') {
          throw new Error(statusData.error_message ?? 'Processing failed');
        }
        attempts++;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      setFiles(prev => prev.map(f => f.id === upload.id ? { ...f, status: 'error', error: msg } : f));
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
        <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>Upload Linux authentication logs for threat analysis. Supports auth.log, secure, and syslog formats.</p>
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
        <input ref={fileInputRef} type="file" multiple accept=".log,.txt,.gz" onChange={e => addFiles(Array.from(e.target.files ?? []))} style={{ display: 'none' }} />
        <div style={{ width: 56, height: 56, borderRadius: '50%', background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 1rem' }}>
          <Upload size={24} color="#00FF88" />
        </div>
        <h3 style={{ color: '#E8EDF5', fontSize: '1rem', fontWeight: 700, margin: '0 0 0.5rem' }}>Drop log files here or click to browse</h3>
        <p style={{ color: '#8892A4', fontSize: '0.8125rem', margin: 0 }}>Supports <span className="mono" style={{ color: '#00FF88' }}>.log</span>, <span className="mono" style={{ color: '#00FF88' }}>.txt</span>, <span className="mono" style={{ color: '#00FF88' }}>.gz</span> — up to 100MB each</p>
      </div>

      {/* File list */}
      {files.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1rem' }}>
          {files.map(upload => (
            <div key={upload.id} className="glass-card" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <FileText size={18} color={upload.status === 'error' ? '#FF3B30' : upload.status === 'complete' ? '#00FF88' : '#8892A4'} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: upload.status === 'uploading' || upload.status === 'processing' ? '0.5rem' : 0 }}>
                  <span style={{ fontSize: '0.875rem', color: '#E8EDF5', fontFamily: 'JetBrains Mono, monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{upload.file.name}</span>
                  <span style={{ fontSize: '0.75rem', color: '#8892A4', marginLeft: '0.5rem', flexShrink: 0 }}>{(upload.file.size / 1024).toFixed(0)} KB</span>
                </div>
                {(upload.status === 'uploading' || upload.status === 'processing') && (
                  <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${upload.progress}%`, background: '#00FF88', borderRadius: 2, transition: 'width 0.5s ease' }} />
                  </div>
                )}
                {upload.error && <div style={{ fontSize: '0.75rem', color: '#FF3B30', marginTop: '0.25rem' }}>{upload.error}</div>}
                {upload.status === 'processing' && <div style={{ fontSize: '0.75rem', color: '#00D4FF', marginTop: '0.25rem' }}>Analyzing... running detection rules</div>}
              </div>
              <div style={{ flexShrink: 0 }}>
                {upload.status === 'complete' && <CheckCircle size={18} color="#00FF88" />}
                {upload.status === 'error' && <AlertCircle size={18} color="#FF3B30" />}
                {(upload.status === 'uploading' || upload.status === 'processing') && <Loader2 size={18} color="#00D4FF" style={{ animation: 'spin 1s linear infinite' }} />}
                {upload.status === 'pending' && (
                  <button onClick={(e) => { e.stopPropagation(); setFiles(prev => prev.filter(f => f.id !== upload.id)); }} style={{ background: 'none', border: 'none', color: '#8892A4', cursor: 'pointer', display: 'flex' }}>
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
          <button onClick={startUploads} disabled={isUploading} style={{ flex: 1, padding: '0.875rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '8px', border: 'none', cursor: isUploading ? 'not-allowed' : 'pointer', fontSize: '0.875rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', opacity: isUploading ? 0.7 : 1 }}>
            {isUploading ? <><Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> Analyzing...</> : <><Upload size={16} /> Analyze {files.filter(f => f.status === 'pending').length} File{files.filter(f => f.status === 'pending').length !== 1 ? 's' : ''}</>}
          </button>
        )}
        {hasComplete && (
          <button onClick={() => router.push('/dashboard')} style={{ flex: 1, padding: '0.875rem', background: 'transparent', color: '#00FF88', fontWeight: 700, borderRadius: '8px', border: '1px solid rgba(0,255,136,0.4)', cursor: 'pointer', fontSize: '0.875rem' }}>
            View Dashboard →
          </button>
        )}
      </div>

      {/* Sample log info */}
      <div className="glass-card" style={{ padding: '1rem', marginTop: '2rem' }}>
        <h4 style={{ color: '#8892A4', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', margin: '0 0 0.5rem' }}>Supported Log Sources</h4>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {['/var/log/auth.log', '/var/log/secure', '/var/log/syslog', 'journald JSON'].map(s => (
            <span key={s} className="mono" style={{ fontSize: '0.75rem', color: '#00FF88', background: 'rgba(0,255,136,0.08)', padding: '2px 8px', borderRadius: 4 }}>{s}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
