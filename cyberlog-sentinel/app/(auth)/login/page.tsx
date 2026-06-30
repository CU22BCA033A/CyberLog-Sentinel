'use client';
import { useState } from 'react';
import { getSupabaseClient } from '@/lib/supabase/client';
import { useRouter } from 'next/navigation';
import { Shield, Eye, EyeOff, Loader2 } from 'lucide-react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [magicLoading, setMagicLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [magicSent, setMagicSent] = useState(false);
  const [isRegister, setIsRegister] = useState(false);
  const [fullName, setFullName] = useState('');
  const router = useRouter();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const supabase = getSupabaseClient();
    if (isRegister) {
      const { error: err } = await supabase.auth.signUp({
        email, password,
        options: { data: { full_name: fullName } },
      });
      if (err) { setError(err.message); setLoading(false); return; }
      setError(null);
      alert('Registration successful! Check your email to confirm your account, then log in.');
      setIsRegister(false);
    } else {
      const { error: err } = await supabase.auth.signInWithPassword({ email, password });
      if (err) { setError(err.message); setLoading(false); return; }
      router.push('/dashboard');
    }
    setLoading(false);
  }

  async function handleMagicLink() {
    if (!email) { setError('Enter your email first'); return; }
    setMagicLoading(true);
    setError(null);
    const supabase = getSupabaseClient();
    const { error: err } = await supabase.auth.signInWithOtp({ email });
    if (err) { setError(err.message); } else { setMagicSent(true); }
    setMagicLoading(false);
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0A0E17', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem' }}>
      {/* Background grid */}
      <div style={{ position: 'fixed', inset: 0, backgroundImage: 'linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px)', backgroundSize: '40px 40px', pointerEvents: 'none' }} />

      <div style={{ width: '100%', maxWidth: '420px', position: 'relative', zIndex: 1 }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '64px', height: '64px', background: 'rgba(0,255,136,0.1)', borderRadius: '16px', border: '1px solid rgba(0,255,136,0.3)', marginBottom: '1rem' }}>
            <Shield size={32} color="#00FF88" />
          </div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#E8EDF5', margin: 0 }}>CyberLog Sentinel</h1>
          <p style={{ color: '#8892A4', fontSize: '0.875rem', marginTop: '0.25rem' }}>SOC Log Analysis Platform</p>
        </div>

        <div className="glass-card" style={{ padding: '2rem' }}>
          <h2 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '1.5rem', color: '#E8EDF5' }}>
            {isRegister ? 'Create Account' : 'Sign In'}
          </h2>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {isRegister && (
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#8892A4', marginBottom: '0.5rem', letterSpacing: '0.05em', textTransform: 'uppercase' }}>Full Name</label>
                <input
                  type="text"
                  value={fullName}
                  onChange={e => setFullName(e.target.value)}
                  placeholder="Jane Smith"
                  required
                  style={{ width: '100%', padding: '0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#E8EDF5', fontSize: '0.875rem', outline: 'none' }}
                />
              </div>
            )}
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#8892A4', marginBottom: '0.5rem', letterSpacing: '0.05em', textTransform: 'uppercase' }}>Email</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="analyst@company.com"
                required
                style={{ width: '100%', padding: '0.75rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#E8EDF5', fontSize: '0.875rem', outline: 'none' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#8892A4', marginBottom: '0.5rem', letterSpacing: '0.05em', textTransform: 'uppercase' }}>Password</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  style={{ width: '100%', padding: '0.75rem', paddingRight: '2.5rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#E8EDF5', fontSize: '0.875rem', outline: 'none' }}
                />
                <button type="button" onClick={() => setShowPassword(!showPassword)} style={{ position: 'absolute', right: '0.75rem', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: '#8892A4', cursor: 'pointer' }}>
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {error && (
              <div style={{ padding: '0.75rem', background: 'rgba(255,59,48,0.1)', border: '1px solid rgba(255,59,48,0.3)', borderRadius: '8px', color: '#FF3B30', fontSize: '0.875rem' }}>
                {error}
              </div>
            )}
            {magicSent && (
              <div style={{ padding: '0.75rem', background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.3)', borderRadius: '8px', color: '#00FF88', fontSize: '0.875rem' }}>
                Magic link sent! Check your email.
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{ width: '100%', padding: '0.875rem', background: '#00FF88', color: '#0A0E17', fontWeight: 700, borderRadius: '8px', border: 'none', cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', fontSize: '0.875rem', opacity: loading ? 0.7 : 1 }}
            >
              {loading && <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />}
              {isRegister ? 'Create Account' : 'Sign In'}
            </button>
          </form>

          {!isRegister && (
            <>
              <div style={{ textAlign: 'center', color: '#4A5568', fontSize: '0.75rem', margin: '1rem 0' }}>or</div>
              <button
                onClick={handleMagicLink}
                disabled={magicLoading}
                style={{ width: '100%', padding: '0.875rem', background: 'transparent', color: '#00D4FF', fontWeight: 600, borderRadius: '8px', border: '1px solid rgba(0,212,255,0.3)', cursor: magicLoading ? 'not-allowed' : 'pointer', fontSize: '0.875rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
              >
                {magicLoading && <Loader2 size={16} />}
                Send Magic Link
              </button>
            </>
          )}

          <div style={{ textAlign: 'center', marginTop: '1.5rem' }}>
            <button
              onClick={() => { setIsRegister(!isRegister); setError(null); }}
              style={{ background: 'none', border: 'none', color: '#8892A4', cursor: 'pointer', fontSize: '0.875rem' }}
            >
              {isRegister ? 'Already have an account? Sign in' : "Don't have an account? Register"}
            </button>
          </div>
        </div>

        <p style={{ textAlign: 'center', marginTop: '1.5rem', color: '#4A5568', fontSize: '0.75rem' }}>
          Protected system. All access is logged and audited.
        </p>
      </div>
    </div>
  );
}
