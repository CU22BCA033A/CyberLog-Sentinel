'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Shield, LayoutDashboard, Table2, AlertTriangle,
  Terminal, Search, FileText, Settings, Upload,
  ChevronLeft, ChevronRight, LogOut, Bell, Menu, X
} from 'lucide-react';
import { getSupabaseClient } from '@/lib/supabase/client';

const NAV_ITEMS = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/dashboard/events', label: 'Events', icon: Table2 },
  { href: '/dashboard/threats', label: 'Threats', icon: AlertTriangle },
  { href: '/dashboard/sessions', label: 'Sessions', icon: Terminal },
  { href: '/dashboard/search', label: 'Search', icon: Search },
  { href: '/dashboard/reports', label: 'Reports', icon: FileText },
  { href: '/dashboard/settings', label: 'Settings', icon: Settings },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [user, setUser] = useState<{ email?: string } | null>(null);
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    const supabase = getSupabaseClient();
    supabase.auth.getUser().then(({ data }) => {
      if (!data.user) router.push('/login');
      else setUser(data.user);
    });
  }, [router]);

  async function handleLogout() {
    const supabase = getSupabaseClient();
    await supabase.auth.signOut();
    router.push('/login');
  }

  const sidebarW = collapsed ? 64 : 240;

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0A0E17' }}>
      {/* Sidebar */}
      <aside style={{
        width: sidebarW, flexShrink: 0, background: '#0F1520',
        borderRight: '1px solid rgba(255,255,255,0.06)', display: 'flex',
        flexDirection: 'column', position: 'fixed', top: 0, left: 0,
        height: '100vh', zIndex: 40, transition: 'width 0.2s ease',
        overflowX: 'hidden',
      }}>
        {/* Logo */}
        <div style={{ padding: '1rem', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: '0.75rem', minHeight: '64px' }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: 'rgba(0,255,136,0.15)', border: '1px solid rgba(0,255,136,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Shield size={16} color="#00FF88" />
          </div>
          {!collapsed && <span style={{ fontWeight: 800, fontSize: '0.9rem', color: '#E8EDF5', whiteSpace: 'nowrap' }}>CyberLog Sentinel</span>}
        </div>

        {/* Upload CTA */}
        {!collapsed && (
          <div style={{ padding: '0.75rem' }}>
            <Link href="/upload" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.625rem 0.75rem', background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.25)', borderRadius: '8px', color: '#00FF88', textDecoration: 'none', fontSize: '0.8125rem', fontWeight: 600 }}>
              <Upload size={14} />
              Upload Logs
            </Link>
          </div>
        )}

        {/* Nav */}
        <nav style={{ flex: 1, padding: '0.5rem', overflowY: 'auto' }}>
          {NAV_ITEMS.map(item => {
            const Icon = item.icon;
            const active = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
            return (
              <Link key={item.href} href={item.href} style={{
                display: 'flex', alignItems: 'center', gap: '0.75rem',
                padding: collapsed ? '0.75rem' : '0.625rem 0.75rem',
                borderRadius: '8px', marginBottom: '2px', textDecoration: 'none',
                color: active ? '#00FF88' : '#8892A4', fontWeight: active ? 600 : 400,
                background: active ? 'rgba(0,255,136,0.08)' : 'transparent',
                fontSize: '0.875rem', justifyContent: collapsed ? 'center' : 'flex-start',
                transition: 'all 0.15s ease',
              }}>
                <Icon size={16} style={{ flexShrink: 0 }} />
                {!collapsed && <span style={{ whiteSpace: 'nowrap' }}>{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Bottom */}
        <div style={{ padding: '0.75rem', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <button onClick={handleLogout} style={{
            display: 'flex', alignItems: 'center', gap: '0.75rem',
            padding: collapsed ? '0.75rem' : '0.625rem 0.75rem', borderRadius: '8px',
            background: 'none', border: 'none', color: '#8892A4', cursor: 'pointer',
            fontSize: '0.875rem', width: '100%', justifyContent: collapsed ? 'center' : 'flex-start',
          }}>
            <LogOut size={16} />
            {!collapsed && 'Sign Out'}
          </button>
          <button onClick={() => setCollapsed(!collapsed)} style={{
            display: 'flex', alignItems: 'center', gap: '0.75rem',
            padding: collapsed ? '0.75rem' : '0.625rem 0.75rem', borderRadius: '8px',
            background: 'none', border: 'none', color: '#4A5568', cursor: 'pointer',
            fontSize: '0.875rem', width: '100%', marginTop: '4px', justifyContent: collapsed ? 'center' : 'flex-start',
          }}>
            {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
            {!collapsed && 'Collapse'}
          </button>
        </div>
      </aside>

      {/* Main */}
      <div style={{ flex: 1, marginLeft: sidebarW, display: 'flex', flexDirection: 'column', minHeight: '100vh', transition: 'margin-left 0.2s ease' }}>
        {/* Topbar */}
        <header style={{
          height: 64, background: '#0F1520', borderBottom: '1px solid rgba(255,255,255,0.06)',
          display: 'flex', alignItems: 'center', padding: '0 1.5rem', gap: '1rem',
          position: 'sticky', top: 0, zIndex: 30,
        }}>
          <div style={{ flex: 1 }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#8892A4', fontSize: '0.75rem' }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#00FF88', boxShadow: '0 0 8px #00FF88' }} />
            LIVE
          </div>
          <button style={{ width: 36, height: 36, borderRadius: '8px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: '#8892A4' }}>
            <Bell size={16} />
          </button>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'rgba(0,255,136,0.15)', border: '1px solid rgba(0,255,136,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, color: '#00FF88' }}>
              {user?.email?.[0]?.toUpperCase() ?? 'A'}
            </div>
            {user?.email && <span style={{ fontSize: '0.8125rem', color: '#8892A4', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user.email}</span>}
          </div>
        </header>

        {/* Content */}
        <main style={{ flex: 1, padding: '1.5rem', overflowY: 'auto' }}>
          {children}
        </main>
      </div>
    </div>
  );
}
