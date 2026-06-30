import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'CyberLog Sentinel — SOC Log Analysis Platform',
  description: 'Professional Linux authentication log analysis and threat detection platform',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
