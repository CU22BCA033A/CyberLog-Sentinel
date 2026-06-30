export function isInternalIP(ip: string): boolean {
  if (!ip) return false;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return ip === '::1' || ip === 'localhost';
  const [a, b] = parts;
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 127)
  );
}

export async function enrichIPGeo(ip: string): Promise<{ country: string | null; city: string | null }> {
  if (isInternalIP(ip)) return { country: 'Internal', city: null };
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=country,city,status`, {
      signal: AbortSignal.timeout(3000),
    });
    const data = await res.json() as { status: string; country?: string; city?: string };
    if (data.status === 'success') {
      return { country: data.country ?? null, city: data.city ?? null };
    }
  } catch {
    // Geo enrichment is best-effort
  }
  return { country: null, city: null };
}
