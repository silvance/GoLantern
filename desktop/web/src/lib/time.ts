// Human-friendly time formatting. Analysts skim tables — "2m ago"
// communicates freshness faster than "5/20/2026, 2:34:15 PM". Keep the
// absolute timestamp around as a title-attribute fallback so the exact
// value is one hover away.

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (isNaN(t)) return "—";
  const diff = Date.now() - t;
  const abs = Math.abs(diff) / 1000;
  const suffix = diff >= 0 ? "ago" : "from now";
  if (abs < 5) return "just now";
  if (abs < 60) return `${Math.round(abs)}s ${suffix}`;
  if (abs < 3600) return `${Math.round(abs / 60)}m ${suffix}`;
  if (abs < 86_400) return `${Math.round(abs / 3600)}h ${suffix}`;
  if (abs < 86_400 * 30) return `${Math.round(abs / 86_400)}d ${suffix}`;
  return new Date(iso).toLocaleDateString();
}

export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}
