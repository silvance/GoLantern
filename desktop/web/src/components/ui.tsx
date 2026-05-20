// Reusable UI primitives. Tailwind composed once here so pages don't
// repeat the same long class strings. Keep these dumb — no data
// fetching, no router awareness.

import {
  ReactNode,
  Ref,
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
  useEffect,
  useState,
} from "react";
import { formatTimestamp, relativeTime } from "../lib/time";

export function Button({
  variant = "primary",
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
}) {
  const base =
    "inline-flex items-center justify-center px-3 py-1.5 rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  const styles: Record<string, string> = {
    primary:
      "bg-blue-600 text-white hover:bg-blue-500 dark:bg-blue-500 dark:hover:bg-blue-400",
    secondary:
      "bg-slate-200 text-slate-900 hover:bg-slate-300 dark:bg-slate-700 dark:text-slate-100 dark:hover:bg-slate-600",
    danger:
      "bg-red-600 text-white hover:bg-red-500 dark:bg-red-500 dark:hover:bg-red-400",
    ghost:
      "bg-transparent text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800",
  };
  return <button className={`${base} ${styles[variant]} ${className}`} {...rest} />;
}

export function Input({
  className = "",
  ref,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { ref?: Ref<HTMLInputElement> }) {
  return (
    <input
      ref={ref}
      className={`px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${className}`}
      {...rest}
    />
  );
}

export function Select({ className = "", ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={`px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${className}`}
      {...rest}
    />
  );
}

export function Textarea({ className = "", ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={`px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${className}`}
      {...rest}
    />
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg ${className}`}>
      {children}
    </div>
  );
}

export function PageTitle({ children, actions }: { children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex items-center justify-between mb-6">
      <h1 className="text-2xl font-semibold">{children}</h1>
      {actions && <div className="flex gap-2">{actions}</div>}
    </div>
  );
}

export function SectionTitle({ children, actions }: { children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex items-center justify-between mb-3">
      <h2 className="text-lg font-medium">{children}</h2>
      {actions && <div className="flex gap-2">{actions}</div>}
    </div>
  );
}

// Empty is the placeholder rendered when a list/table has no rows.
// The dashed border, optional icon, and optional action button make
// empty states feel intentional instead of half-built.
export function Empty({
  children,
  icon,
  action,
}: {
  children: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="text-center py-10 px-4 border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-lg">
      {icon && (
        <div className="mx-auto mb-3 inline-flex text-slate-400 dark:text-slate-600">
          {icon}
        </div>
      )}
      <p className="text-sm text-slate-500 dark:text-slate-400">{children}</p>
      {action && <div className="mt-4 inline-flex">{action}</div>}
    </div>
  );
}

export function ErrorMessage({ children }: { children: ReactNode }) {
  return (
    <p className="text-sm text-red-700 dark:text-red-400 py-2">{children}</p>
  );
}

export function Spinner() {
  return (
    <div className="inline-block h-4 w-4 border-2 border-slate-300 border-t-blue-600 rounded-full animate-spin" />
  );
}

const severityColors: Record<string, string> = {
  info: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  low: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200",
  medium: "bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-200",
  high: "bg-orange-100 text-orange-900 dark:bg-orange-900/40 dark:text-orange-200",
  critical: "bg-red-100 text-red-900 dark:bg-red-900/50 dark:text-red-200",
};

const severityDots: Record<string, string> = {
  info: "bg-slate-400 dark:bg-slate-500",
  low: "bg-blue-500",
  medium: "bg-amber-500",
  high: "bg-orange-500",
  critical: "bg-red-500",
};

export function SeverityBadge({ value }: { value: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded uppercase tracking-wide ${
        severityColors[value] ?? severityColors.info
      }`}
    >
      <span
        aria-hidden
        className={`inline-block w-1.5 h-1.5 rounded-full ${
          severityDots[value] ?? severityDots.info
        }`}
      />
      {value}
    </span>
  );
}

const statusColors: Record<string, string> = {
  pending: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  running: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200",
  completed: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
  failed: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200",
  cancelled: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  skipped_out_of_scope:
    "bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-200",
};

const statusDots: Record<string, string> = {
  pending: "bg-slate-400 dark:bg-slate-500",
  running: "bg-blue-500 animate-pulse",
  completed: "bg-emerald-500",
  failed: "bg-red-500",
  cancelled: "bg-slate-400 dark:bg-slate-500",
  skipped_out_of_scope: "bg-amber-500",
};

export function StatusBadge({ value }: { value: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded ${
        statusColors[value] ?? statusColors.pending
      }`}
    >
      <span
        aria-hidden
        className={`inline-block w-1.5 h-1.5 rounded-full ${
          statusDots[value] ?? statusDots.pending
        }`}
      />
      {value.replace(/_/g, " ")}
    </span>
  );
}

// RelativeTime renders a self-refreshing "2m ago" with the absolute
// timestamp on hover. Re-renders every 30s so a long-open page doesn't
// freeze at "just now" forever.
export function RelativeTime({
  iso,
  className = "",
}: {
  iso?: string | null;
  className?: string;
}) {
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!iso) return;
    const id = setInterval(() => setTick((n) => n + 1), 30_000);
    return () => clearInterval(id);
  }, [iso]);
  if (!iso) return <span className={className}>—</span>;
  return (
    <span className={className} title={formatTimestamp(iso)}>
      {relativeTime(iso)}
    </span>
  );
}

// CopyButton copies the supplied text to the clipboard and flips to a
// checkmark for 1.5s. The button intentionally stops propagation so it
// can live inside a clickable row without triggering navigation.
export function CopyButton({
  value,
  label = "Copy",
  className = "",
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async (e) => {
        e.preventDefault();
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          // Clipboard access can fail in some sandboxed contexts; the
          // toast/inline error is up to the caller. Silently no-op here.
        }
      }}
      title={copied ? "Copied" : label}
      aria-label={label}
      className={`inline-flex items-center justify-center w-6 h-6 rounded text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors ${className}`}
    >
      {copied ? (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ) : (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <rect x="9" y="9" width="13" height="13" rx="2" />
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </svg>
      )}
    </button>
  );
}

// LanternMark is the small brand glyph beside the wordmark in the
// header. Inline SVG so we don't ship an asset file or web font.
export function LanternMark({ className = "" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="22"
      height="22"
      fill="none"
      strokeWidth="1.8"
      strokeLinejoin="round"
      strokeLinecap="round"
      aria-hidden
      className={className}
    >
      <path d="M8 5h8l1 2H7z" stroke="currentColor" />
      <rect x="6" y="7" width="12" height="11" rx="1" stroke="currentColor" />
      <path d="M10 18v2h4v-2" stroke="currentColor" />
      <path
        d="M12 9c-2 1.8-2 3.6 0 5.5 2-1.9 2-3.7 0-5.5z"
        className="fill-amber-400 dark:fill-amber-300"
      />
    </svg>
  );
}

// FolderIcon and PlayIcon are reusable icons for empty states.
export function FolderIcon({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
    </svg>
  );
}

export function PlayIcon({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <polygon points="6 4 20 12 6 20 6 4" />
    </svg>
  );
}

export function SearchIcon({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="11" cy="11" r="7" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}
