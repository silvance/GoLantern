// Toast notifications confirm mutations that would otherwise complete
// silently — deletes, cancels, copy-to-clipboard. Slides in from the
// bottom-right and auto-dismisses. Mounted once at the app root via
// ToastProvider; pages call useToast() to push messages.

import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";

type ToastKind = "success" | "error" | "info";
type Toast = { id: number; kind: ToastKind; message: string };

type Push = (kind: ToastKind, message: string) => void;
const ToastCtx = createContext<Push | null>(null);

const TOAST_TTL_MS = 3500;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const push = useCallback<Push>((kind, message) => {
    const id = nextId.current++;
    setToasts((prev) => [...prev, { id, kind, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, TOAST_TTL_MS);
  }, []);

  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div
        aria-live="polite"
        aria-atomic="true"
        className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm pointer-events-none"
      >
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} />
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

function ToastItem({ toast }: { toast: Toast }) {
  const [show, setShow] = useState(false);
  useEffect(() => {
    // One frame later so the transition runs.
    const id = requestAnimationFrame(() => setShow(true));
    return () => cancelAnimationFrame(id);
  }, []);
  const palette: Record<ToastKind, string> = {
    success:
      "bg-emerald-50 dark:bg-emerald-900/60 border-emerald-200 dark:border-emerald-800 text-emerald-900 dark:text-emerald-100",
    error:
      "bg-red-50 dark:bg-red-900/60 border-red-200 dark:border-red-800 text-red-900 dark:text-red-100",
    info: "bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100",
  };
  return (
    <div
      role="status"
      className={`pointer-events-auto px-4 py-2 rounded-md shadow-lg border text-sm flex items-start gap-2 transition-all duration-200 ${
        palette[toast.kind]
      } ${show ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2"}`}
    >
      <span aria-hidden className="mt-0.5 shrink-0">
        {toast.kind === "success" && (
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12" />
          </svg>
        )}
        {toast.kind === "error" && (
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        )}
        {toast.kind === "info" && (
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="16" x2="12" y2="12" />
            <line x1="12" y1="8" x2="12.01" y2="8" />
          </svg>
        )}
      </span>
      <span>{toast.message}</span>
    </div>
  );
}

export function useToast(): Push {
  const ctx = useContext(ToastCtx);
  if (!ctx) {
    throw new Error("useToast must be used inside <ToastProvider>");
  }
  return ctx;
}
