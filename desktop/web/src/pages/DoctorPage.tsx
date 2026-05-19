import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type { DoctorEntry } from "../api/types";
import {
  Card,
  ErrorMessage,
  PageTitle,
  SectionTitle,
  Spinner,
} from "../components/ui";

export default function DoctorPage() {
  const q = useQuery({ queryKey: ["doctor"], queryFn: api.doctor, retry: false });

  if (q.isLoading) return <Spinner />;
  if (q.isError) {
    const err = q.error as Error;
    if (err instanceof ApiError && err.status === 501) {
      return (
        <div>
          <PageTitle>Doctor</PageTitle>
          <Card className="p-4">
            <p className="text-sm text-slate-600 dark:text-slate-300">
              The collector registry isn't wired into this server's API
              handler. The doctor view needs it to probe binaries on
              PATH.
            </p>
          </Card>
        </div>
      );
    }
    return <ErrorMessage>{err.message}</ErrorMessage>;
  }
  if (!q.data) return null;

  const ok = q.data.filter((e) => e.status === "ok");
  const missing = q.data.filter((e) => e.status === "missing");
  const noBinary = q.data.filter((e) => e.status === "no_binary");

  return (
    <div>
      <PageTitle>Doctor</PageTitle>
      <p className="text-sm text-slate-600 dark:text-slate-300 mb-4">
        Probes PATH for every collector's external binary. Collectors
        with <code>missing</code> here will fail at runtime; install
        the binary or remove the collector from your run.
      </p>

      <div className="grid grid-cols-3 gap-3 mb-6">
        <Stat label="OK on PATH" value={ok.length} kind="ok" />
        <Stat label="Missing" value={missing.length} kind="missing" />
        <Stat label="No binary needed" value={noBinary.length} kind="info" />
      </div>

      {missing.length > 0 && (
        <Section title="Missing binaries">
          {missing.map((e) => (
            <DoctorRow key={e.name} entry={e} />
          ))}
        </Section>
      )}
      <Section title="Installed">
        {ok.map((e) => (
          <DoctorRow key={e.name} entry={e} />
        ))}
      </Section>
      {noBinary.length > 0 && (
        <Section title="Pure-Go collectors (no external binary)">
          {noBinary.map((e) => (
            <DoctorRow key={e.name} entry={e} />
          ))}
        </Section>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  kind,
}: {
  label: string;
  value: number;
  kind: "ok" | "missing" | "info";
}) {
  const colors = {
    ok: "border-emerald-300 bg-emerald-50 dark:bg-emerald-950/30 dark:border-emerald-800",
    missing: "border-red-300 bg-red-50 dark:bg-red-950/30 dark:border-red-800",
    info: "border-slate-200 bg-slate-50 dark:bg-slate-900 dark:border-slate-800",
  };
  return (
    <div className={`border rounded-md p-4 ${colors[kind]}`}>
      <div className="text-2xl font-semibold">{value}</div>
      <div className="text-xs text-slate-600 dark:text-slate-300">{label}</div>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mb-6">
      <SectionTitle>{title}</SectionTitle>
      <Card>
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {children}
        </ul>
      </Card>
    </div>
  );
}

function DoctorRow({ entry }: { entry: DoctorEntry }) {
  return (
    <li className="px-4 py-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-mono text-sm font-medium">{entry.name}</span>
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {entry.phase}
        </span>
        {entry.status === "ok" && (
          <span className="text-xs text-emerald-700 dark:text-emerald-400">
            → <code>{entry.path}</code>
          </span>
        )}
        {entry.status === "missing" && (
          <span className="text-xs text-red-700 dark:text-red-400">
            binary <code>{entry.binary}</code> not on PATH
          </span>
        )}
      </div>
      {entry.install_hint && entry.status === "missing" && (
        <details className="mt-2">
          <summary className="text-xs text-slate-500 dark:text-slate-400 cursor-pointer">
            Install hint
          </summary>
          <pre className="mt-2 bg-slate-50 dark:bg-slate-800 p-2 rounded text-[11px] overflow-x-auto whitespace-pre-wrap">
            {entry.install_hint}
          </pre>
        </details>
      )}
    </li>
  );
}
