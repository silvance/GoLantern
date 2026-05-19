import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import {
  Card,
  ErrorMessage,
  PageTitle,
  SectionTitle,
  Spinner,
} from "../components/ui";

export default function AboutPage() {
  const q = useQuery({ queryKey: ["info"], queryFn: api.info });

  if (q.isLoading) return <Spinner />;
  if (q.isError) return <ErrorMessage>{(q.error as Error).message}</ErrorMessage>;
  if (!q.data) return null;

  const f = q.data.features;

  return (
    <div>
      <PageTitle>About this server</PageTitle>
      <div className="grid sm:grid-cols-2 gap-4">
        <Card className="p-4">
          <SectionTitle>Runtime</SectionTitle>
          <dl className="grid grid-cols-[140px_1fr] gap-2 text-sm">
            <dt className="text-slate-500 dark:text-slate-400">Go version</dt>
            <dd className="font-mono">{q.data.go_version}</dd>
            <dt className="text-slate-500 dark:text-slate-400">Server time</dt>
            <dd>{new Date(q.data.server_time).toLocaleString()}</dd>
            <dt className="text-slate-500 dark:text-slate-400">Collectors</dt>
            <dd>{q.data.collector_count} registered</dd>
          </dl>
        </Card>
        <Card className="p-4">
          <SectionTitle>Features</SectionTitle>
          <ul className="text-sm space-y-1">
            <Feature on={f.assistant} label="LLM assistant" />
            <Feature on={f.artifacts} label="Artifact storage" />
            <Feature on={f.event_bus} label="Event bus (SSE)" />
            <Feature on={f.enqueue} label="Background queue" />
            <Feature on={f.entity_report} label="Entity / finding report" />
            <Feature on={f.webui} label="Web UI (this SPA)" />
          </ul>
        </Card>
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-400 mt-6">
        Pressing <kbd className="px-1 py-0.5 border border-slate-300 dark:border-slate-700 rounded text-[10px]">/</kbd>{" "}
        anywhere on the Projects page focuses the search input.
      </p>
    </div>
  );
}

function Feature({ on, label }: { on: boolean; label: string }) {
  return (
    <li className="flex items-center gap-2">
      <span
        className={
          on
            ? "inline-block w-2 h-2 rounded-full bg-emerald-500"
            : "inline-block w-2 h-2 rounded-full bg-slate-400"
        }
      />
      <span>{label}</span>
      <span className="text-xs text-slate-500 dark:text-slate-400">
        {on ? "on" : "off"}
      </span>
    </li>
  );
}
