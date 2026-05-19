import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import type { Phase } from "../../api/types";
import {
  Button,
  Card,
  Empty,
  ErrorMessage,
  Input,
  SectionTitle,
  Select,
  Spinner,
  StatusBadge,
} from "../../components/ui";

const PHASES: Phase[] = [
  "scope",
  "osint",
  "asset_discovery",
  "validation",
  "exposure",
  "enrichment",
  "review",
  "reporting",
];

export default function RunsTab({ projectID }: { projectID: string }) {
  const qc = useQueryClient();
  const runsQ = useQuery({
    queryKey: ["runs", projectID],
    queryFn: () => api.listRuns(projectID),
  });

  const [phase, setPhase] = useState<Phase>("osint");
  const [label, setLabel] = useState("");
  const [tools, setTools] = useState("");

  const create = useMutation({
    mutationFn: () =>
      api.createRun(projectID, {
        phase,
        label: label || undefined,
        tools: parseTools(tools),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["runs", projectID] });
      setLabel("");
      setTools("");
    },
  });

  function onAdd(e: FormEvent) {
    e.preventDefault();
    create.mutate();
  }

  return (
    <div className="space-y-6">
      <Card className="p-4">
        <SectionTitle>New run</SectionTitle>
        <form onSubmit={onAdd} className="grid grid-cols-[180px_1fr_auto] gap-3 items-end">
          <label className="block">
            <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">Phase</span>
            <Select value={phase} onChange={(e) => setPhase(e.target.value as Phase)} className="w-full">
              {PHASES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </Select>
          </label>
          <label className="block">
            <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">
              Label (optional)
            </span>
            <Input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Initial sweep"
              className="w-full"
            />
          </label>
          <Button type="submit" disabled={create.isPending}>
            {create.isPending ? "Starting..." : "Start"}
          </Button>
          <label className="col-span-3 block">
            <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">
              Tools (comma-separated, optional). Leave empty for a metadata-only run.
            </span>
            <Input
              value={tools}
              onChange={(e) => setTools(e.target.value)}
              placeholder="crtsh, theharvester"
              className="w-full"
            />
          </label>
        </form>
        {create.error && <ErrorMessage>{(create.error as Error).message}</ErrorMessage>}
      </Card>

      <div>
        <SectionTitle>History</SectionTitle>
        {runsQ.isLoading && <Spinner />}
        {runsQ.isError && <ErrorMessage>{(runsQ.error as Error).message}</ErrorMessage>}
        {runsQ.data && runsQ.data.length === 0 && (
          <Empty>No runs yet.</Empty>
        )}
        {runsQ.data && runsQ.data.length > 0 && (
          <Card>
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="px-4 py-2">Phase</th>
                  <th className="px-4 py-2">Status</th>
                  <th className="px-4 py-2">Label</th>
                  <th className="px-4 py-2">Started</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {runsQ.data.map((r) => (
                  <tr key={r.id}>
                    <td className="px-4 py-2">{r.phase}</td>
                    <td className="px-4 py-2">
                      <StatusBadge value={r.status} />
                    </td>
                    <td className="px-4 py-2">
                      <Link
                        to={`/projects/${projectID}/runs/${r.id}`}
                        className="text-blue-600 dark:text-blue-400 hover:underline"
                      >
                        {r.label || r.id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="px-4 py-2 text-slate-500 dark:text-slate-400 text-xs">
                      {r.started_at ? new Date(r.started_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}
      </div>
    </div>
  );
}

function parseTools(raw: string) {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((tool) => ({ tool }));
}
