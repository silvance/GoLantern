import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { Phase, RunStatus, ToolInvocation } from "../../api/types";
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
import { ToolPicker } from "../../components/ToolPicker";

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
  const nav = useNavigate();
  const runsQ = useQuery({
    queryKey: ["runs", projectID],
    queryFn: () => api.listRuns(projectID),
    // Poll while any run is in flight so the row's status badge
    // updates without a manual reload. Stops polling once everything
    // is in a terminal state.
    refetchInterval: (q) => {
      const list = q.state.data ?? [];
      const anyInFlight = list.some(
        (r) => r.status === "pending" || r.status === "running",
      );
      return anyInFlight ? 2_500 : false;
    },
  });
  const [statusFilter, setStatusFilter] = useState<RunStatus | "all">("all");

  const filteredRuns = useMemo(() => {
    if (!runsQ.data) return [];
    if (statusFilter === "all") return runsQ.data;
    return runsQ.data.filter((r) => r.status === statusFilter);
  }, [runsQ.data, statusFilter]);

  const [phase, setPhase] = useState<Phase>("osint");
  const [label, setLabel] = useState("");
  const [tools, setTools] = useState<ToolInvocation[]>([]);

  // Recommended-tools query keyed off the chosen phase. The picker
  // auto-selects on first mount with a non-empty list.
  const recQ = useQuery({
    queryKey: ["recommended-tools", projectID, phase],
    queryFn: () => api.recommendedTools(projectID, phase),
  });

  const create = useMutation({
    mutationFn: () =>
      api.createRun(projectID, {
        phase,
        label: label || undefined,
        tools,
      }),
    onSuccess: (run) => {
      qc.invalidateQueries({ queryKey: ["runs", projectID] });
      setLabel("");
      setTools([]);
      // If the run dispatched any collectors, jump straight to the
      // run detail page so the operator can watch the SSE feed.
      // Metadata-only runs (no tools) stay on the list.
      if (tools.length > 0) {
        nav(`/projects/${projectID}/runs/${run.id}`);
      }
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
        <form onSubmit={onAdd} className="space-y-4">
          <div className="grid grid-cols-[180px_1fr] gap-3">
            <label className="block">
              <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">Phase</span>
              <Select
                value={phase}
                onChange={(e) => {
                  setPhase(e.target.value as Phase);
                  // Reset selection when phase changes; the picker
                  // auto-selects the new phase's recommended tools.
                  setTools([]);
                }}
                className="w-full"
              >
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
          </div>

          <div>
            <div className="text-xs text-slate-500 dark:text-slate-400 mb-2">
              Tools for {phase} ({tools.length} selected)
            </div>
            <ToolPicker
              phase={phase}
              value={tools}
              onChange={setTools}
              recommended={recQ.data?.tools ?? []}
            />
          </div>

          {create.error && <ErrorMessage>{(create.error as Error).message}</ErrorMessage>}

          <div className="flex gap-2">
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "Starting..." : "Start run"}
            </Button>
            <span className="text-xs text-slate-500 dark:text-slate-400 self-center">
              {tools.length === 0
                ? "Metadata-only run — no collectors will dispatch."
                : `${tools.length} collector${tools.length === 1 ? "" : "s"} will dispatch.`}
            </span>
          </div>
        </form>
      </Card>

      <div>
        <SectionTitle
          actions={
            <Select
              value={statusFilter}
              onChange={(e) =>
                setStatusFilter(e.target.value as RunStatus | "all")
              }
            >
              <option value="all">All statuses</option>
              <option value="running">Running</option>
              <option value="pending">Pending</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </Select>
          }
        >
          History
        </SectionTitle>
        {runsQ.isLoading && <Spinner />}
        {runsQ.isError && <ErrorMessage>{(runsQ.error as Error).message}</ErrorMessage>}
        {runsQ.data && runsQ.data.length === 0 && <Empty>No runs yet.</Empty>}
        {runsQ.data && runsQ.data.length > 0 && filteredRuns.length === 0 && (
          <Empty>No runs match this status filter.</Empty>
        )}
        {filteredRuns.length > 0 && (
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
                {filteredRuns.map((r) => (
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
