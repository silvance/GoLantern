import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { ToolInvocation } from "../api/types";
import {
  Button,
  Card,
  CopyButton,
  Empty,
  ErrorMessage,
  PageTitle,
  RelativeTime,
  SectionTitle,
  Spinner,
  StatusBadge,
} from "../components/ui";
import { useRunEvents } from "../hooks/useRunEvents";
import { useToast } from "../components/Toast";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export default function RunDetailPage() {
  const { projectID = "", runID = "" } = useParams();
  const qc = useQueryClient();
  const nav = useNavigate();
  const toast = useToast();
  const runQ = useQuery({
    queryKey: ["run", runID],
    queryFn: () => api.getRun(runID),
    enabled: !!runID,
    // While the run is in-flight we poll for status changes. SSE
    // carries the per-tool events; this poll catches the run.status
    // transition that completes the run as a whole.
    refetchInterval: (q) => {
      const data = q.state.data;
      if (data && (data.status === "running" || data.status === "pending")) {
        return 2_000;
      }
      return false;
    },
  });

  const txsQ = useQuery({
    queryKey: ["tool-executions", runID],
    queryFn: () => api.listToolExecutions(runID),
    enabled: !!runID,
    refetchInterval: (q) => {
      const runData = runQ.data;
      if (runData && (runData.status === "running" || runData.status === "pending")) {
        return 2_000;
      }
      // One last poll when the run finishes so the final
      // tool-execution row is fresh.
      return q.state.data && q.state.data.some((tx) => tx.status === "running")
        ? 1_500
        : false;
    },
  });

  const { events, status: sseStatus } = useRunEvents(runID);

  // Cancel: flip the row to cancelled. Cooperative — the engine
  // checks the row between dispatches; in-flight collectors finish
  // naturally. The button shows for pending/running runs only.
  const cancel = useMutation({
    mutationFn: () => api.cancelRun(runID),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["run", runID] });
      qc.invalidateQueries({ queryKey: ["runs", projectID] });
      toast("info", "Run cancelled — in-flight collectors will finish");
    },
    onError: (e: Error) => toast("error", `Cancel failed: ${e.message}`),
  });

  // Re-run: POST a new run with the same phase + tool list this run
  // dispatched. Built from the tool_executions we already loaded so
  // we don't have to round-trip the original Run.parameters JSON.
  const rerun = useMutation({
    mutationFn: () => {
      const tools: ToolInvocation[] = (txsQ.data ?? []).map((tx) => ({
        tool: tx.tool,
        parameters: tx.parameters,
      }));
      return api.createRun(projectID, {
        phase: runQ.data!.phase,
        label: runQ.data!.label ? `${runQ.data!.label} (rerun)` : undefined,
        tools,
      });
    },
    onSuccess: (newRun) => {
      qc.invalidateQueries({ queryKey: ["runs", projectID] });
      toast("success", "New run started");
      nav(`/projects/${projectID}/runs/${newRun.id}`);
    },
    onError: (e: Error) => toast("error", `Could not re-run: ${e.message}`),
  });

  // When a tool finishes (or emits anything report-shaped), invalidate
  // the project-level caches so the user's other tabs come back to
  // life when they switch back. Throttling: we only invalidate on
  // tool.finished, not on every entity/finding emit, because the
  // tabs aren't visible during a run anyway and TanStack Query will
  // re-fetch when the user navigates.
  const lastEvent = events[events.length - 1];
  useEffect(() => {
    if (!lastEvent) return;
    if (
      lastEvent.kind === "tool.finished" ||
      lastEvent.kind === "tool.started"
    ) {
      qc.invalidateQueries({ queryKey: ["tool-executions", runID] });
      qc.invalidateQueries({ queryKey: ["run", runID] });
    }
    if (lastEvent.kind === "tool.finished") {
      qc.invalidateQueries({ queryKey: ["report", projectID] });
      qc.invalidateQueries({ queryKey: ["artifacts", projectID] });
      qc.invalidateQueries({ queryKey: ["runs", projectID] });
    }
  }, [lastEvent, qc, projectID, runID]);

  useDocumentTitle(
    runQ.data ? runQ.data.label || `Run ${runQ.data.id.slice(0, 8)}` : null,
  );

  if (runQ.isLoading) return <Spinner />;
  if (runQ.isError) return <ErrorMessage>{(runQ.error as Error).message}</ErrorMessage>;
  if (!runQ.data) return null;
  const run = runQ.data;

  return (
    <div>
      <Link
        to={`/projects/${projectID}`}
        className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
      >
        ← Back to project
      </Link>
      <PageTitle
        actions={
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <span
                className={`inline-block w-2 h-2 rounded-full ${
                  sseStatus === "live"
                    ? "bg-emerald-500 animate-pulse"
                    : sseStatus === "connecting"
                      ? "bg-amber-500"
                      : "bg-slate-400"
                }`}
              />
              events: {sseStatus}
            </span>
            {(run.status === "pending" || run.status === "running") && (
              <Button
                variant="danger"
                onClick={() => cancel.mutate()}
                disabled={cancel.isPending}
              >
                {cancel.isPending ? "Cancelling..." : "Cancel run"}
              </Button>
            )}
            {(run.status === "completed" ||
              run.status === "failed" ||
              run.status === "cancelled") &&
              (txsQ.data?.length ?? 0) > 0 && (
                <Button
                  variant="secondary"
                  onClick={() => rerun.mutate()}
                  disabled={rerun.isPending}
                >
                  {rerun.isPending ? "Starting..." : "Run again"}
                </Button>
              )}
          </div>
        }
      >
        {run.label || `Run ${run.id.slice(0, 8)}`}
      </PageTitle>

      <Card className="p-4 mb-6">
        <div className="grid grid-cols-[120px_1fr] gap-2 text-sm">
          <div className="text-slate-500 dark:text-slate-400">Status</div>
          <div>
            <StatusBadge value={run.status} />
          </div>
          <div className="text-slate-500 dark:text-slate-400">Phase</div>
          <div>{run.phase}</div>
          <div className="text-slate-500 dark:text-slate-400">Started</div>
          <div><RelativeTime iso={run.started_at} /></div>
          <div className="text-slate-500 dark:text-slate-400">Finished</div>
          <div><RelativeTime iso={run.finished_at} /></div>
          <div className="text-slate-500 dark:text-slate-400">Run ID</div>
          <div className="flex items-center gap-1.5">
            <code className="text-xs">{run.id}</code>
            <CopyButton value={run.id} label="Copy run ID" />
          </div>
          {run.error_summary && (
            <>
              <div className="text-slate-500 dark:text-slate-400">Error</div>
              <div className="text-red-700 dark:text-red-400 whitespace-pre-wrap">
                {run.error_summary}
              </div>
            </>
          )}
        </div>
      </Card>

      <SectionTitle>Tool executions</SectionTitle>
      {txsQ.isLoading && <Spinner />}
      {txsQ.data && txsQ.data.length === 0 && (
        <Empty>No tools dispatched on this run.</Empty>
      )}
      {txsQ.data && txsQ.data.length > 0 && (
        <Card className="mb-6">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">
              <tr>
                <th className="px-4 py-2">Tool</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Entities</th>
                <th className="px-4 py-2">Evidence</th>
                <th className="px-4 py-2">Findings</th>
                <th className="px-4 py-2">Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {txsQ.data.map((tx) => (
                <tr
                  key={tx.id}
                  className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                >
                  <td className="px-4 py-2 font-mono text-xs">{tx.tool}</td>
                  <td className="px-4 py-2"><StatusBadge value={tx.status} /></td>
                  <td className="px-4 py-2">{tx.entities_emitted}</td>
                  <td className="px-4 py-2">{tx.evidence_emitted}</td>
                  <td className="px-4 py-2">{tx.findings_emitted}</td>
                  <td className="px-4 py-2 text-xs text-slate-500 dark:text-slate-400 max-w-md truncate" title={tx.error_summary}>
                    {tx.error_summary || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <SectionTitle
        actions={
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {events.length} event{events.length === 1 ? "" : "s"}
          </span>
        }
      >
        Live event feed
      </SectionTitle>
      <Card>
        {events.length === 0 ? (
          <Empty>No events yet. Connected; waiting for activity.</Empty>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800 max-h-96 overflow-y-auto">
            {events
              .slice()
              .reverse()
              .map((e, i) => (
                <li key={`${e.ts}-${i}`} className="px-4 py-2 text-xs flex gap-2 items-baseline">
                  <span className="font-mono text-slate-400 shrink-0">
                    {new Date(e.ts).toLocaleTimeString()}
                  </span>
                  <span
                    className={`text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 ${eventColor(e.kind)}`}
                  >
                    {e.kind}
                  </span>
                  <span className="text-slate-600 dark:text-slate-300 truncate">
                    {summarizePayload(e.payload)}
                  </span>
                </li>
              ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function summarizePayload(p?: Record<string, unknown>) {
  if (!p) return "";
  const interesting = ["tool", "status", "title", "value", "kind"];
  const bits: string[] = [];
  for (const k of interesting) {
    if (k in p) bits.push(`${k}=${String(p[k])}`);
  }
  return bits.join(" ");
}

function eventColor(kind: string): string {
  switch (kind) {
    case "tool.started":
      return "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200";
    case "tool.finished":
      return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
    case "entity.emitted":
      return "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300";
    case "finding.emitted":
      return "bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-200";
    case "evidence.emitted":
      return "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300";
    case "relation.emitted":
      return "bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-200";
    default:
      return "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300";
  }
}
