import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import {
  Card,
  Empty,
  ErrorMessage,
  PageTitle,
  SectionTitle,
  Spinner,
  StatusBadge,
} from "../components/ui";
import { useRunEvents } from "../hooks/useRunEvents";

export default function RunDetailPage() {
  const { projectID = "", runID = "" } = useParams();
  const qc = useQueryClient();
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
          <div>{run.started_at ? new Date(run.started_at).toLocaleString() : "—"}</div>
          <div className="text-slate-500 dark:text-slate-400">Finished</div>
          <div>{run.finished_at ? new Date(run.finished_at).toLocaleString() : "—"}</div>
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
                <tr key={tx.id}>
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

      <SectionTitle>Live event feed</SectionTitle>
      <Card>
        {events.length === 0 ? (
          <Empty>No events yet. Connected; waiting for activity.</Empty>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800 max-h-96 overflow-y-auto">
            {events
              .slice()
              .reverse()
              .map((e, i) => (
                <li key={`${e.ts}-${i}`} className="px-4 py-2 text-xs">
                  <span className="font-mono text-slate-500 dark:text-slate-400">
                    {new Date(e.ts).toLocaleTimeString()}
                  </span>{" "}
                  <span className="font-medium">{e.kind}</span>{" "}
                  <span className="text-slate-600 dark:text-slate-300">
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
