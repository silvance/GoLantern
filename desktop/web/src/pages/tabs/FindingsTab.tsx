import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { Severity } from "../../api/types";
import {
  Card,
  Empty,
  ErrorMessage,
  SectionTitle,
  Select,
  SeverityBadge,
  Spinner,
} from "../../components/ui";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function FindingsTab({ projectID }: { projectID: string }) {
  const q = useQuery({
    queryKey: ["report", projectID],
    queryFn: () => api.reportJSON(projectID),
  });
  const [minSeverity, setMinSeverity] = useState<Severity | "all">("all");

  const filtered = useMemo(() => {
    if (!q.data) return [];
    if (minSeverity === "all") return q.data.findings;
    const cutoff = SEVERITIES.indexOf(minSeverity);
    return q.data.findings.filter(
      (f) => SEVERITIES.indexOf(f.severity) <= cutoff,
    );
  }, [q.data, minSeverity]);

  return (
    <div>
      <SectionTitle
        actions={
          <Select
            value={minSeverity}
            onChange={(e) => setMinSeverity(e.target.value as Severity | "all")}
          >
            <option value="all">All severities</option>
            <option value="critical">Critical only</option>
            <option value="high">High &amp; up</option>
            <option value="medium">Medium &amp; up</option>
            <option value="low">Low &amp; up</option>
          </Select>
        }
      >
        Findings
      </SectionTitle>
      {q.isLoading && <Spinner />}
      {q.isError && <ErrorMessage>{(q.error as Error).message}</ErrorMessage>}
      {q.data && filtered.length === 0 && <Empty>No findings match this filter.</Empty>}
      {filtered.length > 0 && (
        <div className="space-y-3">
          {filtered.map((f) => (
            <Card key={f.id} className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge value={f.severity} />
                    {f.category && (
                      <span className="text-xs text-slate-500 dark:text-slate-400">
                        {f.category}
                      </span>
                    )}
                  </div>
                  <h3 className="font-medium">{f.title}</h3>
                  {f.description && (
                    <p className="text-sm text-slate-600 dark:text-slate-300 mt-2 whitespace-pre-wrap">
                      {f.description}
                    </p>
                  )}
                  {f.recommendation && (
                    <p className="text-sm mt-2 border-l-2 border-blue-400 dark:border-blue-600 pl-3 text-slate-700 dark:text-slate-200">
                      <span className="font-medium">Recommendation: </span>
                      {f.recommendation}
                    </p>
                  )}
                  {f.evidence && f.evidence.length > 0 && (
                    <details className="mt-3">
                      <summary className="text-xs text-slate-500 dark:text-slate-400 cursor-pointer">
                        {f.evidence.length} evidence row
                        {f.evidence.length === 1 ? "" : "s"}
                      </summary>
                      <ul className="mt-2 space-y-2">
                        {f.evidence.map((ev) => (
                          <li
                            key={ev.id}
                            className="bg-slate-50 dark:bg-slate-800 p-2 rounded text-xs"
                          >
                            <div className="flex flex-wrap items-center gap-x-3 text-slate-600 dark:text-slate-300">
                              <span>
                                <span className="font-medium">tool: </span>
                                <code>{ev.source_tool}</code>
                              </span>
                              <span>
                                <span className="font-medium">source: </span>
                                {ev.source_category}
                              </span>
                              <span>
                                <span className="font-medium">confidence: </span>
                                {ev.confidence}
                              </span>
                            </div>
                            {ev.notes && (
                              <div className="mt-1 text-slate-500 dark:text-slate-400">
                                {ev.notes}
                              </div>
                            )}
                            {ev.payload && Object.keys(ev.payload).length > 0 && (
                              <pre className="mt-1 text-[11px] overflow-x-auto whitespace-pre-wrap">
                                {JSON.stringify(ev.payload, null, 2)}
                              </pre>
                            )}
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                </div>
                <span className="text-xs text-slate-400 shrink-0">
                  confidence: {f.confidence}
                </span>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
