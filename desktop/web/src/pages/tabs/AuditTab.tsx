import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import {
  Card,
  Empty,
  ErrorMessage,
  SectionTitle,
  Spinner,
} from "../../components/ui";

export default function AuditTab({ projectID }: { projectID: string }) {
  const q = useQuery({
    queryKey: ["audit-logs", projectID],
    queryFn: () => api.listAuditLogs(projectID),
  });

  return (
    <div>
      <SectionTitle>Audit log</SectionTitle>
      {q.isLoading && <Spinner />}
      {q.isError && <ErrorMessage>{(q.error as Error).message}</ErrorMessage>}
      {q.data && q.data.length === 0 && (
        <Empty>No audit entries yet.</Empty>
      )}
      {q.data && q.data.length > 0 && (
        <Card>
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">
              <tr>
                <th className="px-4 py-2">When</th>
                <th className="px-4 py-2">Actor</th>
                <th className="px-4 py-2">Action</th>
                <th className="px-4 py-2">Target</th>
                <th className="px-4 py-2">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {q.data.map((e) => (
                <tr key={e.id}>
                  <td className="px-4 py-2 text-xs whitespace-nowrap">
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2 text-xs">{e.actor}</td>
                  <td className="px-4 py-2 text-xs font-mono">{e.action}</td>
                  <td className="px-4 py-2 text-xs">{e.target || "—"}</td>
                  <td className="px-4 py-2 text-xs">
                    {e.detail && Object.keys(e.detail).length > 0 ? (
                      <details>
                        <summary className="cursor-pointer text-slate-500 dark:text-slate-400">
                          {Object.keys(e.detail).length} field
                          {Object.keys(e.detail).length === 1 ? "" : "s"}
                        </summary>
                        <pre className="mt-2 bg-slate-50 dark:bg-slate-800 p-2 rounded text-[11px] overflow-x-auto">
                          {JSON.stringify(e.detail, null, 2)}
                        </pre>
                      </details>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
