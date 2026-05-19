import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import {
  Card,
  Empty,
  ErrorMessage,
  SectionTitle,
  Spinner,
} from "../../components/ui";

export default function EntitiesTab({ projectID }: { projectID: string }) {
  const q = useQuery({
    queryKey: ["report", projectID],
    queryFn: () => api.reportJSON(projectID),
  });

  if (q.isLoading) return <Spinner />;
  if (q.isError) return <ErrorMessage>{(q.error as Error).message}</ErrorMessage>;
  if (!q.data) return null;

  const kinds = Object.keys(q.data.entities_by_kind).sort();
  const anyEntities = kinds.some(
    (k) => q.data!.entities_by_kind[k].length > 0,
  );

  if (!anyEntities) return <Empty>No entities yet. Run a collector to discover some.</Empty>;

  return (
    <div className="space-y-6">
      {kinds.map((kind) => {
        const items = q.data!.entities_by_kind[kind];
        if (items.length === 0) return null;
        return (
          <div key={kind}>
            <SectionTitle>
              <span className="lowercase">{kind}</span>{" "}
              <span className="text-sm font-normal text-slate-500 dark:text-slate-400">
                ({items.length})
              </span>
            </SectionTitle>
            <Card>
              <ul className="divide-y divide-slate-100 dark:divide-slate-800 max-h-96 overflow-y-auto">
                {items.map((e) => (
                  <li
                    key={e.id}
                    className="px-4 py-2 text-sm font-mono break-all"
                  >
                    {e.value}
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        );
      })}
    </div>
  );
}
