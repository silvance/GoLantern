import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import {
  Card,
  Empty,
  ErrorMessage,
  Input,
  SectionTitle,
  Spinner,
} from "../../components/ui";

export default function EntitiesTab({ projectID }: { projectID: string }) {
  const q = useQuery({
    queryKey: ["report", projectID],
    queryFn: () => api.reportJSON(projectID),
  });
  const [filter, setFilter] = useState("");
  const [openEntity, setOpenEntity] = useState<string | null>(null);

  const lcFilter = filter.toLowerCase();
  const filtered = useMemo(() => {
    if (!q.data) return {};
    if (!lcFilter) return q.data.entities_by_kind;
    const out: typeof q.data.entities_by_kind = {};
    for (const [kind, list] of Object.entries(q.data.entities_by_kind)) {
      const matched = list.filter((e) =>
        e.value.toLowerCase().includes(lcFilter),
      );
      if (matched.length > 0) out[kind] = matched;
    }
    return out;
  }, [q.data, lcFilter]);

  if (q.isLoading) return <Spinner />;
  if (q.isError) return <ErrorMessage>{(q.error as Error).message}</ErrorMessage>;
  if (!q.data) return null;

  const kinds = Object.keys(filtered).sort();
  const anyEntities = kinds.some((k) => filtered[k].length > 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter entity values..."
          className="w-72"
        />
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {filter ? `filtered: ${kinds.length} kinds` : `${kinds.length} kinds total`}
        </span>
      </div>

      {!anyEntities && (
        <Empty>
          {filter ? "No entities match that filter." : "No entities yet. Run a collector to discover some."}
        </Empty>
      )}

      {kinds.map((kind) => {
        const items = filtered[kind];
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
                {items.map((e) => {
                  const hasAttrs = e.attributes && Object.keys(e.attributes).length > 0;
                  const isOpen = openEntity === e.id;
                  return (
                    <li key={e.id} className="px-4 py-2 text-sm">
                      <button
                        type="button"
                        onClick={() => setOpenEntity(isOpen ? null : e.id)}
                        className="font-mono break-all text-left w-full hover:text-blue-600 dark:hover:text-blue-400"
                        disabled={!hasAttrs}
                      >
                        {hasAttrs && (
                          <span className="text-slate-400 text-xs mr-1">
                            {isOpen ? "▾" : "▸"}
                          </span>
                        )}
                        {e.value}
                      </button>
                      {isOpen && hasAttrs && (
                        <pre className="mt-2 bg-slate-50 dark:bg-slate-800 p-2 rounded text-[11px] overflow-x-auto whitespace-pre-wrap">
                          {JSON.stringify(e.attributes, null, 2)}
                        </pre>
                      )}
                    </li>
                  );
                })}
              </ul>
            </Card>
          </div>
        );
      })}
    </div>
  );
}
