import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Button, Card, Empty, ErrorMessage, PageTitle, Spinner } from "../components/ui";

export default function ProjectsPage() {
  const q = useQuery({ queryKey: ["projects"], queryFn: api.listProjects });

  return (
    <div>
      <PageTitle
        actions={
          <Link to="/projects/new">
            <Button>New project</Button>
          </Link>
        }
      >
        Projects
      </PageTitle>

      {q.isLoading && <Spinner />}
      {q.isError && <ErrorMessage>{(q.error as Error).message}</ErrorMessage>}
      {q.data && q.data.length === 0 && (
        <Empty>
          No projects yet. Create one to get started.
        </Empty>
      )}

      {q.data && q.data.length > 0 && (
        <Card>
          <ul className="divide-y divide-slate-200 dark:divide-slate-800">
            {q.data.map((p) => (
              <li key={p.id}>
                <Link
                  to={`/projects/${p.id}`}
                  className="block px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50"
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">{p.name}</div>
                      {p.organization && (
                        <div className="text-sm text-slate-500 dark:text-slate-400">
                          {p.organization}
                        </div>
                      )}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 flex gap-3">
                      <span>mode: {p.mode}</span>
                      <span>scope: {p.default_scope}</span>
                    </div>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
