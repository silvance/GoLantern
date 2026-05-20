import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import {
  Button,
  Card,
  Empty,
  ErrorMessage,
  FolderIcon,
  Input,
  PageTitle,
  Select,
  Spinner,
} from "../components/ui";
import type { Mode, Project } from "../api/types";

type SortKey = "name" | "mode";

export default function ProjectsPage() {
  const q = useQuery({ queryKey: ["projects"], queryFn: api.listProjects });
  const [filter, setFilter] = useState("");
  const [modeFilter, setModeFilter] = useState<Mode | "all">("all");
  const [sort, setSort] = useState<SortKey>("name");
  const searchRef = useRef<HTMLInputElement>(null);

  // "/" focuses the search box, unless the user is already typing in
  // an input. Standard pattern for search-driven analyst tools.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== "/") return;
      const t = e.target as HTMLElement | null;
      if (
        t &&
        (t.tagName === "INPUT" ||
          t.tagName === "TEXTAREA" ||
          (t as HTMLElement).isContentEditable)
      ) {
        return;
      }
      e.preventDefault();
      searchRef.current?.focus();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const filtered = useMemo(() => {
    const lc = filter.toLowerCase();
    const list = (q.data ?? []).filter((p: Project) => {
      if (modeFilter !== "all" && p.mode !== modeFilter) return false;
      if (!lc) return true;
      return (
        p.name.toLowerCase().includes(lc) ||
        (p.organization ?? "").toLowerCase().includes(lc) ||
        (p.description ?? "").toLowerCase().includes(lc)
      );
    });
    list.sort((a, b) => {
      if (sort === "name") return a.name.localeCompare(b.name);
      return a.mode.localeCompare(b.mode) || a.name.localeCompare(b.name);
    });
    return list;
  }, [q.data, filter, modeFilter, sort]);

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
        <Empty
          icon={<FolderIcon size={40} />}
          action={
            <Link to="/projects/new">
              <Button>Create your first project</Button>
            </Link>
          }
        >
          No projects yet. Projects group scope, runs, findings, and reports
          for one engagement.
        </Empty>
      )}

      {q.data && q.data.length > 0 && (
        <>
          <div className="flex flex-wrap gap-3 mb-4">
            <Input
              ref={searchRef}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter — press / to focus"
              className="w-72"
            />
            <Select
              value={modeFilter}
              onChange={(e) => setModeFilter(e.target.value as Mode | "all")}
            >
              <option value="all">All modes</option>
              <option value="assessment">Assessment</option>
              <option value="bug_bounty">Bug Bounty</option>
              <option value="ctf">CTF</option>
            </Select>
            <Select value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
              <option value="name">Sort: name</option>
              <option value="mode">Sort: mode then name</option>
            </Select>
            <span className="text-xs text-slate-500 dark:text-slate-400 self-center">
              {filtered.length} of {q.data.length}
            </span>
          </div>

          {filtered.length === 0 && <Empty>No projects match your filter.</Empty>}

          {filtered.length > 0 && (
            <Card>
              <ul className="divide-y divide-slate-200 dark:divide-slate-800">
                {filtered.map((p) => (
                  <li key={p.id}>
                    <Link
                      to={`/projects/${p.id}`}
                      className="block px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="font-medium truncate">{p.name}</div>
                          {p.organization && (
                            <div className="text-sm text-slate-500 dark:text-slate-400 truncate">
                              {p.organization}
                            </div>
                          )}
                        </div>
                        <div className="text-xs text-slate-500 dark:text-slate-400 flex gap-3 shrink-0">
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
        </>
      )}
    </div>
  );
}
