import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import {
  Button,
  Card,
  Empty,
  ErrorMessage,
  Input,
  PageTitle,
  SectionTitle,
  Spinner,
} from "../components/ui";
import OverviewTab from "./tabs/OverviewTab";
import ScopeTab from "./tabs/ScopeTab";
import RunsTab from "./tabs/RunsTab";
import FindingsTab from "./tabs/FindingsTab";
import EntitiesTab from "./tabs/EntitiesTab";
import ArtifactsTab from "./tabs/ArtifactsTab";

type TabKey =
  | "overview"
  | "scope"
  | "runs"
  | "findings"
  | "entities"
  | "artifacts";

const TABS: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "scope", label: "Scope" },
  { key: "runs", label: "Runs" },
  { key: "findings", label: "Findings" },
  { key: "entities", label: "Entities" },
  { key: "artifacts", label: "Artifacts" },
];

export default function ProjectDetailPage() {
  const { projectID = "" } = useParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const [tab, setTab] = useState<TabKey>("overview");
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const q = useQuery({
    queryKey: ["project", projectID],
    queryFn: () => api.getProject(projectID),
    enabled: !!projectID,
  });

  const del = useMutation({
    mutationFn: () => api.deleteProject(projectID),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects"] });
      nav("/");
    },
  });

  if (q.isLoading) return <Spinner />;
  if (q.isError)
    return <ErrorMessage>{(q.error as Error).message}</ErrorMessage>;
  if (!q.data) return null;

  const p = q.data;

  return (
    <div>
      <PageTitle
        actions={
          confirmingDelete ? (
            <>
              <Button variant="danger" onClick={() => del.mutate()} disabled={del.isPending}>
                {del.isPending ? "Deleting..." : "Confirm delete"}
              </Button>
              <Button variant="ghost" onClick={() => setConfirmingDelete(false)}>
                Cancel
              </Button>
            </>
          ) : (
            <Button variant="danger" onClick={() => setConfirmingDelete(true)}>
              Delete project
            </Button>
          )
        }
      >
        {p.name}
      </PageTitle>
      {p.organization && (
        <p className="text-sm text-slate-500 dark:text-slate-400 -mt-4 mb-6">
          {p.organization}
        </p>
      )}

      <div className="border-b border-slate-200 dark:border-slate-800 mb-6">
        <nav className="flex gap-1 -mb-px">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={
                tab === t.key
                  ? "px-4 py-2 text-sm font-medium border-b-2 border-blue-600 text-blue-600 dark:text-blue-400"
                  : "px-4 py-2 text-sm text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white border-b-2 border-transparent"
              }
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      {tab === "overview" && <OverviewTab project={p} />}
      {tab === "scope" && <ScopeTab projectID={projectID} />}
      {tab === "runs" && <RunsTab projectID={projectID} />}
      {tab === "findings" && <FindingsTab projectID={projectID} />}
      {tab === "entities" && <EntitiesTab projectID={projectID} />}
      {tab === "artifacts" && <ArtifactsTab projectID={projectID} />}
    </div>
  );
}

// Convenience re-exports used by tab components (kept here so tab files
// don't all need to reach back up to ../components/ui).
export { Button, Card, Empty, ErrorMessage, Input, SectionTitle, Spinner };
