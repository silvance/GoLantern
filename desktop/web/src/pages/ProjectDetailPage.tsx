import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import {
  Button,
  ErrorMessage,
  PageTitle,
  Spinner,
} from "../components/ui";
import { useToast } from "../components/Toast";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import OverviewTab from "./tabs/OverviewTab";
import ScopeTab from "./tabs/ScopeTab";
import RunsTab from "./tabs/RunsTab";
import FindingsTab from "./tabs/FindingsTab";
import EntitiesTab from "./tabs/EntitiesTab";
import ArtifactsTab from "./tabs/ArtifactsTab";
import AssistantTab from "./tabs/AssistantTab";
import AuditTab from "./tabs/AuditTab";

type TabKey =
  | "overview"
  | "scope"
  | "runs"
  | "findings"
  | "entities"
  | "artifacts"
  | "assistant"
  | "audit";

const TABS: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "scope", label: "Scope" },
  { key: "runs", label: "Runs" },
  { key: "findings", label: "Findings" },
  { key: "entities", label: "Entities" },
  { key: "artifacts", label: "Artifacts" },
  { key: "assistant", label: "Assistant" },
  { key: "audit", label: "Audit" },
];

const VALID_TABS = new Set<string>(TABS.map((t) => t.key));

export default function ProjectDetailPage() {
  const { projectID = "" } = useParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const tab: TabKey =
    tabParam && VALID_TABS.has(tabParam) ? (tabParam as TabKey) : "overview";

  function setTab(next: TabKey) {
    setSearchParams(
      (prev) => {
        const sp = new URLSearchParams(prev);
        if (next === "overview") sp.delete("tab");
        else sp.set("tab", next);
        return sp;
      },
      { replace: true },
    );
  }

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
      toast("success", "Project deleted");
      nav("/");
    },
    onError: (e: Error) => toast("error", `Delete failed: ${e.message}`),
  });

  useDocumentTitle(q.data?.name);

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
              <Button
                variant="danger"
                onClick={() => del.mutate()}
                disabled={del.isPending}
              >
                {del.isPending ? "Deleting..." : "Confirm delete"}
              </Button>
              <Button variant="ghost" onClick={() => setConfirmingDelete(false)}>
                Cancel
              </Button>
            </>
          ) : (
            <>
              <ReportDownload projectID={projectID} />
              <Button variant="danger" onClick={() => setConfirmingDelete(true)}>
                Delete project
              </Button>
            </>
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

      <div className="border-b border-slate-200 dark:border-slate-800 mb-6 overflow-x-auto">
        <nav className="flex gap-1 -mb-px whitespace-nowrap">
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
      {tab === "assistant" && <AssistantTab projectID={projectID} />}
      {tab === "audit" && <AuditTab projectID={projectID} />}
    </div>
  );
}

// ReportDownload is a small <details> dropdown of the supported
// report formats. Each option is a plain <a download> link so the
// browser fetches and saves the file without any SPA round-trip.
function ReportDownload({ projectID }: { projectID: string }) {
  const formats: Array<{
    key: "html" | "csv" | "pdf" | "docx" | "json";
    label: string;
  }> = [
    { key: "pdf", label: "PDF" },
    { key: "docx", label: "DOCX" },
    { key: "html", label: "HTML" },
    { key: "csv", label: "CSV" },
    { key: "json", label: "JSON" },
  ];
  return (
    <details className="relative">
      <summary className="list-none cursor-pointer inline-flex items-center justify-center px-3 py-1.5 rounded-md text-sm font-medium bg-slate-200 text-slate-900 hover:bg-slate-300 dark:bg-slate-700 dark:text-slate-100 dark:hover:bg-slate-600">
        Download report ▾
      </summary>
      <div className="absolute right-0 mt-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md shadow-lg z-10 min-w-[140px]">
        <ul className="py-1 text-sm">
          {formats.map((f) => (
            <li key={f.key}>
              <a
                href={api.reportURL(projectID, f.key)}
                target="_blank"
                rel="noopener noreferrer"
                className="block px-3 py-1.5 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                {f.label}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </details>
  );
}
