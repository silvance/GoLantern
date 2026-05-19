import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../../api/client";
import {
  Card,
  Empty,
  ErrorMessage,
  SectionTitle,
  Spinner,
} from "../../components/ui";

export default function ArtifactsTab({ projectID }: { projectID: string }) {
  const q = useQuery({
    queryKey: ["artifacts", projectID],
    queryFn: () => api.listArtifacts(projectID),
    retry: false, // 501 is meaningful, don't keep retrying
  });

  if (q.isLoading) return <Spinner />;
  if (q.isError) {
    const err = q.error as Error;
    const isUnconfigured = err instanceof ApiError && err.status === 501;
    return (
      <Card className="p-4">
        <SectionTitle>Artifacts</SectionTitle>
        {isUnconfigured ? (
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Artifact storage isn't configured on this server. Restart
            with <code className="text-xs">--artifacts-dir</code> (or set
            <code className="text-xs"> GOLANTERN_ARTIFACTS_DIR</code> for
            the Tauri shell) to enable screenshot capture.
          </p>
        ) : (
          <ErrorMessage>{err.message}</ErrorMessage>
        )}
      </Card>
    );
  }
  if (!q.data || q.data.length === 0) {
    return (
      <div>
        <SectionTitle>Artifacts</SectionTitle>
        <Empty>
          No artifacts yet. Run the gowitness collector to capture screenshots.
        </Empty>
      </div>
    );
  }

  return (
    <div>
      <SectionTitle>
        Artifacts{" "}
        <span className="text-sm font-normal text-slate-500 dark:text-slate-400">
          ({q.data.length})
        </span>
      </SectionTitle>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-3">
        {q.data.map((a) => {
          const isImage = a.content_type.startsWith("image/");
          const href = api.artifactURL(a.id);
          return (
            <Card key={a.id} className="overflow-hidden">
              <a href={href} target="_blank" rel="noopener noreferrer" className="block">
                {isImage ? (
                  <img
                    src={href}
                    alt={a.filename}
                    loading="lazy"
                    className="w-full h-32 object-cover bg-slate-900"
                  />
                ) : (
                  <div className="w-full h-32 flex items-center justify-center bg-slate-100 dark:bg-slate-800 text-xs text-slate-500">
                    {a.content_type}
                  </div>
                )}
              </a>
              <div className="p-2 text-xs">
                <div className="font-mono truncate" title={a.filename}>
                  {a.filename}
                </div>
                <div className="text-slate-500 dark:text-slate-400">
                  {formatBytes(a.size_bytes)}
                </div>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
