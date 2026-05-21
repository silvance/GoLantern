import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import {
  Button,
  Card,
  Empty,
  ErrorMessage,
  Input,
  SectionTitle,
  Select,
  Spinner,
  Textarea,
} from "../../components/ui";
import { useToast } from "../../components/Toast";

// IngestTab is the post-foothold "paste evidence" surface. Operator
// pastes raw LinPEAS / WinPEAS / mimikatz output from a reverse-shell
// session and the server parses it into findings + entities. The
// resulting facts show up in the Findings and Entities tabs alongside
// scanner-driven results.
export default function IngestTab({ projectID }: { projectID: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const parsersQ = useQuery({
    queryKey: ["evidence-parsers"],
    queryFn: api.listEvidenceParsers,
  });

  const [tool, setTool] = useState("");
  const [target, setTarget] = useState("");
  const [content, setContent] = useState("");
  const [notes, setNotes] = useState("");
  const [lastResult, setLastResult] = useState<{
    findings: number;
    entities: number;
  } | null>(null);

  // Auto-select the first parser when the list loads.
  if (tool === "" && parsersQ.data && parsersQ.data.length > 0) {
    setTool(parsersQ.data[0].name);
  }

  const ingest = useMutation({
    mutationFn: () =>
      api.ingestEvidence(projectID, {
        tool,
        content,
        target: target || undefined,
        notes: notes || undefined,
      }),
    onSuccess: (r) => {
      setLastResult({ findings: r.findings_emitted, entities: r.entities_emitted });
      setContent("");
      setNotes("");
      qc.invalidateQueries({ queryKey: ["report", projectID] });
      qc.invalidateQueries({ queryKey: ["entities", projectID] });
      toast(
        "success",
        `Ingested — ${r.findings_emitted} finding${r.findings_emitted === 1 ? "" : "s"}, ${r.entities_emitted} entit${r.entities_emitted === 1 ? "y" : "ies"}`,
      );
    },
    onError: (e: Error) => toast("error", `Ingest failed: ${e.message}`),
  });

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!tool || !content.trim()) return;
    ingest.mutate();
  }

  const selectedDesc =
    parsersQ.data?.find((p) => p.name === tool)?.description ?? "";

  return (
    <div className="space-y-6">
      <Card className="p-4">
        <SectionTitle>Paste post-foothold output</SectionTitle>
        <p className="text-sm text-slate-600 dark:text-slate-300 mb-4">
          Ran LinPEAS or WinPEAS on the compromised host via your reverse shell?
          Paste the raw output here and we'll extract the actionable findings
          into the project graph.
        </p>

        {parsersQ.isLoading && <Spinner />}
        {parsersQ.isError && (
          <ErrorMessage>
            Evidence ingest not configured on this server.
          </ErrorMessage>
        )}
        {parsersQ.data && parsersQ.data.length === 0 && (
          <Empty>No parsers registered.</Empty>
        )}

        {parsersQ.data && parsersQ.data.length > 0 && (
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="grid grid-cols-[200px_1fr] gap-3 items-start">
              <label className="block">
                <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">
                  Tool
                </span>
                <Select
                  value={tool}
                  onChange={(e) => setTool(e.target.value)}
                  className="w-full"
                >
                  {parsersQ.data.map((p) => (
                    <option key={p.name} value={p.name}>
                      {p.name}
                    </option>
                  ))}
                </Select>
                {selectedDesc && (
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                    {selectedDesc}
                  </p>
                )}
              </label>
              <label className="block">
                <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">
                  Target (optional)
                </span>
                <Input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="10.0.0.5 or host.example.com"
                  className="w-full"
                />
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                  The host this evidence pertains to. Findings get attached to
                  this entity in the graph.
                </p>
              </label>
            </div>

            <label className="block">
              <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">
                Raw tool output
              </span>
              <Textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                rows={14}
                className="w-full font-mono text-xs"
                placeholder="Paste the LinPEAS / WinPEAS / etc. output here…"
                required
              />
            </label>

            <label className="block">
              <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">
                Notes (optional)
              </span>
              <Input
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="post-foothold paste from initial recon"
                className="w-full"
              />
            </label>

            {ingest.error && (
              <ErrorMessage>{(ingest.error as Error).message}</ErrorMessage>
            )}

            <div className="flex gap-2 items-center">
              <Button
                type="submit"
                disabled={ingest.isPending || !tool || !content.trim()}
              >
                {ingest.isPending ? "Ingesting…" : "Ingest"}
              </Button>
              {lastResult && (
                <span className="text-xs text-slate-500 dark:text-slate-400">
                  Last ingest: {lastResult.findings} finding
                  {lastResult.findings === 1 ? "" : "s"},{" "}
                  {lastResult.entities} entit
                  {lastResult.entities === 1 ? "y" : "ies"}.
                </span>
              )}
            </div>
          </form>
        )}
      </Card>
    </div>
  );
}
