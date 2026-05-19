import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ScopeKind } from "../../api/types";
import {
  Button,
  Card,
  Empty,
  ErrorMessage,
  Input,
  SectionTitle,
  Select,
  Spinner,
} from "../../components/ui";

export default function ScopeTab({ projectID }: { projectID: string }) {
  const qc = useQueryClient();
  const rulesQ = useQuery({
    queryKey: ["scope-rules", projectID],
    queryFn: () => api.listScopeRules(projectID),
  });

  const [pattern, setPattern] = useState("");
  const [kind, setKind] = useState<ScopeKind>("light_active");
  const [note, setNote] = useState("");

  const create = useMutation({
    mutationFn: () =>
      api.createScopeRule(projectID, { pattern, kind, note: note || undefined }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scope-rules", projectID] });
      setPattern("");
      setNote("");
    },
  });

  const del = useMutation({
    mutationFn: (ruleID: string) => api.deleteScopeRule(projectID, ruleID),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["scope-rules", projectID] }),
  });

  function onAdd(e: FormEvent) {
    e.preventDefault();
    create.mutate();
  }

  return (
    <div className="space-y-6">
      <div>
        <SectionTitle>Rules</SectionTitle>
        {rulesQ.isLoading && <Spinner />}
        {rulesQ.isError && <ErrorMessage>{(rulesQ.error as Error).message}</ErrorMessage>}
        {rulesQ.data && rulesQ.data.length === 0 && (
          <Empty>No scope rules. Targets fall back to the project's default scope.</Empty>
        )}
        {rulesQ.data && rulesQ.data.length > 0 && (
          <Card>
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="px-4 py-2">Pattern</th>
                  <th className="px-4 py-2">Kind</th>
                  <th className="px-4 py-2">Note</th>
                  <th className="px-4 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {rulesQ.data.map((r) => (
                  <tr key={r.id}>
                    <td className="px-4 py-2 font-mono text-xs">{r.pattern}</td>
                    <td className="px-4 py-2">{r.kind}</td>
                    <td className="px-4 py-2 text-slate-500 dark:text-slate-400">
                      {r.note || "—"}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <Button
                        variant="ghost"
                        onClick={() => del.mutate(r.id)}
                        disabled={del.isPending}
                      >
                        Delete
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}
      </div>

      <Card className="p-4">
        <SectionTitle>Add rule</SectionTitle>
        <form onSubmit={onAdd} className="grid grid-cols-[1fr_180px_1fr_auto] gap-3 items-end">
          <label className="block">
            <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">
              Pattern
            </span>
            <Input
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="*.example.com"
              required
              className="w-full"
            />
          </label>
          <label className="block">
            <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">
              Kind
            </span>
            <Select
              value={kind}
              onChange={(e) => setKind(e.target.value as ScopeKind)}
              className="w-full"
            >
              <option value="passive">Passive</option>
              <option value="light_active">Light active</option>
              <option value="full_active">Full active</option>
              <option value="deny">Deny</option>
            </Select>
          </label>
          <label className="block">
            <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">
              Note (optional)
            </span>
            <Input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              className="w-full"
            />
          </label>
          <Button type="submit" disabled={create.isPending || !pattern}>
            {create.isPending ? "Adding..." : "Add"}
          </Button>
        </form>
        {create.error && <ErrorMessage>{(create.error as Error).message}</ErrorMessage>}
      </Card>

      <ScopeTester projectID={projectID} />
    </div>
  );
}

function ScopeTester({ projectID }: { projectID: string }) {
  const [target, setTarget] = useState("");
  const m = useMutation({
    mutationFn: (t: string) => api.scopeTest(projectID, t),
  });
  return (
    <Card className="p-4">
      <SectionTitle>Test a target</SectionTitle>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (target) m.mutate(target);
        }}
        className="flex gap-2 items-end"
      >
        <Input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="api.example.com"
          className="flex-1"
        />
        <Button type="submit" disabled={m.isPending || !target}>
          Test
        </Button>
      </form>
      {m.data && (
        <div className="mt-3 text-sm space-y-1">
          <div>
            <span className="font-medium">{m.data.allowed ? "Allowed" : "Denied"}</span>
            {m.data.matched_pattern && (
              <span className="text-slate-500 dark:text-slate-400">
                {" "}— matched <code>{m.data.matched_pattern}</code> ({m.data.matched_kind})
              </span>
            )}
          </div>
        </div>
      )}
      {m.error && <ErrorMessage>{(m.error as Error).message}</ErrorMessage>}
    </Card>
  );
}
