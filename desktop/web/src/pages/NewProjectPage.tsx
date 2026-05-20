import { FormEvent, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { Button, ErrorMessage, Input, PageTitle, Select, Textarea } from "../components/ui";
import { useToast } from "../components/Toast";
import type { Mode, ScopeKind } from "../api/types";

export default function NewProjectPage() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [organization, setOrganization] = useState("");
  const [description, setDescription] = useState("");
  const [mode, setMode] = useState<Mode>("assessment");
  const [defaultScope, setDefaultScope] = useState<ScopeKind>("passive");

  const m = useMutation({
    mutationFn: () =>
      api.createProject({
        name,
        organization: organization || undefined,
        description: description || undefined,
        mode,
        default_scope: defaultScope,
      }),
    onSuccess: (p) => {
      qc.invalidateQueries({ queryKey: ["projects"] });
      toast("success", `Project "${p.name}" created`);
      nav(`/projects/${p.id}`);
    },
    onError: (e: Error) => toast("error", `Could not create: ${e.message}`),
  });

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    m.mutate();
  }

  return (
    <div className="max-w-xl">
      <PageTitle>New project</PageTitle>
      <form onSubmit={onSubmit} className="space-y-4">
        <Field label="Name" hint="Unique within this server.">
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            autoFocus
            placeholder="Acme Corp Q3"
          />
        </Field>
        <Field label="Organization (optional)">
          <Input
            value={organization}
            onChange={(e) => setOrganization(e.target.value)}
            placeholder="Acme Corp"
          />
        </Field>
        <Field label="Description (optional)">
          <Textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
          />
        </Field>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Mode" hint="Affects recommended tools per phase.">
            <Select value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
              <option value="assessment">Assessment</option>
              <option value="bug_bounty">Bug Bounty</option>
              <option value="ctf">CTF</option>
            </Select>
          </Field>
          <Field label="Default scope" hint="Floor for unmatched targets.">
            <Select
              value={defaultScope}
              onChange={(e) => setDefaultScope(e.target.value as ScopeKind)}
            >
              <option value="passive">Passive</option>
              <option value="light_active">Light active</option>
              <option value="full_active">Full active</option>
              <option value="deny">Deny</option>
            </Select>
          </Field>
        </div>

        {m.error && <ErrorMessage>{(m.error as Error).message}</ErrorMessage>}

        <div className="flex gap-2">
          <Button type="submit" disabled={m.isPending || !name}>
            {m.isPending ? "Creating..." : "Create project"}
          </Button>
          <Button type="button" variant="ghost" onClick={() => nav(-1)}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium block mb-1">{label}</span>
      {children}
      {hint && (
        <span className="text-xs text-slate-500 dark:text-slate-400 block mt-1">
          {hint}
        </span>
      )}
    </label>
  );
}
