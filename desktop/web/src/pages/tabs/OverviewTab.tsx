import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { Mode, Project, ScopeKind } from "../../api/types";
import {
  Button,
  Card,
  ErrorMessage,
  Input,
  SectionTitle,
  Select,
  Textarea,
} from "../../components/ui";

export default function OverviewTab({ project }: { project: Project }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(project.name);
  const [organization, setOrganization] = useState(project.organization ?? "");
  const [description, setDescription] = useState(project.description ?? "");
  const [mode, setMode] = useState<Mode>(project.mode);
  const [defaultScope, setDefaultScope] = useState<ScopeKind>(project.default_scope);

  const m = useMutation({
    mutationFn: () =>
      api.updateProject(project.id, {
        name,
        organization: organization || undefined,
        description: description || undefined,
        mode,
        default_scope: defaultScope,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["project", project.id] });
      qc.invalidateQueries({ queryKey: ["projects"] });
      setEditing(false);
    },
  });

  if (!editing) {
    return (
      <div className="space-y-4">
        <SectionTitle actions={<Button onClick={() => setEditing(true)}>Edit</Button>}>
          Metadata
        </SectionTitle>
        <Card className="p-4 space-y-3">
          <Row label="Name" value={project.name} />
          <Row label="Organization" value={project.organization || "—"} />
          <Row label="Description" value={project.description || "—"} />
          <Row label="Mode" value={project.mode} />
          <Row label="Default scope" value={project.default_scope} />
          <Row label="Report template" value={project.report_template || "—"} />
          <Row label="ID" value={<code className="text-xs">{project.id}</code>} />
        </Card>
      </div>
    );
  }

  return (
    <div className="max-w-xl space-y-4">
      <SectionTitle>Edit metadata</SectionTitle>
      <label className="block">
        <span className="text-sm font-medium block mb-1">Name</span>
        <Input value={name} onChange={(e) => setName(e.target.value)} required />
      </label>
      <label className="block">
        <span className="text-sm font-medium block mb-1">Organization</span>
        <Input value={organization} onChange={(e) => setOrganization(e.target.value)} />
      </label>
      <label className="block">
        <span className="text-sm font-medium block mb-1">Description</span>
        <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
      </label>
      <div className="grid grid-cols-2 gap-4">
        <label className="block">
          <span className="text-sm font-medium block mb-1">Mode</span>
          <Select value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
            <option value="assessment">Assessment</option>
            <option value="bug_bounty">Bug Bounty</option>
            <option value="ctf">CTF</option>
          </Select>
        </label>
        <label className="block">
          <span className="text-sm font-medium block mb-1">Default scope</span>
          <Select value={defaultScope} onChange={(e) => setDefaultScope(e.target.value as ScopeKind)}>
            <option value="passive">Passive</option>
            <option value="light_active">Light active</option>
            <option value="full_active">Full active</option>
            <option value="deny">Deny</option>
          </Select>
        </label>
      </div>
      {m.error && <ErrorMessage>{(m.error as Error).message}</ErrorMessage>}
      <div className="flex gap-2">
        <Button onClick={() => m.mutate()} disabled={m.isPending}>
          {m.isPending ? "Saving..." : "Save"}
        </Button>
        <Button variant="ghost" onClick={() => setEditing(false)}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-2 text-sm">
      <div className="text-slate-500 dark:text-slate-400">{label}</div>
      <div>{value}</div>
    </div>
  );
}
