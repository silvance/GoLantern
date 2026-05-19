// ToolPicker renders the available collectors grouped by phase with
// a checkbox per tool and an expandable parameter form per selected
// tool. Output via onChange is a `ToolInvocation[]` ready to drop
// into CreateRunRequest.tools.
//
// We keep state internal but echo every change via onChange so the
// parent (RunsTab) doesn't have to duplicate the selection logic.

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { ParameterSpec, Phase, ToolInvocation } from "../api/types";
import { Empty, ErrorMessage, Input, Select, Spinner } from "./ui";

type ParamsByTool = Record<string, Record<string, unknown>>;

export function ToolPicker({
  phase,
  value,
  onChange,
  recommended = [],
}: {
  phase: Phase;
  value: ToolInvocation[];
  onChange: (next: ToolInvocation[]) => void;
  /** Tool names to highlight + auto-select on first render. */
  recommended?: string[];
}) {
  const q = useQuery({
    queryKey: ["collectors"],
    queryFn: api.listCollectors,
    retry: false,
  });

  // Local state mirrors `value` so we can edit parameters in-place
  // without forcing the parent to round-trip every keystroke.
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(value.map((v) => v.tool)),
  );
  const [paramsByTool, setParamsByTool] = useState<ParamsByTool>(() => {
    const m: ParamsByTool = {};
    for (const inv of value) m[inv.tool] = inv.parameters ?? {};
    return m;
  });

  // Auto-select recommended tools the first time the picker mounts
  // with a fresh, empty selection.
  useEffect(() => {
    if (value.length === 0 && recommended.length > 0 && selected.size === 0) {
      const next = new Set(recommended);
      setSelected(next);
      onChange(
        recommended.map((tool) => ({ tool, parameters: paramsByTool[tool] })),
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recommended.join("|")]);

  function emit(nextSel: Set<string>, nextParams: ParamsByTool) {
    const list: ToolInvocation[] = [];
    for (const tool of nextSel) {
      const params = nextParams[tool];
      list.push(
        params && Object.keys(params).length > 0 ? { tool, parameters: params } : { tool },
      );
    }
    onChange(list);
  }

  function toggle(tool: string) {
    const next = new Set(selected);
    if (next.has(tool)) next.delete(tool);
    else next.add(tool);
    setSelected(next);
    emit(next, paramsByTool);
  }

  function setParam(tool: string, name: string, v: unknown) {
    const nextForTool = { ...(paramsByTool[tool] ?? {}) };
    if (v === "" || v === undefined || v === null) {
      delete nextForTool[name];
    } else {
      nextForTool[name] = v;
    }
    const next: ParamsByTool = { ...paramsByTool, [tool]: nextForTool };
    setParamsByTool(next);
    emit(selected, next);
  }

  // Filter to the phase the user picked. The picker stays responsive
  // when the form's phase changes — selection survives across phase
  // switches so the user can build a cross-phase plan in one go
  // (though the run-create form always sends them under one phase).
  const collectorsForPhase = useMemo(
    () => (q.data ?? []).filter((c) => c.phase === phase),
    [q.data, phase],
  );

  if (q.isLoading) return <Spinner />;
  if (q.isError) {
    return (
      <ErrorMessage>
        Couldn't load collector list: {(q.error as Error).message}
      </ErrorMessage>
    );
  }
  if (collectorsForPhase.length === 0) {
    return <Empty>No collectors registered for phase “{phase}”.</Empty>;
  }

  const recSet = new Set(recommended);

  return (
    <div className="space-y-2">
      {collectorsForPhase.map((c) => {
        const isOn = selected.has(c.name);
        return (
          <div
            key={c.name}
            className={`border rounded-md p-3 ${
              isOn
                ? "border-blue-400 bg-blue-50/40 dark:bg-blue-950/30"
                : "border-slate-200 dark:border-slate-800"
            }`}
          >
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={isOn}
                onChange={() => toggle(c.name)}
                className="mt-1"
              />
              <div className="flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-medium">{c.name}</span>
                  {recSet.has(c.name) && (
                    <span className="text-[10px] uppercase tracking-wide bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200 px-1.5 py-0.5 rounded">
                      recommended
                    </span>
                  )}
                  <span className="text-xs text-slate-500 dark:text-slate-400">
                    requires {c.required_scope.replace("_", " ")}
                  </span>
                  {c.binary && (
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      · binary <code className="text-xs">{c.binary}</code>
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300 mt-1">
                  {c.description}
                </p>
              </div>
            </label>
            {isOn && c.parameters.length > 0 && (
              <ParameterForm
                parameters={c.parameters}
                values={paramsByTool[c.name] ?? {}}
                onChange={(name, v) => setParam(c.name, name, v)}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

function ParameterForm({
  parameters,
  values,
  onChange,
}: {
  parameters: ParameterSpec[];
  values: Record<string, unknown>;
  onChange: (name: string, value: unknown) => void;
}) {
  return (
    <div className="mt-3 ml-7 grid grid-cols-1 sm:grid-cols-2 gap-3">
      {parameters.map((p) => (
        <ParameterField
          key={p.name}
          spec={p}
          value={values[p.name]}
          onChange={(v) => onChange(p.name, v)}
        />
      ))}
    </div>
  );
}

function ParameterField({
  spec,
  value,
  onChange,
}: {
  spec: ParameterSpec;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  const label = (
    <span className="text-xs text-slate-600 dark:text-slate-300 block mb-1">
      <span className="font-medium">{spec.name}</span>
      {spec.required && <span className="text-red-600 ml-0.5">*</span>}
      {spec.description && (
        <span className="text-slate-500 dark:text-slate-400 font-normal ml-1">
          — {spec.description}
        </span>
      )}
    </span>
  );

  // Defensive coercion: server's Default arrives untyped, but we know
  // the spec's `type` field. Render the right input shape so the
  // parameter goes back as the type the collector expects.
  switch (spec.type) {
    case "bool":
      return (
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={!!value}
            onChange={(e) => onChange(e.target.checked)}
            className="mt-0.5"
          />
          <div>
            <span className="font-medium">{spec.name}</span>
            {spec.description && (
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                {spec.description}
              </span>
            )}
          </div>
        </label>
      );
    case "enum":
      return (
        <label className="block">
          {label}
          <Select
            value={(value as string) ?? ""}
            onChange={(e) => onChange(e.target.value)}
            className="w-full"
          >
            <option value="">(unset)</option>
            {spec.choices?.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </Select>
        </label>
      );
    case "int":
    case "float":
      return (
        <label className="block">
          {label}
          <Input
            type="number"
            inputMode={spec.type === "int" ? "numeric" : "decimal"}
            step={spec.type === "int" ? "1" : "any"}
            value={value === undefined ? "" : String(value)}
            placeholder={spec.placeholder ?? displayDefault(spec.default)}
            onChange={(e) => {
              const s = e.target.value;
              if (s === "") return onChange(undefined);
              const n = Number(s);
              onChange(Number.isFinite(n) ? n : undefined);
            }}
            className="w-full"
          />
        </label>
      );
    case "string_list":
      return (
        <label className="block">
          {label}
          <Input
            value={Array.isArray(value) ? value.join(", ") : ((value as string) ?? "")}
            placeholder={spec.placeholder ?? "comma-separated"}
            onChange={(e) => {
              const parts = e.target.value
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean);
              onChange(parts.length === 0 ? undefined : parts);
            }}
            className="w-full"
          />
        </label>
      );
    default:
      return (
        <label className="block">
          {label}
          <Input
            value={(value as string) ?? ""}
            placeholder={spec.placeholder ?? displayDefault(spec.default)}
            onChange={(e) => onChange(e.target.value)}
            className="w-full"
          />
        </label>
      );
  }
}

function displayDefault(v: unknown): string {
  if (v === undefined || v === null) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
