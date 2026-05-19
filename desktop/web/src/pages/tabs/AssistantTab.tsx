import { FormEvent, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, ApiError } from "../../api/client";
import {
  Button,
  Card,
  ErrorMessage,
  SectionTitle,
  Spinner,
  Textarea,
} from "../../components/ui";

interface Exchange {
  question: string;
  content: string;
  model: string;
  input_tokens?: number;
  output_tokens?: number;
}

export default function AssistantTab({ projectID }: { projectID: string }) {
  const [question, setQuestion] = useState("");
  const [history, setHistory] = useState<Exchange[]>([]);

  const ask = useMutation({
    mutationFn: (q: string) => api.ask(projectID, q),
    onSuccess: (resp, q) => {
      setHistory((h) => [
        {
          question: q,
          content: resp.content,
          model: resp.model,
          input_tokens: resp.input_tokens,
          output_tokens: resp.output_tokens,
        },
        ...h,
      ]);
      setQuestion("");
    },
  });

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    const q = question.trim();
    if (!q) return;
    ask.mutate(q);
  }

  const apiErr = ask.error as Error | null;
  const isUnconfigured = apiErr instanceof ApiError && apiErr.status === 501;

  if (isUnconfigured) {
    return (
      <Card className="p-4">
        <SectionTitle>Assistant</SectionTitle>
        <p className="text-sm text-slate-600 dark:text-slate-300">
          The assistant isn't configured on this server. Set the
          following env vars and restart:
        </p>
        <ul className="list-disc ml-6 mt-2 text-sm text-slate-600 dark:text-slate-300 space-y-1">
          <li><code>LANTERN_ASSISTANT_ENABLED=true</code></li>
          <li><code>LANTERN_ASSISTANT_PROVIDER=anthropic</code> (or <code>openai</code>)</li>
          <li><code>LANTERN_ASSISTANT_API_KEY=&lt;key&gt;</code></li>
          <li><code>LANTERN_ASSISTANT_MODEL=&lt;model id&gt;</code> (optional)</li>
        </ul>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <SectionTitle>Ask the assistant</SectionTitle>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
          The assistant sees a snapshot of this project's findings,
          entities, and recent runs. Replies aren't authoritative —
          treat them as a research aid, not as conclusions.
        </p>
        <form onSubmit={onSubmit} className="space-y-2">
          <Textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            rows={3}
            placeholder="What should I check next on the discovered subdomains?"
            className="w-full"
          />
          <div className="flex items-center gap-2">
            <Button type="submit" disabled={ask.isPending || !question.trim()}>
              {ask.isPending ? "Thinking..." : "Ask"}
            </Button>
            {ask.isPending && <Spinner />}
          </div>
        </form>
        {apiErr && !isUnconfigured && (
          <ErrorMessage>{apiErr.message}</ErrorMessage>
        )}
      </Card>

      {history.length > 0 && (
        <div className="space-y-3">
          {history.map((ex, i) => (
            <Card key={i} className="p-4">
              <div className="text-xs text-slate-500 dark:text-slate-400 mb-2">
                {ex.model}
                {typeof ex.input_tokens === "number" && (
                  <> · in {ex.input_tokens} tok</>
                )}
                {typeof ex.output_tokens === "number" && (
                  <> · out {ex.output_tokens} tok</>
                )}
              </div>
              <p className="text-sm font-medium whitespace-pre-wrap">
                {ex.question}
              </p>
              <hr className="my-3 border-slate-200 dark:border-slate-800" />
              <p className="text-sm whitespace-pre-wrap leading-relaxed">
                {ex.content}
              </p>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
