import { useEffect, useState } from "react";
import { api } from "../api/client";

export interface RunEvent {
  kind: string;
  run_id: string;
  payload?: Record<string, unknown>;
  ts: number; // client-side receive timestamp
}

// useRunEvents subscribes to /api/v1/runs/{id}/events via EventSource
// and accumulates received events into state. Closed on unmount.
//
// EventSource auto-reconnects on transient drops; we also expose a
// `status` state so the UI can show "connecting" vs "live" vs "closed".
export function useRunEvents(runID: string | undefined): {
  events: RunEvent[];
  status: "idle" | "connecting" | "live" | "closed" | "error";
} {
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [status, setStatus] = useState<"idle" | "connecting" | "live" | "closed" | "error">("idle");

  useEffect(() => {
    if (!runID) return;
    setEvents([]);
    setStatus("connecting");
    const es = new EventSource(api.runEventsURL(runID));
    es.onopen = () => setStatus("live");
    es.onerror = () => {
      // EventSource will retry by default; surface the in-flight
      // condition without tearing down state. If the server's down
      // for good, readyState transitions to CLOSED.
      if (es.readyState === EventSource.CLOSED) {
        setStatus("closed");
      } else {
        setStatus("error");
      }
    };
    es.onmessage = (m) => {
      try {
        const parsed = JSON.parse(m.data);
        setEvents((prev) => [...prev, { ...parsed, ts: Date.now() }]);
      } catch {
        // Server sometimes sends comment-only keepalive frames; the
        // browser delivers those as empty data. Ignore.
      }
    };
    return () => {
      es.close();
      setStatus("closed");
    };
  }, [runID]);

  return { events, status };
}
