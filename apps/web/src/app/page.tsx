"use client";

import { Activity, AlertTriangle, Brain, FileUp, Network, Search, Settings2 } from "lucide-react";
import { useMemo, useState } from "react";

type TraceResult = {
  trace_id: string;
  filename: string;
  event_count: number;
  events: Array<Record<string, unknown>>;
  errors: Array<Record<string, unknown>>;
  ai_context: {
    trace_summary?: {
      event_count?: number;
      error_count?: number;
      protocols?: string[];
      participants?: Array<{ address: string; label: string }>;
      procedures?: Array<Record<string, unknown>>;
    };
  };
  settings?: {
    http2_ports?: number[];
    show_heartbeats?: boolean;
    hide_duplicate_pfcp?: boolean;
  };
};

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<TraceResult | null>(null);
  const [status, setStatus] = useState<"idle" | "uploading" | "error">("idle");
  const [http2Ports, setHttp2Ports] = useState("29502,29503,29504,29507,29509,29518");
  const [showHeartbeats, setShowHeartbeats] = useState(false);
  const [hideDuplicatePfcp, setHideDuplicatePfcp] = useState(true);
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [errorsOnly, setErrorsOnly] = useState(false);

  const protocols = useMemo(
    () => result?.ai_context.trace_summary?.protocols?.join(", ") || "Waiting for trace",
    [result],
  );
  const errorFrames = useMemo(() => new Set((result?.errors || []).map((error) => String(error.frame))), [result]);
  const participants = result?.ai_context.trace_summary?.participants || [];
  const visibleEvents = useMemo(() => {
    const events = result?.events || [];
    return events.filter((event) => {
      const matchesProtocol = protocolFilter === "all" || event.protocol === protocolFilter;
      const matchesError = !errorsOnly || errorFrames.has(String(event.frame));
      return matchesProtocol && matchesError;
    });
  }, [errorFrames, errorsOnly, protocolFilter, result]);

  async function uploadTrace() {
    if (!file) return;
    setStatus("uploading");

    const body = new FormData();
    body.append("file", file);
    body.append("http2_ports", http2Ports);
    body.append("show_heartbeats", String(showHeartbeats));
    body.append("hide_duplicate_pfcp", String(hideDuplicatePfcp));

    try {
      const apiBaseUrl =
        process.env.NEXT_PUBLIC_API_BASE_URL ||
        `${window.location.protocol}//${window.location.hostname}:8000`;
      const response = await fetch(`${apiBaseUrl}/traces`, {
        method: "POST",
        body,
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }

      setResult(await response.json());
      setStatus("idle");
    } catch {
      setStatus("error");
    }
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Network size={28} />
          <div>
            <strong>TraceLens AI</strong>
            <span>Protocol troubleshooting</span>
          </div>
        </div>

        <nav>
          <a className="active"><Activity size={18} /> Analyzer</a>
          <a><AlertTriangle size={18} /> Errors</a>
          <a><Brain size={18} /> AI Context</a>
          <a><Search size={18} /> Packets</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Trace Analyzer</h1>
            <p>Upload a PCAP to decode flows, detect failures, and prepare evidence for AI analysis.</p>
          </div>
          <button className="primary" onClick={uploadTrace} disabled={!file || status === "uploading"}>
            <FileUp size={18} />
            {status === "uploading" ? "Decoding" : "Analyze"}
          </button>
        </header>

        <section className="uploadPanel">
          <label>
            <FileUp size={28} />
            <span>{file ? file.name : "Choose PCAP / PCAPNG"}</span>
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={(event) => setFile(event.target.files?.[0] || null)}
            />
          </label>
          {status === "error" && <p className="errorText">Decode failed. Check API status and TShark availability.</p>}
        </section>

        <section className="settingsPanel">
          <div className="settingsTitle">
            <Settings2 size={18} />
            <strong>Trace Options</strong>
          </div>
          <label>
            <span>HTTP/2 ports</span>
            <input value={http2Ports} onChange={(event) => setHttp2Ports(event.target.value)} />
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={showHeartbeats}
              onChange={(event) => setShowHeartbeats(event.target.checked)}
            />
            <span>Show heartbeat messages</span>
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={hideDuplicatePfcp}
              onChange={(event) => setHideDuplicatePfcp(event.target.checked)}
            />
            <span>Hide duplicate PFCP</span>
          </label>
        </section>

        <section className="metrics">
          <Metric label="Frames decoded" value={String(result?.event_count || 0)} />
          <Metric label="Errors found" value={String(result?.errors.length || 0)} />
          <Metric label="Protocols" value={protocols} />
        </section>

        <section className="panel ladderPanel">
          <div className="panelTitle">
            <h2>Flow Ladder</h2>
            <div className="filters">
              <select value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)}>
                <option value="all">All protocols</option>
                {(result?.ai_context.trace_summary?.protocols || []).map((protocol) => (
                  <option value={protocol} key={protocol}>
                    {protocol}
                  </option>
                ))}
              </select>
              <label className="inlineCheck">
                <input
                  type="checkbox"
                  checked={errorsOnly}
                  onChange={(event) => setErrorsOnly(event.target.checked)}
                />
                <span>Errors only</span>
              </label>
            </div>
          </div>
          <Ladder events={visibleEvents} errorFrames={errorFrames} participants={participants} />
        </section>

        <section className="contentGrid">
          <div className="panel">
            <div className="panelTitle">
              <h2>Detected Errors</h2>
              <span>{result?.filename || "No trace loaded"}</span>
            </div>
            <div className="list">
              {(result?.errors || []).slice(0, 8).map((error) => (
                <article className="errorItem" key={`${error.protocol}-${error.frame}-${error.code}`}>
                  <strong>{String(error.error)}</strong>
                  <span>
                    Frame {String(error.frame)} | {String(error.protocol)} | Code {String(error.code)}
                  </span>
                  <p>{String(error.evidence)}</p>
                  {typeof error.root_cause === "string" && <p className="rootCause">{error.root_cause}</p>}
                  {asStringList(error.recommended_checks).length > 0 && (
                    <ul>
                      {asStringList(error.recommended_checks).map((check) => (
                        <li key={check}>{check}</li>
                      ))}
                    </ul>
                  )}
                </article>
              ))}
              {!result?.errors.length && <p className="empty">No decoded errors yet.</p>}
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Recent Events</h2>
              <span>First 200 normalized events</span>
            </div>
            <div className="table">
              <div className="row head">
                <span>Frame</span>
                <span>Protocol</span>
                <span>Source</span>
                <span>Destination</span>
              </div>
              {visibleEvents.slice(0, 12).map((event) => (
                <div className={`row ${errorFrames.has(String(event.frame)) ? "rowError" : ""}`} key={String(event.frame)}>
                  <span>{String(event.frame)}</span>
                  <span>{String(event.protocol || event.protocols || "-")}</span>
                  <span>{String(event.src || "-")}</span>
                  <span>{String(event.dst || "-")}</span>
                </div>
              ))}
            </div>
          </div>
        </section>
      </section>
    </main>
  );
}

function Ladder({
  events,
  errorFrames,
  participants,
}: {
  events: Array<Record<string, unknown>>;
  errorFrames: Set<string>;
  participants: Array<{ address: string; label: string }>;
}) {
  if (!events.length) {
    return <p className="empty ladderEmpty">No flow events yet.</p>;
  }

  const labels = new Map(participants.map((participant) => [participant.address, participant.label]));

  return (
    <div className="ladder">
      {events.slice(0, 80).map((event) => {
        const failed = errorFrames.has(String(event.frame));
        return (
          <article className={`ladderEvent ${failed ? "failed" : ""}`} key={String(event.frame)}>
            <div className="endpoint left">
              <strong>{labels.get(String(event.src)) || String(event.src || "-")}</strong>
              <span>{String(event.src || "-")}</span>
            </div>
            <div className="arrow">
              <span className="line" />
              <span className="head" />
            </div>
            <div className="endpoint right">
              <strong>{labels.get(String(event.dst)) || String(event.dst || "-")}</strong>
              <span>{String(event.dst || "-")}</span>
            </div>
            <div className="message">
              <strong>
                Frame {String(event.frame)} | {String(event.protocol || "-")}
              </strong>
              <span>
                {String(event.message || event.protocols || "-")}
                {event.cause_code ? ` | Cause ${String(event.cause_code)}` : ""}
                {event.sequence_number ? ` | Seq ${String(event.sequence_number)}` : ""}
              </span>
            </div>
          </article>
        );
      })}
    </div>
  );
}

function asStringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
