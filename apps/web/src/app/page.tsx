"use client";

import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle2,
  Clipboard,
  Clock3,
  ExternalLink,
  FileUp,
  Network,
  Search,
  Settings2,
  Shield,
} from "lucide-react";
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
      procedure_groups?: Array<Record<string, unknown>>;
    };
  };
  settings?: {
    http2_ports?: number[];
    show_heartbeats?: boolean;
    hide_duplicate_pfcp?: boolean;
  };
};

type AiAnalysis = {
  provider: string;
  mode: string;
  ai_used: boolean;
  masked: boolean;
  summary: string;
  root_cause: string;
  confidence: string;
  evidence: string[];
  recommended_actions: string[];
  ai_text?: string;
  ai_error?: string;
};

export default function Home() {
  const [files, setFiles] = useState<File[]>([]);
  const [mappingFile, setMappingFile] = useState<File | null>(null);
  const [result, setResult] = useState<TraceResult | null>(null);
  const [status, setStatus] = useState<"idle" | "uploading" | "error">("idle");
  const [http2Ports, setHttp2Ports] = useState("29502,29503,29504,29507,29509,29518");
  const [showHeartbeats, setShowHeartbeats] = useState(false);
  const [hideDuplicatePfcp, setHideDuplicatePfcp] = useState(true);
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [selectedFrame, setSelectedFrame] = useState<string | null>(null);
  const [aiQuestion, setAiQuestion] = useState("Explain the failure and recommended troubleshooting steps.");
  const [maskIdentifiers, setMaskIdentifiers] = useState(true);
  const [aiStatus, setAiStatus] = useState<"idle" | "analyzing" | "error">("idle");
  const [aiAnalysis, setAiAnalysis] = useState<AiAnalysis | null>(null);
  const [chatGptStatus, setChatGptStatus] = useState<"idle" | "copied" | "error">("idle");

  const protocols = useMemo(
    () => result?.ai_context.trace_summary?.protocols?.join(", ") || "Waiting for trace",
    [result],
  );
  const errorFrames = useMemo(() => new Set((result?.errors || []).map((error) => String(error.frame))), [result]);
  const participants = result?.ai_context.trace_summary?.participants || [];
  const procedures = result?.ai_context.trace_summary?.procedures || [];
  const procedureGroups = result?.ai_context.trace_summary?.procedure_groups || [];
  const primaryError = result?.errors[0] || null;
  const visibleEvents = useMemo(() => {
    const events = result?.events || [];
    return events.filter((event) => {
      const matchesProtocol = protocolFilter === "all" || event.protocol === protocolFilter;
      const matchesError = !errorsOnly || errorFrames.has(String(event.frame));
      return matchesProtocol && matchesError;
    });
  }, [errorFrames, errorsOnly, protocolFilter, result]);
  const selectedEvent = useMemo(
    () => visibleEvents.find((event) => String(event.frame) === selectedFrame) || null,
    [selectedFrame, visibleEvents],
  );

  async function uploadTrace() {
    if (!files.length) return;
    setStatus("uploading");

    const body = new FormData();
    for (const selectedFile of files) {
      body.append("files", selectedFile);
    }
    if (mappingFile) {
      body.append("mapping_file", mappingFile);
    }
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
      setSelectedFrame(null);
      setAiAnalysis(null);
      setStatus("idle");
    } catch {
      setStatus("error");
    }
  }

  async function explainTrace() {
    if (!result) return;
    setAiStatus("analyzing");

    try {
      const apiBaseUrl =
        process.env.NEXT_PUBLIC_API_BASE_URL ||
        `${window.location.protocol}//${window.location.hostname}:8000`;
      const response = await fetch(`${apiBaseUrl}/analysis/explain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ai_context: result.ai_context,
          question: aiQuestion,
          use_ai: true,
          mask_identifiers: maskIdentifiers,
        }),
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }

      setAiAnalysis(await response.json());
      setAiStatus("idle");
    } catch {
      setAiStatus("error");
    }
  }

  async function copyChatGptPrompt() {
    if (!result) return;
    const prompt = buildChatGptPrompt(result, aiQuestion, maskIdentifiers);

    try {
      await navigator.clipboard.writeText(prompt);
      setChatGptStatus("copied");
      window.setTimeout(() => setChatGptStatus("idle"), 2500);
    } catch {
      setChatGptStatus("error");
    }
  }

  function openChatGpt() {
    window.open("https://chatgpt.com/", "_blank", "noopener,noreferrer");
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
          <button className="primary" onClick={uploadTrace} disabled={!files.length || status === "uploading"}>
            <FileUp size={18} />
            {status === "uploading" ? "Decoding" : "Analyze"}
          </button>
        </header>

        <section className="uploadPanel">
          <label>
            <FileUp size={28} />
            <span>{files.length ? files.map((item) => item.name).join(", ") : "Choose PCAP / PCAPNG"}</span>
            <input
              type="file"
              multiple
              accept=".pcap,.pcapng,.cap"
              onChange={(event) => setFiles(Array.from(event.target.files || []))}
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
          <label>
            <span>Endpoint mapping</span>
            <input
              type="file"
              accept=".yaml,.yml,.json"
              onChange={(event) => setMappingFile(event.target.files?.[0] || null)}
            />
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
          <Metric label="Procedures" value={String(procedures.length)} />
          <Metric label="Protocols" value={protocols} />
        </section>

        <section className="troubleshootingBoard">
          <FailureFocus error={primaryError} procedures={procedures} />
          <ProcedureOverview groups={procedureGroups} procedures={procedures} />
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
          <Ladder
            events={visibleEvents}
            errorFrames={errorFrames}
            participants={participants}
            selectedFrame={selectedFrame}
            onSelectFrame={setSelectedFrame}
          />
        </section>

        <section className="panel aiPanel">
          <div className="panelTitle">
            <h2>TraceLens Explanation</h2>
            <span>{aiAnalysis ? explanationModeLabel(aiAnalysis) : "Local rules or connected AI provider"}</span>
          </div>
          <div className="aiSourceNotice">
            <strong>{aiAnalysis?.ai_used ? "Connected AI explanation" : "Local evidence explanation"}</strong>
            <span>
              {aiAnalysis?.ai_used
                ? "Generated by the configured AI provider from masked decoded evidence."
                : "Generated by TraceLens rules from decoded protocol fields. Use ChatGPT Web below when you want external AI without an API key."}
            </span>
          </div>
          <div className="aiControls">
            <label>
              <span>Question</span>
              <input value={aiQuestion} onChange={(event) => setAiQuestion(event.target.value)} />
            </label>
            <label className="inlineCheck">
              <input
                type="checkbox"
                checked={maskIdentifiers}
                onChange={(event) => setMaskIdentifiers(event.target.checked)}
              />
              <span><Shield size={15} /> Mask identifiers</span>
            </label>
            <button className="primary" onClick={explainTrace} disabled={!result || aiStatus === "analyzing"}>
              <Brain size={18} />
              {aiStatus === "analyzing" ? "Explaining" : "Explain Locally"}
            </button>
          </div>
          <div className="chatGptHandoff">
            <button onClick={copyChatGptPrompt} disabled={!result}>
              <Clipboard size={17} />
              Copy ChatGPT Prompt
            </button>
            <button onClick={openChatGpt}>
              <ExternalLink size={17} />
              Open ChatGPT
            </button>
            <span>
              {chatGptStatus === "copied"
                ? "Prompt copied"
                : chatGptStatus === "error"
                  ? "Copy failed"
                  : "Manual paste, no API key needed"}
            </span>
          </div>
          {aiStatus === "error" && <p className="errorText aiMessage">AI analysis failed. Backend fallback may need review.</p>}
          {aiAnalysis ? <AiAnalysisView analysis={aiAnalysis} /> : <p className="empty aiMessage">No analysis generated yet.</p>}
        </section>

        <section className="contentGrid threeColumn">
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
                <button
                  className={`row ${errorFrames.has(String(event.frame)) ? "rowError" : ""}`}
                  key={String(event.frame)}
                  onClick={() => setSelectedFrame(String(event.frame))}
                >
                  <span>{String(event.frame)}</span>
                  <span>{String(event.protocol || event.protocols || "-")}</span>
                  <span>{String(event.src || "-")}</span>
                  <span>{String(event.dst || "-")}</span>
                </button>
              ))}
            </div>
          </div>

          <FrameDetails event={selectedEvent} participants={participants} />
        </section>
      </section>
    </main>
  );
}

function FailureFocus({
  error,
  procedures,
}: {
  error: Record<string, unknown> | null;
  procedures: Array<Record<string, unknown>>;
}) {
  const failedProcedure = procedures.find((procedure) => procedure.status === "failed");

  return (
    <section className={`insightPanel ${error ? "hasFailure" : ""}`}>
      <div className="insightHeader">
        <AlertTriangle size={18} />
        <strong>Failure Focus</strong>
      </div>
      {error ? (
        <>
          <h2>{String(error.error || "Protocol failure")}</h2>
          <p>{String(error.root_cause || error.evidence || "A peer returned a supported failure code.")}</p>
          <div className="failureFacts">
            <span>Frame {String(error.frame || "-")}</span>
            <span>{String(error.protocol || "-")}</span>
            <span>Code {String(error.code || "-")}</span>
            {failedProcedure ? <span>{String(failedProcedure.procedure || "Procedure")} failed</span> : null}
          </div>
        </>
      ) : (
        <>
          <h2>No supported failure detected</h2>
          <p>TraceLens decoded the trace, but no current rule matched a known protocol error.</p>
          <div className="failureFacts">
            <span>Review timing</span>
            <span>Check missing responses</span>
            <span>Ask AI with evidence</span>
          </div>
        </>
      )}
    </section>
  );
}

function ProcedureOverview({
  groups,
  procedures,
}: {
  groups: Array<Record<string, unknown>>;
  procedures: Array<Record<string, unknown>>;
}) {
  const visibleGroups = groups.slice(0, 6);

  if (visibleGroups.length) {
    return (
      <section className="insightPanel timelinePanel">
        <div className="insightHeader">
          <Clock3 size={18} />
          <strong>Procedure Overview</strong>
        </div>
        <div className="procedureList">
          {visibleGroups.map((group) => {
            const failed = group.status === "failed";
            const protocols = asStringList(group.protocols).join(", ");
            return (
              <article className={`procedureStep ${failed ? "failed" : ""}`} key={`${group.name}-${group.start_frame}`}>
                {failed ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
                <div>
                  <strong>
                    {String(group.name || "Procedure")}
                    <small> {String(group.technology || "Network")}</small>
                  </strong>
                  <span>
                    Frames {String(group.start_frame || "-")} to {String(group.end_frame || "-")}
                    {group.duration_ms !== undefined && group.duration_ms !== null ? ` | ${String(group.duration_ms)} ms` : ""}
                    {protocols ? ` | ${protocols}` : ""}
                  </span>
                </div>
              </article>
            );
          })}
        </div>
      </section>
    );
  }

  return <ProcedureTimeline procedures={procedures} />;
}

function ProcedureTimeline({ procedures }: { procedures: Array<Record<string, unknown>> }) {
  const visibleProcedures = procedures.slice(0, 6);

  return (
    <section className="insightPanel timelinePanel">
      <div className="insightHeader">
        <Clock3 size={18} />
        <strong>Procedure Timing</strong>
      </div>
      {visibleProcedures.length ? (
        <div className="procedureList">
          {visibleProcedures.map((procedure) => {
            const failed = procedure.status === "failed";
            return (
              <article className={`procedureStep ${failed ? "failed" : ""}`} key={`${procedure.request_frame}-${procedure.response_frame}`}>
                {failed ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
                <div>
                  <strong>{String(procedure.procedure || "Procedure")}</strong>
                  <span>
                    Frame {String(procedure.request_frame)} to {String(procedure.response_frame)}
                    {procedure.duration_ms !== undefined ? ` | ${String(procedure.duration_ms)} ms` : ""}
                  </span>
                </div>
              </article>
            );
          })}
        </div>
      ) : (
        <p className="empty">No request/response procedure pairs found yet.</p>
      )}
    </section>
  );
}

function AiAnalysisView({ analysis }: { analysis: AiAnalysis }) {
  return (
    <div className="aiResult">
      {analysis.ai_text ? (
        <article>
          <strong>AI Explanation</strong>
          <p>{analysis.ai_text}</p>
        </article>
      ) : null}
      <article>
        <strong>Summary</strong>
        <p>{analysis.summary}</p>
      </article>
      <article>
        <strong>Root Cause</strong>
        <p>{analysis.root_cause}</p>
      </article>
      <article>
        <strong>Confidence</strong>
        <p>{analysis.confidence}</p>
      </article>
      {analysis.evidence.length > 0 && (
        <article>
          <strong>Evidence</strong>
          <ul>
            {analysis.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </article>
      )}
      <article>
        <strong>Recommended Actions</strong>
        <ul>
          {analysis.recommended_actions.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </article>
      {analysis.ai_error ? <p className="errorText">{analysis.ai_error}</p> : null}
    </div>
  );
}

function Ladder({
  events,
  errorFrames,
  participants,
  selectedFrame,
  onSelectFrame,
}: {
  events: Array<Record<string, unknown>>;
  errorFrames: Set<string>;
  participants: Array<{ address: string; label: string }>;
  selectedFrame: string | null;
  onSelectFrame: (frame: string) => void;
}) {
  if (!events.length) {
    return <p className="empty ladderEmpty">No flow events yet.</p>;
  }

  const lanes = participants.length
    ? participants.slice(0, 8)
    : Array.from(
        new Set(events.flatMap((event) => [String(event.src || "-"), String(event.dst || "-")])),
      ).slice(0, 8).map((address) => ({ address, label: address }));
  const laneIndexes = new Map(lanes.map((participant, index) => [participant.address, index]));
  const gridTemplateColumns = `repeat(${Math.max(lanes.length, 1)}, minmax(160px, 1fr))`;

  return (
    <div className="sequenceDiagram">
      <div className="sequenceHeader" style={{ gridTemplateColumns }}>
        {lanes.map((participant) => (
          <div className="sequenceParticipant" key={participant.address}>
            <strong>{participant.label}</strong>
            <span>{participant.address}</span>
          </div>
        ))}
      </div>
      {events.slice(0, 80).map((event) => {
        const failed = errorFrames.has(String(event.frame));
        const srcIndex = laneIndexes.get(String(event.src || "-")) ?? 0;
        const dstIndex = laneIndexes.get(String(event.dst || "-")) ?? srcIndex;
        const left = Math.min(srcIndex, dstIndex);
        const right = Math.max(srcIndex, dstIndex);
        const reverse = srcIndex > dstIndex;
        return (
          <div className="sequenceRow" style={{ gridTemplateColumns }} key={String(event.frame)}>
            {lanes.map((participant) => (
              <span className="lifeLine" key={participant.address} />
            ))}
            <button
              className={`sequenceMessage ${failed ? "failed" : ""} ${
                selectedFrame === String(event.frame) ? "selected" : ""
              } ${reverse ? "reverse" : ""}`}
              style={{ gridColumn: `${left + 1} / ${right + 2}` }}
              onClick={() => onSelectFrame(String(event.frame))}
            >
              <span className="messageLine" />
              <span className="messageCard">
                <strong>
                  {String(event.message || event.protocols || "-")}
                  {event.cause_code ? ` | Cause ${String(event.cause_code)}` : ""}
                </strong>
                <span>
                  Frame {String(event.frame)} | {String(event.protocol || "-")}
                  {event.sequence_number ? ` | Seq ${String(event.sequence_number)}` : ""}
                </span>
              </span>
            </button>
          </div>
        );
      })}
    </div>
  );
}

function FrameDetails({
  event,
  participants,
}: {
  event: Record<string, unknown> | null;
  participants: Array<{ address: string; label: string; namespace?: string }>;
}) {
  const labels = new Map(participants.map((participant) => [participant.address, participant]));
  if (!event) {
    return (
      <div className="panel detailPanel">
        <div className="panelTitle">
          <h2>Frame Details</h2>
          <span>Select a ladder event</span>
        </div>
        <p className="empty detailEmpty">No frame selected.</p>
      </div>
    );
  }

  const src = labels.get(String(event.src));
  const dst = labels.get(String(event.dst));
  const details = [
    ["Frame", event.frame],
    ["Capture", event.capture_file],
    ["Original frame", event.original_frame],
    ["Protocol", event.protocol || event.protocols],
    ["Message", event.message],
    ["TEID", event.teid],
    ["Sequence", event.sequence_number],
    ["Cause", event.cause_code],
    ["IMSI", event.imsi],
    ["APN", event.apn],
    ["Source", src ? `${src.label} (${event.src})` : event.src],
    ["Destination", dst ? `${dst.label} (${event.dst})` : event.dst],
  ].filter(([, value]) => value !== undefined && value !== null && value !== "");

  return (
    <div className="panel detailPanel">
      <div className="panelTitle">
        <h2>Frame Details</h2>
        <span>Frame {String(event.frame)}</span>
      </div>
      <dl className="details">
        {details.map(([label, value]) => (
          <div key={String(label)}>
            <dt>{String(label)}</dt>
            <dd>{String(value)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function asStringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function explanationModeLabel(analysis: AiAnalysis) {
  if (analysis.ai_used) {
    return `${analysis.provider} | ${analysis.mode}`;
  }
  return "TraceLens rule-engine | offline";
}

function buildChatGptPrompt(result: TraceResult, question: string, maskIdentifiers: boolean) {
  const context = maskIdentifiers ? maskTraceContext(result.ai_context) : result.ai_context;
  return [
    "You are a telecom packet-trace troubleshooting assistant.",
    "Analyze the decoded TraceLens AI evidence below.",
    "Use only the supplied frame evidence unless you clearly label external/public knowledge.",
    "Cite frame numbers. Explain the failure point, likely root cause, confidence, and recommended checks.",
    "",
    `Engineer question: ${question || "Explain the trace failure and recommended troubleshooting actions."}`,
    "",
    "Decoded trace evidence:",
    JSON.stringify(
      {
        filename: result.filename,
        event_count: result.event_count,
        errors: result.errors,
        ai_context: context,
      },
      null,
      2,
    ),
  ].join("\n");
}

function maskTraceContext(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(maskTraceContext);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, maskIdentifierValue(key, maskTraceContext(child))]),
    );
  }
  if (typeof value === "string") {
    return maskIdentifierString(value);
  }
  return value;
}

function maskIdentifierValue(key: string, value: unknown): unknown {
  if (typeof value === "string" && ["imsi", "msisdn", "imei", "supi", "gpsi"].includes(key.toLowerCase())) {
    return maskDigits(value);
  }
  return value;
}

function maskIdentifierString(value: string) {
  return value
    .replace(/\b\d{14,16}\b/g, (match) => maskDigits(match))
    .replace(/\bimsi-\d{5,16}\b/g, (match) => `imsi-${maskDigits(match.slice(5))}`);
}

function maskDigits(value: string) {
  const digits = value.replace(/\D/g, "");
  if (digits.length <= 6) return "x".repeat(digits.length);
  return `${digits.slice(0, 5)}${"x".repeat(digits.length - 7)}${digits.slice(-2)}`;
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
