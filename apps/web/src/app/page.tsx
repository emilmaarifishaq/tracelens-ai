"use client";

import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle2,
  Clipboard,
  Clock3,
  Download,
  ExternalLink,
  FileUp,
  Network,
  Search,
  Settings2,
  Shield,
} from "lucide-react";
import { toPng } from "html-to-image";
import { type RefObject, useMemo, useRef, useState } from "react";

import { ApiStatus } from "@/components/ApiStatus";
import { ProtocolFilter } from "@/components/ProtocolFilter";
import { SettingsPanel } from "@/components/SettingsPanel";

interface ProtocolStats {
  count: number;
  first_frame: number;
  last_frame: number;
  error_count: number;
  ports: string[];
}

interface AIProviderConfig {
  apiKey: string;
  provider: "openai" | "claude" | "azure" | "ollama" | "gemini" | "generic" | "rule-engine";
  model: string;
  webSearchEnabled: boolean;
  baseUrl?: string;
}

type TraceResult = {
  trace_id: string;
  filename: string;
  event_count: number;
  events: Array<Record<string, unknown>>;
  errors: Array<Record<string, unknown>>;
  warnings?: string[];
  ai_context: {
    trace_summary?: {
      event_count?: number;
      error_count?: number;
      protocols?: string[];
      participants?: Array<{ address: string; label: string }>;
      procedures?: Array<Record<string, unknown>>;
      procedure_groups?: Array<Record<string, unknown>>;
      failure_timeline?: Array<Record<string, unknown>>;
      host_flows?: Array<Record<string, unknown>>;
      session_drilldowns?: Array<Record<string, unknown>>;
      protocol_statistics?: Record<string, ProtocolStats>;
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

type HostSessionInsight = {
  whatHappened: string;
  likelyCause: string;
  nextChecks: string[];
  dnsIssues: number;
  redirects: number;
  httpErrors: number;
  tcpIssues: number;
};

export default function Home() {
  const [files, setFiles] = useState<File[]>([]);
  const [mappingFile, setMappingFile] = useState<File | null>(null);
  const [keylogFile, setKeylogFile] = useState<File | null>(null);
  const [result, setResult] = useState<TraceResult | null>(null);
  const [status, setStatus] = useState<"idle" | "uploading" | "error">("idle");
  const [uploadError, setUploadError] = useState<string | null>(null);
  const uploadRequestRef = useRef(0);
  const uploadAbortRef = useRef<AbortController | null>(null);
  const [http2Ports, setHttp2Ports] = useState("29502,29503,29504,29507,29509,29518");
  const [showHeartbeats, setShowHeartbeats] = useState(false);
  const [hideDuplicatePfcp, setHideDuplicatePfcp] = useState(true);
  const [selectedProtocols, setSelectedProtocols] = useState<Set<string>>(new Set());
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [selectedFrame, setSelectedFrame] = useState<string | null>(null);
  const [selectedHostFlow, setSelectedHostFlow] = useState<Record<string, unknown> | null>(null);
  const [searchText, setSearchText] = useState("");
  const [aiQuestion, setAiQuestion] = useState("Explain the failure and recommended troubleshooting steps.");
  const [maskIdentifiers, setMaskIdentifiers] = useState(true);
  const [aiStatus, setAiStatus] = useState<"idle" | "analyzing" | "error">("idle");
  const [aiAnalysis, setAiAnalysis] = useState<AiAnalysis | null>(null);
  const [chatGptStatus, setChatGptStatus] = useState<"idle" | "copied" | "error">("idle");
  const ladderRef = useRef<HTMLDivElement>(null);
  const [ladderExportStatus, setLadderExportStatus] = useState<"idle" | "exporting" | "error">("idle");
  const [aiConfig, setAiConfig] = useState<AIProviderConfig>({
    apiKey: "",
    provider: "rule-engine",
    model: "gpt-4o",
    webSearchEnabled: false,
    baseUrl: undefined,
  });

  const protocols = useMemo(
    () => result?.ai_context.trace_summary?.protocols?.join(", ") || "Waiting for trace",
    [result],
  );
  const errorFrames = useMemo(() => new Set((result?.errors || []).map((error) => String(error.frame))), [result]);
  const participants = result?.ai_context.trace_summary?.participants || [];
  const procedures = result?.ai_context.trace_summary?.procedures || [];
  const procedureGroups = result?.ai_context.trace_summary?.procedure_groups || [];
  const failureTimeline = result?.ai_context.trace_summary?.failure_timeline || [];
  const hostFlows = result?.ai_context.trace_summary?.host_flows || [];
  const sessionDrilldowns = result?.ai_context.trace_summary?.session_drilldowns || [];
  const primaryError = result?.errors[0] || null;
  const selectedHostDrilldown = useMemo(
    () => findSessionDrilldown(sessionDrilldowns, selectedHostFlow),
    [sessionDrilldowns, selectedHostFlow],
  );
  const selectedHostEvents = useMemo(
    () => {
      const drilldownEvents = selectedHostDrilldown?.events;
      if (Array.isArray(drilldownEvents)) return drilldownEvents as Array<Record<string, unknown>>;
      return getHostSessionEvents(result?.events || [], selectedHostFlow);
    },
    [result, selectedHostDrilldown, selectedHostFlow],
  );
  const selectedHostInsight = useMemo(
    () => drilldownToHostSessionInsight(selectedHostDrilldown) || buildHostSessionInsight(selectedHostFlow, selectedHostEvents),
    [selectedHostDrilldown, selectedHostEvents, selectedHostFlow],
  );
  const visibleEvents = useMemo(() => {
    const events = result?.events || [];
    const needle = searchText.trim().toLowerCase();
    return events.filter((event) => {
      const matchesProtocol = selectedProtocols.size === 0 || selectedProtocols.has(String(event.protocol));
      const matchesError = !errorsOnly || errorFrames.has(String(event.frame));
      const matchesSearch =
        !needle ||
        [
          event.frame,
          event.original_frame,
          event.protocol,
          event.protocols,
          event.message,
          event.host,
          event.url,
          event.redirect_url,
          event.http_location,
          event.dns_query,
          event.http_host,
          event.http_uri,
          event.tls_sni,
          event.sip_call_id,
          event.src,
          event.dst,
        ]
          .some((value) => String(value || "").toLowerCase().includes(needle));
      return matchesProtocol && matchesError && matchesSearch;
    });
  }, [errorFrames, errorsOnly, selectedProtocols, result, searchText]);
  const selectedEvent = useMemo(
    () => visibleEvents.find((event) => String(event.frame) === selectedFrame) || null,
    [selectedFrame, visibleEvents],
  );
  const explicitFilter = selectedProtocols.size > 0 || errorsOnly || Boolean(searchText.trim());

  const ladderEvents = useMemo(() => {
    if (explicitFilter) {
      return visibleEvents.slice(0, 240);
    }
    return pickImportantLadderEvents(visibleEvents, errorFrames, 240);
  }, [errorFrames, errorsOnly, selectedProtocols, searchText, visibleEvents]);

  async function uploadTrace() {
    if (!files.length) return;

    // Cancel any previous upload still in flight so its eventual
    // success/failure can't land after this one and clobber the UI --
    // e.g. a slow/corrupted large file finally erroring out after a
    // faster, later file already finished and displayed results.
    uploadAbortRef.current?.abort();
    const controller = new AbortController();
    uploadAbortRef.current = controller;
    const requestId = ++uploadRequestRef.current;

    setStatus("uploading");
    setUploadError(null);

    const body = new FormData();
    for (const selectedFile of files) {
      body.append("files", selectedFile);
    }
    if (mappingFile) {
      body.append("mapping_file", mappingFile);
    }
    if (keylogFile) {
      body.append("keylog_file", keylogFile);
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
        signal: controller.signal,
      });

      if (!response.ok) {
        const bodyText = await response.text();
        throw new Error(extractErrorDetail(bodyText));
      }

      const decoded = (await response.json()) as TraceResult;
      if (uploadRequestRef.current !== requestId) return;

      const initialHostFlow = decoded.ai_context.trace_summary?.host_flows?.[0] || null;
      setResult(decoded);
      setSelectedHostFlow(initialHostFlow);
      setSelectedFrame(initialHostFlow?.first_frame ? String(initialHostFlow.first_frame) : null);
      setAiAnalysis(null);
      setStatus("idle");
    } catch (error) {
      if (uploadRequestRef.current !== requestId) return;
      if (error instanceof DOMException && error.name === "AbortError") return;
      setUploadError(error instanceof Error ? error.message : "Decode failed. Check API status and TShark availability.");
      setStatus("error");
    }
  }

  function extractErrorDetail(bodyText: string): string {
    try {
      const parsed = JSON.parse(bodyText) as { detail?: unknown };
      if (typeof parsed.detail === "string" && parsed.detail.trim()) {
        return parsed.detail;
      }
    } catch {
      // not JSON -- fall through to raw text
    }
    return bodyText.trim() || "Decode failed. Check API status and TShark availability.";
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
          use_ai: aiConfig.provider !== "rule-engine",
          mask_identifiers: maskIdentifiers,
          provider: aiConfig.provider,
          ...(aiConfig.provider !== "rule-engine" && {
            api_key: aiConfig.apiKey,
            model: aiConfig.model,
            web_search_enabled: aiConfig.webSearchEnabled,
            base_url: aiConfig.baseUrl,
          }),
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

  async function exportLadderImage() {
    const node = ladderRef.current;
    if (!node) return;

    setLadderExportStatus("exporting");

    // The ladder scrolls internally (max-height + overflow: auto) so more
    // than a screenful of events fit on screen -- export the whole flow,
    // not just what's currently visible, by temporarily lifting that
    // clipping before capturing.
    const originalMaxHeight = node.style.maxHeight;
    const originalOverflow = node.style.overflow;
    node.style.maxHeight = "none";
    node.style.overflow = "visible";

    try {
      const dataUrl = await toPng(node, { backgroundColor: "#ffffff", pixelRatio: 2 });
      const baseName = (result?.filename || "trace").replace(/[^a-z0-9_-]+/gi, "_");
      const link = document.createElement("a");
      link.href = dataUrl;
      link.download = `tracelens-flow-ladder-${baseName}.png`;
      link.click();
      setLadderExportStatus("idle");
    } catch {
      setLadderExportStatus("error");
    } finally {
      node.style.maxHeight = originalMaxHeight;
      node.style.overflow = originalOverflow;
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
          <div className="flex flex-col items-end gap-3">
            <ApiStatus
              apiBaseUrl={
                process.env.NEXT_PUBLIC_API_BASE_URL ||
                `${typeof window !== "undefined" ? window.location.protocol : "http:"}//${typeof window !== "undefined" ? window.location.hostname : "localhost"}:8000`
              }
            />
            <div className="flex gap-2">
              <SettingsPanel
                config={aiConfig}
                onConfigChange={setAiConfig}
                onClose={() => {}}
              />
              <button className="primary" onClick={uploadTrace} disabled={!files.length || status === "uploading"}>
                <FileUp size={18} />
                {status === "uploading" ? "Decoding" : "Analyze"}
              </button>
            </div>
          </div>
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
          {status === "error" && (
            <p className="errorText">{uploadError || "Decode failed. Check API status and TShark availability."}</p>
          )}
          {result?.warnings?.map((warning) => (
            <p className="errorText" key={warning}>
              {warning}
            </p>
          ))}
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
          <label>
            <span>TLS keylog file</span>
            <input
              type="file"
              accept=".log,.keylog,.txt"
              onChange={(event) => setKeylogFile(event.target.files?.[0] || null)}
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
          <Metric label="Issues found" value={String(result?.errors.length || 0)} />
          <Metric label="Flow groups" value={String(procedureGroups.length || procedures.length)} />
          <Metric label="Protocols" value={protocols} />
        </section>

        <section className="troubleshootingBoard">
          <FailureFocus error={primaryError} procedures={procedures} />
          <ProcedureOverview groups={procedureGroups} procedures={procedures} />
        </section>

        <section className="troubleshootingGrid">
          <HostFlowSummary
            flows={hostFlows}
            selectedFlow={selectedHostFlow}
            onSelectFlow={(flow) => {
              setSelectedHostFlow(flow);
              setSelectedFrame(flow.first_frame ? String(flow.first_frame) : null);
              setSearchText(String(flow.host || firstString(flow.urls) || ""));
            }}
          />
          <FailureTimeline timeline={failureTimeline} onSelectFrame={setSelectedFrame} />
        </section>

        <HostSessionDrilldown
          flow={selectedHostFlow}
          events={selectedHostEvents}
          insight={selectedHostInsight}
          eventTotal={Number(selectedHostDrilldown?.session_event_count || selectedHostEvents.length)}
          errorFrames={errorFrames}
          onSelectFrame={setSelectedFrame}
        />

        <section className="panel ladderPanel">
          <div className="panelTitle">
            <h2>Flow Ladder</h2>
            <div className="filters">
              <label className="searchBox">
                <Search size={16} />
                <input
                  value={searchText}
                  placeholder="Search host, URL, frame, IP"
                  onChange={(event) => setSearchText(event.target.value)}
                />
              </label>
              <ProtocolFilter
                protocols={result?.ai_context.trace_summary?.protocols || []}
                protocolStats={result?.ai_context.trace_summary?.protocol_statistics}
                selectedProtocols={selectedProtocols}
                onProtocolChange={(protocol, selected) => {
                  const newSelection = new Set(selectedProtocols);
                  if (selected) {
                    newSelection.add(protocol);
                  } else {
                    newSelection.delete(protocol);
                  }
                  setSelectedProtocols(newSelection);
                }}
                onSelectAll={() => {
                  const allProtocols = result?.ai_context.trace_summary?.protocols || [];
                  setSelectedProtocols(new Set(allProtocols));
                }}
                onClearAll={() => {
                  setSelectedProtocols(new Set());
                }}
              />
              <label className="inlineCheck">
                <input
                  type="checkbox"
                  checked={errorsOnly}
                  onChange={(event) => setErrorsOnly(event.target.checked)}
                />
                <span>Errors only</span>
              </label>
              <button
                onClick={exportLadderImage}
                disabled={!ladderEvents.length || ladderExportStatus === "exporting"}
              >
                <Download size={16} />
                {ladderExportStatus === "exporting" ? "Exporting" : "Export PNG"}
              </button>
            </div>
          </div>
          <p className="ladderScope">
            Showing {ladderEvents.length} important flow events from {visibleEvents.length} matching decoded events.
            {ladderExportStatus === "error" && <span className="errorText"> Export failed -- try again.</span>}
          </p>
          <Ladder
            containerRef={ladderRef}
            events={ladderEvents}
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
              {aiStatus === "analyzing" ? "Explaining" : getExplainButtonLabel(aiConfig.provider)}
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
              <h2>Detected Issues</h2>
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
              {!result?.errors.length && <p className="empty">No decoded issues yet.</p>}
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Recent Events</h2>
              <span>{visibleEvents.length ? `${visibleEvents.length} matching events` : "No matching events"}</span>
            </div>
            <div className="table">
              <div className="row head">
                <span>Frame</span>
                <span>Protocol</span>
                <span>Source</span>
                <span>Destination</span>
                <span>Host / URL</span>
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
                  <span>{String(event.redirect_url || event.url || event.host || "-")}</span>
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

function HostFlowSummary({
  flows,
  selectedFlow,
  onSelectFlow,
}: {
  flows: Array<Record<string, unknown>>;
  selectedFlow: Record<string, unknown> | null;
  onSelectFlow: (flow: Record<string, unknown>) => void;
}) {
  const visibleFlows = flows.slice(0, 8);

  return (
    <section className="panel troubleshootingPanel">
      <div className="panelTitle">
        <h2>Host Flow Summary</h2>
        <span>{flows.length ? `${flows.length} observed targets` : "No host target yet"}</span>
      </div>
      <div className="compactList">
        {visibleFlows.map((flow) => (
          <button
            className={`compactItem ${String(flow.status || "")} ${
              selectedFlow && sameHostFlow(flow, selectedFlow) ? "selected" : ""
            }`}
            key={`${flow.host}-${flow.protocol}-${flow.first_frame}`}
            onClick={() => onSelectFlow(flow)}
          >
            <strong>{String(flow.host || "-")}</strong>
            <span>
              {String(flow.protocol || "-")} | Frames {String(flow.first_frame || "-")} to {String(flow.last_frame || "-")} |{" "}
              {String(flow.event_count || 0)} events
            </span>
            <small>
              {String(flow.status || "observed")}
              {flow.issue_count ? ` | ${String(flow.issue_count)} issues` : ""}
              {flow.redirect_count ? ` | ${String(flow.redirect_count)} redirects` : ""}
              {Array.isArray(flow.status_codes) && flow.status_codes.length ? ` | codes ${flow.status_codes.join(", ")}` : ""}
            </small>
            <small>
              {Array.isArray(flow.sources) && flow.sources.length ? `src ${flow.sources.join(", ")}` : "src -"}
              {" | "}
              {Array.isArray(flow.destinations) && flow.destinations.length ? `dst ${flow.destinations.join(", ")}` : "dst -"}
            </small>
            {Array.isArray(flow.urls) && flow.urls.length ? <em>{String(flow.urls[0])}</em> : null}
          </button>
        ))}
        {!visibleFlows.length && <p className="empty compactEmpty">No DNS, HTTP, TLS, SIP, MQTT, or QUIC host observed yet.</p>}
      </div>
    </section>
  );
}

function HostSessionDrilldown({
  flow,
  events,
  insight,
  eventTotal,
  errorFrames,
  onSelectFrame,
}: {
  flow: Record<string, unknown> | null;
  events: Array<Record<string, unknown>>;
  insight: HostSessionInsight | null;
  eventTotal: number;
  errorFrames: Set<string>;
  onSelectFrame: (frame: string) => void;
}) {
  if (!flow || !insight) {
    return (
      <section className="panel drilldownPanel">
        <div className="panelTitle">
          <h2>Host Session Drilldown</h2>
          <span>Select a host flow</span>
        </div>
        <p className="empty compactEmpty">Select a host from Host Flow Summary to inspect related DNS, HTTP, TLS, and TCP evidence.</p>
      </section>
    );
  }

  return (
    <section className="panel drilldownPanel">
      <div className="panelTitle">
        <h2>Host Session Drilldown</h2>
        <span>
          {String(flow.host || "-")} | {eventTotal} related events
        </span>
      </div>
      <div className="drilldownGrid">
        <article className="drilldownNarrative">
          <h3>What Happened</h3>
          <p>{insight.whatHappened}</p>
          <h3>Likely Cause</h3>
          <p>{insight.likelyCause}</p>
          <h3>Next Check</h3>
          <ul>
            {insight.nextChecks.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </article>
        <div className="drilldownFacts">
          <Stat label="DNS issues" value={String(insight.dnsIssues)} />
          <Stat label="Redirects" value={String(insight.redirects)} />
          <Stat label="HTTP errors" value={String(insight.httpErrors)} />
          <Stat label="TCP issues" value={String(insight.tcpIssues)} />
        </div>
      </div>
      <div className="sessionEvents">
        <div className="sessionHeader">
          <span>Frame</span>
          <span>Protocol</span>
          <span>Evidence</span>
          <span>Host / URL</span>
        </div>
        {events.slice(0, 24).map((event) => (
          <button
            className={`sessionRow ${errorFrames.has(String(event.frame)) ? "rowError" : ""}`}
            key={`${event.frame}-${event.protocol}-${event.message}`}
            onClick={() => onSelectFrame(String(event.frame))}
          >
            <span>{String(event.frame || "-")}</span>
            <span>{String(event.protocol || event.protocols || "-")}</span>
            <span>{sessionEvidence(event)}</span>
            <span>{String(event.redirect_url || event.url || event.host || event.dns_query || "-")}</span>
          </button>
        ))}
        {!events.length && <p className="empty compactEmpty">No matching session events found for this host.</p>}
      </div>
    </section>
  );
}

function FailureTimeline({
  timeline,
  onSelectFrame,
}: {
  timeline: Array<Record<string, unknown>>;
  onSelectFrame: (frame: string) => void;
}) {
  const visibleItems = timeline.slice(0, 8);

  return (
    <section className="panel troubleshootingPanel">
      <div className="panelTitle">
        <h2>Failure Timeline</h2>
        <span>{timeline.length ? `${timeline.length} notable events` : "No failure timeline yet"}</span>
      </div>
      <div className="compactList">
        {visibleItems.map((item) => (
          <button
            className={`compactItem ${String(item.severity || "")}`}
            key={`${item.frame}-${item.reason}`}
            onClick={() => onSelectFrame(String(item.frame))}
          >
            <strong>
              Frame {String(item.frame || "-")} | {String(item.reason || item.protocol || "-")}
            </strong>
            <span>{String(item.message || "-")}</span>
            <small>
              {String(item.src || "-")} to {String(item.dst || "-")}
              {item.host ? ` | ${String(item.host)}` : ""}
            </small>
            {item.url ? <em>{String(item.url)}</em> : null}
          </button>
        ))}
        {!visibleItems.length && <p className="empty compactEmpty">No redirect, protocol error, or explicit failure observed yet.</p>}
      </div>
    </section>
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
  containerRef,
  events,
  errorFrames,
  participants,
  selectedFrame,
  onSelectFrame,
}: {
  containerRef: RefObject<HTMLDivElement | null>;
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
    <div className="sequenceDiagram" ref={containerRef}>
      <div className="sequenceHeader" style={{ gridTemplateColumns }}>
        {lanes.map((participant) => (
          <div className="sequenceParticipant" key={participant.address}>
            <strong>{participant.label}</strong>
            <span>{participant.address}</span>
          </div>
        ))}
      </div>
      {events.map((event) => {
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
                  {event.host ? ` | Host ${String(event.host)}` : ""}
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
    ["Host", event.host],
    ["URL", event.url],
    ["URL source", event.url_source],
    ["URL inferred", event.url_inferred],
    ["Redirect URL", event.redirect_url],
    ["TEID", event.teid],
    ["Sequence", event.sequence_number],
    ["Cause", event.cause_code],
    ["IMSI", event.imsi],
    ["APN", event.apn],
    ["DNS query", event.dns_query],
    ["HTTP host", event.http_host],
    ["HTTP URI", event.http_uri],
    ["HTTP Location", event.http_location],
    ["TLS SNI", event.tls_sni],
    ["SIP Call-ID", event.sip_call_id],
    ["MQTT topic", event.mqtt_topic],
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

function firstString(value: unknown): string {
  return Array.isArray(value) && typeof value[0] === "string" ? value[0] : "";
}

function sameHostFlow(left: Record<string, unknown>, right: Record<string, unknown>) {
  return (
    String(left.host || "") === String(right.host || "") &&
    String(left.protocol || "") === String(right.protocol || "") &&
    String(left.first_frame || "") === String(right.first_frame || "")
  );
}

function getHostSessionEvents(events: Array<Record<string, unknown>>, flow: Record<string, unknown> | null) {
  if (!flow) return [];
  return events
    .filter((event) => eventMatchesHostFlow(event, flow))
    .sort((left, right) => frameNumber(left) - frameNumber(right))
    .slice(0, 240);
}

function findSessionDrilldown(
  drilldowns: Array<Record<string, unknown>>,
  flow: Record<string, unknown> | null,
) {
  if (!flow) return null;
  return drilldowns.find((drilldown) => sameHostFlow(drilldown, flow)) || null;
}

function drilldownToHostSessionInsight(drilldown: Record<string, unknown> | null): HostSessionInsight | null {
  if (!drilldown) return null;
  return {
    whatHappened: String(drilldown.what_happened || ""),
    likelyCause: String(drilldown.likely_cause || ""),
    nextChecks: asStringList(drilldown.next_checks),
    dnsIssues: Number(drilldown.dns_issues || 0),
    redirects: Number(drilldown.redirects || 0),
    httpErrors: Number(drilldown.http_errors || 0),
    tcpIssues: Number(drilldown.tcp_issues || 0),
  };
}

function eventMatchesHostFlow(event: Record<string, unknown>, flow: Record<string, unknown>) {
  const target = String(flow.host || "").toLowerCase();
  const urls = asStringList(flow.urls).map((url) => url.toLowerCase());
  const eventText = [
    event.host,
    event.url,
    event.redirect_url,
    event.http_host,
    event.http_uri,
    event.http_location,
    event.dns_query,
    event.tls_sni,
    event.quic_sni,
    event.sip_uri,
  ]
    .map((value) => String(value || "").toLowerCase())
    .join(" ");
  const compactEventText = eventText.trim();

  const textualMatch =
    Boolean(target && eventText.includes(target)) ||
    urls.some((url) => Boolean(compactEventText) && (eventText.includes(url) || url.includes(compactEventText)));
  if (textualMatch) return true;

  const sources = asStringList(flow.sources);
  const destinations = asStringList(flow.destinations);
  const protocol = String(event.protocol || "");
  const endpointMatch =
    isAddressLike(target) &&
    [...sources, ...destinations].some((address) => [event.src, event.dst].map(String).includes(address));
  return endpointMatch && ["DNS", "HTTP", "TLS", "QUIC", "TCP"].includes(protocol);
}

function isAddressLike(value: string) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(":");
}

function buildHostSessionInsight(
  flow: Record<string, unknown> | null,
  events: Array<Record<string, unknown>>,
): HostSessionInsight | null {
  if (!flow) return null;

  const redirects = events.filter((event) => event.redirect_url).length;
  const dnsIssues = events.filter((event) => {
    const code = String(event.dns_response_code || "");
    return String(event.protocol || "") === "DNS" && Boolean(code) && code !== "0";
  }).length;
  const httpErrors = events.filter((event) => {
    const status = Number(event.http_status_code || 0);
    return status >= 400;
  }).length;
  const tcpIssues = events.filter((event) => event.tcp_reset || event.is_retransmission).length;
  const tlsIssues = events.filter((event) => event.tls_alert).length;
  const httpsHosts = events.filter((event) => event.url_inferred).length;
  const statusCodes = Array.from(
    new Set(events.map((event) => event.http_status_code || event.dns_response_code).filter(Boolean).map(String)),
  ).slice(0, 6);
  const target = String(flow.host || "selected target");
  const frameRange = `frames ${String(flow.first_frame || "-")} to ${String(flow.last_frame || "-")}`;

  const whatHappened = [
    `${target} was observed in ${events.length} related DNS/HTTP/TLS/TCP events across ${frameRange}.`,
    redirects ? `${redirects} HTTP redirect response${redirects > 1 ? "s" : ""} pointed the client to a new URL.` : "",
    httpErrors ? `${httpErrors} HTTP error response${httpErrors > 1 ? "s" : ""} appeared in the same session.` : "",
    dnsIssues ? `${dnsIssues} DNS response issue${dnsIssues > 1 ? "s" : ""} appeared for this target or its related lookup.` : "",
    tlsIssues ? `${tlsIssues} TLS alert${tlsIssues > 1 ? "s" : ""} appeared after the host was identified.` : "",
    tcpIssues ? `${tcpIssues} TCP reset/retransmission event${tcpIssues > 1 ? "s" : ""} appeared in the path.` : "",
    httpsHosts ? `${httpsHosts} encrypted HTTPS host observation${httpsHosts > 1 ? "s were" : " was"} inferred from TLS/QUIC fields.` : "",
    statusCodes.length ? `Observed status/code values: ${statusCodes.join(", ")}.` : "",
  ]
    .filter(Boolean)
    .join(" ");

  let likelyCause = "TraceLens did not find an explicit failure for this host; review the surrounding packets for missing responses or unexpected routing.";
  if (redirects && /captive|portal|login|walled/i.test(`${target} ${firstString(flow.urls)}`)) {
    likelyCause = "The client traffic is being intercepted by a captive portal or walled-garden policy before normal internet access is allowed.";
  } else if (redirects) {
    likelyCause = "The server or gateway is intentionally redirecting the client, so the next troubleshooting point is the Location URL and policy that triggered it.";
  } else if (httpErrors) {
    likelyCause = "The target service or proxy returned an application-layer error, so the failure is likely above basic IP reachability.";
  } else if (dnsIssues) {
    likelyCause = "Name resolution failed or returned a non-success response before the application session could complete.";
  } else if (tlsIssues) {
    likelyCause = "The TCP path reached the encrypted service, but TLS negotiation reported an alert.";
  } else if (tcpIssues) {
    likelyCause = "The session shows transport instability, reset, or retransmission before a clean application exchange.";
  }

  const nextChecks = buildHostNextChecks({ redirects, dnsIssues, httpErrors, tcpIssues, tlsIssues, target });
  return { whatHappened, likelyCause, nextChecks, dnsIssues, redirects, httpErrors, tcpIssues };
}

function buildHostNextChecks({
  redirects,
  dnsIssues,
  httpErrors,
  tcpIssues,
  tlsIssues,
  target,
}: {
  redirects: number;
  dnsIssues: number;
  httpErrors: number;
  tcpIssues: number;
  tlsIssues: number;
  target: string;
}) {
  if (redirects) {
    return [
      `Open the first redirect frame and verify the Location URL for ${target}.`,
      "Confirm whether captive portal, proxy, quota, or subscriber policy should redirect this client.",
      "Compare DNS result, original Host header, and redirected host to confirm the access path.",
    ];
  }
  if (dnsIssues) {
    return [
      `Check DNS server response code and queried name for ${target}.`,
      "Verify client DNS configuration, resolver reachability, and split-DNS/captive policy.",
      "Look for a later successful DNS answer before judging the application flow.",
    ];
  }
  if (httpErrors) {
    return [
      `Review HTTP status, Host, URI, and response frame for ${target}.`,
      "Check proxy, ACS/API endpoint, authentication, and service-side logs for the same timestamp.",
      "Confirm whether the client should receive this status code in the tested scenario.",
    ];
  }
  if (tlsIssues) {
    return [
      `Check TLS alert frame and SNI/ALPN information for ${target}.`,
      "Verify certificate, TLS version, cipher compatibility, and middlebox inspection policy.",
      "Correlate with TCP resets or retransmissions near the alert.",
    ];
  }
  if (tcpIssues) {
    return [
      `Inspect TCP reset/retransmission frames around ${target}.`,
      "Check packet loss, firewall resets, asymmetric routing, and MTU/MSS behavior.",
      "Confirm whether the server responds after SYN and whether the session closes cleanly.",
    ];
  }
  return [
    `Review first and last frames for ${target}.`,
    "Check whether DNS, TCP setup, TLS host, and application request all appear in order.",
    "Use the host search filter to compare this target with a successful target in the same PCAP.",
  ];
}

function sessionEvidence(event: Record<string, unknown>) {
  if (event.evidence) return String(event.evidence);
  const status = event.http_status_code || event.sip_status_code || event.dns_response_code;
  const parts = [
    event.message || event.protocols,
    status ? `code ${String(status)}` : "",
    event.tcp_reset ? "TCP reset" : "",
    event.is_retransmission ? "retransmission" : "",
    event.tls_alert ? `TLS alert ${String(event.tls_alert)}` : "",
  ].filter(Boolean);
  return parts.length ? parts.join(" | ") : "-";
}

function pickImportantLadderEvents(events: Array<Record<string, unknown>>, errorFrames: Set<string>, limit: number) {
  return events
    .map((event, index) => ({ event, index, score: ladderImportanceScore(event, errorFrames) }))
    .filter((item) => item.score > 0)
    .sort((left, right) => right.score - left.score || frameNumber(left.event) - frameNumber(right.event) || left.index - right.index)
    .slice(0, limit)
    .sort((left, right) => frameNumber(left.event) - frameNumber(right.event) || left.index - right.index)
    .map((item) => item.event);
}

function ladderImportanceScore(event: Record<string, unknown>, errorFrames: Set<string>) {
  if (errorFrames.has(String(event.frame))) return 110;
  if (event.redirect_url) return 100;
  if (event.url) return 92;
  if (event.cause_code || event.result_code || event.experimental_result_code) return 90;

  const protocol = String(event.protocol || "");
  const message = String(event.message || "");
  const dnsCode = String(event.dns_response_code || "");
  const httpCode = Number(event.http_status_code || 0);
  const sipCode = Number(event.sip_status_code || 0);

  if (protocol === "HTTP" && httpCode >= 300) return 96;
  if (protocol === "SIP" && sipCode >= 300) return 94;
  if (protocol === "DNS" && dnsCode && dnsCode !== "0") return 88;
  if (protocol === "TCP" && event.tcp_reset) return 84;
  if (protocol === "TLS" && event.tls_alert) return 82;

  if (["GTPv1-C", "GTPv2-C", "GTP-U", "Diameter", "PFCP", "S1AP", "NGAP", "DHCP", "SIP"].includes(protocol)) {
    return 72;
  }
  if (protocol === "DNS") {
    return event.dns_response ? 58 : 0;
  }
  if (protocol === "HTTP") {
    return event.http_method ? 68 : 0;
  }
  if (protocol === "TLS") {
    return event.tls_sni ? 62 : 0;
  }
  if (protocol === "QUIC") {
    return event.quic_sni ? 60 : 0;
  }
  if (protocol === "TCP") {
    return event.is_retransmission ? 38 : 0;
  }
  if (protocol === "ICMP") {
    return /unreachable|time exceeded/i.test(message) ? 56 : 0;
  }
  return 0;
}

function frameNumber(event: Record<string, unknown>) {
  return Number(event.frame || 0);
}

function explanationModeLabel(analysis: AiAnalysis) {
  if (analysis.ai_used) {
    return `${analysis.provider} | ${analysis.mode}`;
  }
  return "TraceLens rule-engine | offline";
}

function getExplainButtonLabel(provider: AIProviderConfig["provider"]): string {
  switch (provider) {
    case "rule-engine":
      return "Explain Locally";
    case "openai":
      return "Explain with OpenAI";
    case "claude":
      return "Explain with Claude";
    case "gemini":
      return "Explain with Gemini";
    case "azure":
      return "Explain with Azure OpenAI";
    case "ollama":
      return "Explain with Ollama";
    case "generic":
      return "Explain with AI";
    default:
      return "Explain Locally";
  }
}

function buildChatGptPrompt(result: TraceResult, question: string, maskIdentifiers: boolean) {
  const trimmedContext = trimAiContextForPrompt(result.ai_context);
  const context = maskIdentifiers ? (maskTraceContext(trimmedContext) as Record<string, unknown>) : trimmedContext;
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
        ai_context: context,
      },
      null,
      2,
    ),
  ].join("\n");
}

// The AI's job is to explain a failure the rule engine already detected (each
// entry in detected_errors already carries its own root_cause and
// recommended_checks), not to re-derive one from the whole trace structure.
// result.ai_context.events is every decoded frame with no cap -- for a large
// capture that alone is millions of tokens. Mirrors trim_ai_context_for_prompt
// in apps/api/app/services/ai_analysis.py; keep both in sync.
function trimAiContextForPrompt(aiContext: TraceResult["ai_context"]): Record<string, unknown> {
  const traceSummary = aiContext.trace_summary || {};
  const rawContext = aiContext as unknown as { detected_errors?: unknown[] };
  const detectedErrors = Array.isArray(rawContext.detected_errors) ? rawContext.detected_errors.slice(0, 10) : [];

  const minimal: Record<string, unknown> = {
    event_count: traceSummary.event_count,
    protocols_observed: traceSummary.protocols,
    detected_errors: detectedErrors,
  };

  if (detectedErrors.length === 0) {
    minimal.failure_timeline_sample = (traceSummary.failure_timeline || []).slice(0, 5);
    const sessionDrilldowns = traceSummary.session_drilldowns || [];
    if (sessionDrilldowns.length > 0) {
      const topHost = sessionDrilldowns[0] as Record<string, unknown>;
      minimal.most_active_host = {
        host: topHost.host,
        what_happened: topHost.what_happened,
        likely_cause: topHost.likely_cause,
        next_checks: topHost.next_checks,
      };
    }
  }

  return minimal;
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

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="miniStat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
