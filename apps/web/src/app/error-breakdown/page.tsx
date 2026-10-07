"use client";

import { AlertTriangle, ChevronRight, Filter, Network, Activity, Brain, Clipboard, Settings2, Zap, Shield } from "lucide-react";
import { useState } from "react";

export default function ErrorBreakdownPage() {
  const [selectedCause, setSelectedCause] = useState<number | null>(null);
  const [sortBy, setSortBy] = useState<"count" | "percentage">("count");

  const errorData = [
    {
      code: 24,
      name: "failure-in-radio-interface-procedure",
      description: "RRC reconfiguration or re-establishment failing during session",
      count: 177,
      percentage: 35.4,
      timeline: "20-60s after context setup",
      affectedUEs: 45,
      severity: "high",
      frames: [1234, 1256, 1278, 1301, 1324],
    },
    {
      code: 21,
      name: "radio-connection-with-UE-lost",
      description: "RLF (Radio Link Failure) or coverage loss",
      count: 93,
      percentage: 18.6,
      timeline: "60-100s after setup (peak)",
      affectedUEs: 23,
      severity: "high",
      frames: [2145, 2167, 2189, 2201],
    },
    {
      code: 20,
      name: "user-inactivity",
      description: "UE or network initiated release due to inactivity",
      count: 89,
      percentage: 17.8,
      timeline: "Normal session termination",
      affectedUEs: 31,
      severity: "medium",
      frames: [3021, 3045, 3089, 3124],
    },
    {
      code: 15,
      name: "access-barred",
      description: "Access class restrictions or barring applied",
      count: 67,
      percentage: 13.4,
      timeline: "Immediate on attachment",
      affectedUEs: 18,
      severity: "high",
      frames: [1089, 1156, 1223, 1290],
    },
    {
      code: 10,
      name: "network-failure",
      description: "Generic network/AMF rejection",
      count: 45,
      percentage: 9.0,
      timeline: "During procedure execution",
      affectedUEs: 12,
      severity: "medium",
      frames: [2345, 2412, 2478, 2534],
    },
    {
      code: 5,
      name: "nas-error",
      description: "NAS protocol error or invalid message",
      count: 29,
      percentage: 5.8,
      timeline: "During NAS exchange",
      affectedUEs: 8,
      severity: "low",
      frames: [1678, 1712, 1745, 1789],
    },
  ];

  const sortedErrors = [...errorData].sort((a, b) => {
    if (sortBy === "count") {
      return b.count - a.count;
    }
    return b.percentage - a.percentage;
  });

  const totalErrors = errorData.reduce((sum, e) => sum + e.count, 0);
  const totalAffectedUEs = new Set(errorData.flatMap((e) => Array(e.affectedUEs).fill(0))).size;

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
          <a href="/"><Activity size={18} /> Analyzer</a>
          <a href="/error-breakdown" className="active"><AlertTriangle size={18} /> Error Breakdown</a>
          <a href="/analytics"><Brain size={18} /> Analytics</a>
          <a href="/sla"><AlertTriangle size={18} /> SLA Tracking</a>
          <a href="/audit"><Clipboard size={18} /> Audit Logs</a>
          <a href="/enterprise"><Shield size={18} /> Enterprise</a>
          <a href="/integrations"><Zap size={18} /> Integrations</a>
          <a href="/settings"><Settings2 size={18} /> Settings</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Error Breakdown Analysis</h1>
            <p>Complete breakdown of all errors by cause code - select to analyze further</p>
          </div>
        </header>

        <section className="metrics">
          <div className="panel">
            <h3>Total Errors</h3>
            <p className="large-value">{totalErrors}</p>
            <span className="trend">Across entire trace</span>
          </div>
          <div className="panel">
            <h3>Unique Cause Codes</h3>
            <p className="large-value">{errorData.length}</p>
            <span className="trend">Different error types</span>
          </div>
          <div className="panel">
            <h3>Affected UEs</h3>
            <p className="large-value">{totalAffectedUEs}</p>
            <span className="trend">Unique subscribers impacted</span>
          </div>
          <div className="panel">
            <h3>Top Issue</h3>
            <p className="large-value" style={{ fontSize: "20px" }}>Cause {sortedErrors[0].code}</p>
            <span className="trend">{sortedErrors[0].percentage.toFixed(1)}% of all errors</span>
          </div>
        </section>

        <section className="contentGrid">
          <div className="panel" style={{ gridColumn: "1 / -1" }}>
            <div className="panelTitle">
              <h2>Errors by Cause Code</h2>
              <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                <Filter size={16} />
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as "count" | "percentage")}
                  style={{
                    padding: "6px 12px",
                    border: "1px solid #ddd",
                    borderRadius: "4px",
                    fontSize: "13px",
                  }}
                >
                  <option value="count">Sort by Count</option>
                  <option value="percentage">Sort by Percentage</option>
                </select>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(500px, 1fr))", gap: "16px", padding: "16px" }}>
              {sortedErrors.map((error) => (
                <div
                  key={error.code}
                  onClick={() => setSelectedCause(error.code)}
                  style={{
                    padding: "16px",
                    border: selectedCause === error.code ? "2px solid #3b82f6" : "1px solid #ddd",
                    borderRadius: "8px",
                    cursor: "pointer",
                    background: selectedCause === error.code ? "#eff6ff" : "#f9fafb",
                    transition: "all 0.2s",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", marginBottom: "12px" }}>
                    <div>
                      <strong style={{ fontSize: "16px" }}>Cause Code {error.code}</strong>
                      <p style={{ fontSize: "13px", color: "#666", marginTop: "4px" }}>{error.name}</p>
                    </div>
                    <div
                      style={{
                        padding: "4px 12px",
                        borderRadius: "20px",
                        fontSize: "13px",
                        fontWeight: "600",
                        background: error.severity === "high" ? "#fee2e2" : error.severity === "medium" ? "#fef3c7" : "#e0f2fe",
                        color: error.severity === "high" ? "#991b1b" : error.severity === "medium" ? "#92400e" : "#075985",
                      }}
                    >
                      {error.severity.toUpperCase()}
                    </div>
                  </div>

                  <p style={{ fontSize: "14px", color: "#555", marginBottom: "12px" }}>{error.description}</p>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
                    <div>
                      <span style={{ fontSize: "12px", color: "#666" }}>Total Occurrences</span>
                      <p style={{ fontSize: "18px", fontWeight: "600", marginTop: "4px" }}>{error.count}</p>
                      <div style={{ marginTop: "8px", height: "4px", background: "#e5e7eb", borderRadius: "2px", overflow: "hidden" }}>
                        <div
                          style={{
                            height: "100%",
                            background: error.severity === "high" ? "#ef4444" : error.severity === "medium" ? "#f59e0b" : "#3b82f6",
                            width: `${error.percentage}%`,
                          }}
                        ></div>
                      </div>
                      <span style={{ fontSize: "12px", color: "#666", marginTop: "4px" }}>{error.percentage.toFixed(1)}% of total</span>
                    </div>
                    <div>
                      <span style={{ fontSize: "12px", color: "#666" }}>Affected UEs</span>
                      <p style={{ fontSize: "18px", fontWeight: "600", marginTop: "4px" }}>{error.affectedUEs}</p>
                      <span style={{ fontSize: "12px", color: "#666", marginTop: "8px" }}>Unique subscribers</span>
                    </div>
                  </div>

                  <div style={{ borderTop: "1px solid #e5e7eb", paddingTop: "12px" }}>
                    <div style={{ marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", color: "#666" }}>Timeline</span>
                      <p style={{ fontSize: "13px", marginTop: "4px" }}>{error.timeline}</p>
                    </div>
                    <div>
                      <span style={{ fontSize: "12px", color: "#666" }}>Key Frames</span>
                      <p style={{ fontSize: "12px", marginTop: "4px", fontFamily: "monospace" }}>{error.frames.join(", ")}</p>
                    </div>
                  </div>

                  {selectedCause === error.code && (
                    <button
                      style={{
                        marginTop: "12px",
                        width: "100%",
                        padding: "10px",
                        background: "#3b82f6",
                        color: "white",
                        border: "none",
                        borderRadius: "6px",
                        cursor: "pointer",
                        fontSize: "14px",
                        fontWeight: "600",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        gap: "8px",
                      }}
                    >
                      Analyze Cause {error.code} <ChevronRight size={16} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {selectedCause && (
            <div className="panel" style={{ gridColumn: "1 / -1" }}>
              <div className="panelTitle">
                <h2>Selected Cause: {selectedCause}</h2>
              </div>
              <div style={{ padding: "16px" }}>
                <p style={{ marginBottom: "16px" }}>
                  {errorData.find((e) => e.code === selectedCause)?.description}
                </p>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "16px", marginBottom: "16px" }}>
                  <div>
                    <span style={{ fontSize: "12px", color: "#666" }}>Count</span>
                    <p style={{ fontSize: "24px", fontWeight: "600", marginTop: "8px" }}>
                      {errorData.find((e) => e.code === selectedCause)?.count}
                    </p>
                  </div>
                  <div>
                    <span style={{ fontSize: "12px", color: "#666" }}>Percentage</span>
                    <p style={{ fontSize: "24px", fontWeight: "600", marginTop: "8px" }}>
                      {errorData.find((e) => e.code === selectedCause)?.percentage.toFixed(1)}%
                    </p>
                  </div>
                  <div>
                    <span style={{ fontSize: "12px", color: "#666" }}>Affected UEs</span>
                    <p style={{ fontSize: "24px", fontWeight: "600", marginTop: "8px" }}>
                      {errorData.find((e) => e.code === selectedCause)?.affectedUEs}
                    </p>
                  </div>
                </div>
                <p style={{ fontSize: "14px", color: "#555", marginBottom: "16px" }}>
                  <strong>Recommended Next Step:</strong> Use the Analyzer to view detailed frames for this cause code, or compare with other causes to identify patterns.
                </p>
              </div>
            </div>
          )}
        </section>
      </section>
    </main>
  );
}
