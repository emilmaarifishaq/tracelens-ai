"use client";

import { AlertCircle, Check, X, Zap } from "lucide-react";

export default function AuditPage() {
  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Zap size={28} />
          <div>
            <strong>TraceLens AI</strong>
            <span>Protocol troubleshooting</span>
          </div>
        </div>
        <nav>
          <a href="/"><Zap size={18} /> Analyzer</a>
          <a href="/error-breakdown"><AlertCircle size={18} /> Error Breakdown</a>
          <a href="/analytics"><Zap size={18} /> Analytics</a>
          <a href="/sla"><Zap size={18} /> SLA Tracking</a>
          <a href="/audit" className="active"><AlertCircle size={18} /> Audit Logs</a>
          <a href="/enterprise"><Zap size={18} /> Enterprise</a>
          <a href="/integrations"><Zap size={18} /> Integrations</a>
          <a href="/settings"><Zap size={18} /> Settings</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Audit Logs</h1>
            <p>Complete audit trail of all system activities</p>
          </div>
        </header>

        <section className="uploadPanel">
          <label style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", alignItems: "start" }}>
            <input
              type="text"
              placeholder="Search logs..."
              style={{
                padding: "8px 12px",
                border: "1px solid #ddd",
                borderRadius: "4px",
                fontSize: "14px",
              }}
            />
            <select
              style={{
                padding: "8px 12px",
                border: "1px solid #ddd",
                borderRadius: "4px",
                fontSize: "14px",
              }}
            >
              <option>All Actions</option>
              <option>Login</option>
              <option>Rule Created</option>
              <option>User Added</option>
            </select>
          </label>
        </section>

        <section className="contentGrid">
          <div className="panel">
            <div className="panelTitle">
              <h2>Activity Log</h2>
              <span>Recent 5 entries</span>
            </div>
            <div className="list">
              <article className="logEntry">
                <div style={{ display: "flex", gap: "12px", alignItems: "start" }}>
                  <Check size={18} style={{ color: "#22c55e", marginTop: "2px" }} />
                  <div style={{ flex: 1 }}>
                    <strong>Rule Modified</strong>
                    <span>2026-10-07 14:32:15 | john.analyst@acme.com</span>
                    <p>Updated threshold from 98% to 99%</p>
                  </div>
                  <span style={{ fontSize: "12px", color: "#22c55e", padding: "4px 8px", background: "#dcfce7", borderRadius: "4px" }}>SUCCESS</span>
                </div>
              </article>
              <article className="logEntry">
                <div style={{ display: "flex", gap: "12px", alignItems: "start" }}>
                  <Check size={18} style={{ color: "#22c55e", marginTop: "2px" }} />
                  <div style={{ flex: 1 }}>
                    <strong>User Added</strong>
                    <span>2026-10-07 14:28:42 | admin@acme.com</span>
                    <p>New analyst user added to tenant</p>
                  </div>
                  <span style={{ fontSize: "12px", color: "#22c55e", padding: "4px 8px", background: "#dcfce7", borderRadius: "4px" }}>SUCCESS</span>
                </div>
              </article>
              <article className="logEntry">
                <div style={{ display: "flex", gap: "12px", alignItems: "start" }}>
                  <AlertCircle size={18} style={{ color: "#eab308", marginTop: "2px" }} />
                  <div style={{ flex: 1 }}>
                    <strong>SLA Breach</strong>
                    <span>2026-10-07 14:15:30 | system</span>
                    <p>Network availability fell below 99.9%</p>
                  </div>
                  <span style={{ fontSize: "12px", color: "#eab308", padding: "4px 8px", background: "#fef3c7", borderRadius: "4px" }}>WARNING</span>
                </div>
              </article>
              <article className="logEntry">
                <div style={{ display: "flex", gap: "12px", alignItems: "start" }}>
                  <Check size={18} style={{ color: "#22c55e", marginTop: "2px" }} />
                  <div style={{ flex: 1 }}>
                    <strong>Trace Analyzed</strong>
                    <span>2026-10-07 14:02:18 | john.analyst@acme.com</span>
                    <p>1,245 events decoded, 3 errors found</p>
                  </div>
                  <span style={{ fontSize: "12px", color: "#22c55e", padding: "4px 8px", background: "#dcfce7", borderRadius: "4px" }}>SUCCESS</span>
                </div>
              </article>
              <article className="logEntry">
                <div style={{ display: "flex", gap: "12px", alignItems: "start" }}>
                  <Check size={18} style={{ color: "#22c55e", marginTop: "2px" }} />
                  <div style={{ flex: 1 }}>
                    <strong>Settings Updated</strong>
                    <span>2026-10-07 13:45:55 | admin@acme.com</span>
                    <p>HTTP/2 ports updated: 29502,29503,29504</p>
                  </div>
                  <span style={{ fontSize: "12px", color: "#22c55e", padding: "4px 8px", background: "#dcfce7", borderRadius: "4px" }}>SUCCESS</span>
                </div>
              </article>
            </div>
          </div>
        </section>
      </section>
    </main>
  );
}
