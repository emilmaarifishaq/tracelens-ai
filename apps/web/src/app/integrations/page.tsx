"use client";

import { CheckCircle2, AlertCircle, Zap } from "lucide-react";

export default function IntegrationsPage() {
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
          <a href="/error-breakdown"><Zap size={18} /> Error Breakdown</a>
          <a href="/analytics"><Zap size={18} /> Analytics</a>
          <a href="/sla"><Zap size={18} /> SLA Tracking</a>
          <a href="/audit"><Zap size={18} /> Audit Logs</a>
          <a href="/enterprise"><Zap size={18} /> Enterprise</a>
          <a href="/integrations" className="active"><Zap size={18} /> Integrations</a>
          <a href="/settings"><Zap size={18} /> Settings</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Integrations</h1>
            <p>Connect external systems and manage data flows</p>
          </div>
        </header>

        <section className="contentGrid">
          <div className="panel">
            <div className="panelTitle">
              <h2>Active Integrations</h2>
              <span>4 connected</span>
            </div>
            <div className="list">
              <div style={{ padding: "16px", borderBottom: "1px solid #ddd", display: "flex", justifyContent: "space-between", alignItems: "start" }}>
                <div style={{ flex: 1 }}>
                  <strong>Kafka Cluster</strong>
                  <span style={{ display: "block", fontSize: "12px", color: "#666", marginTop: "4px" }}>brokers: kafka1:9092, kafka2:9092</span>
                  <span style={{ display: "block", fontSize: "12px", color: "#666", marginTop: "2px" }}>Last sync: 2 seconds ago</span>
                </div>
                <CheckCircle2 size={20} style={{ color: "#22c55e" }} />
              </div>
              <div style={{ padding: "16px", borderBottom: "1px solid #ddd", display: "flex", justifyContent: "space-between", alignItems: "start" }}>
                <div style={{ flex: 1 }}>
                  <strong>Elasticsearch</strong>
                  <span style={{ display: "block", fontSize: "12px", color: "#666", marginTop: "4px" }}>host: elastic.internal:9200</span>
                  <span style={{ display: "block", fontSize: "12px", color: "#666", marginTop: "2px" }}>Last sync: 5 seconds ago</span>
                </div>
                <CheckCircle2 size={20} style={{ color: "#22c55e" }} />
              </div>
              <div style={{ padding: "16px", borderBottom: "1px solid #ddd", display: "flex", justifyContent: "space-between", alignItems: "start" }}>
                <div style={{ flex: 1 }}>
                  <strong>Datadog</strong>
                  <span style={{ display: "block", fontSize: "12px", color: "#666", marginTop: "4px" }}>org: acme, api-key: ***</span>
                  <span style={{ display: "block", fontSize: "12px", color: "#666", marginTop: "2px" }}>Last sync: 15 minutes ago (failed)</span>
                </div>
                <AlertCircle size={20} style={{ color: "#ef4444" }} />
              </div>
              <div style={{ padding: "16px", display: "flex", justifyContent: "space-between", alignItems: "start" }}>
                <div style={{ flex: 1 }}>
                  <strong>Splunk</strong>
                  <span style={{ display: "block", fontSize: "12px", color: "#666", marginTop: "4px" }}>hec: splunk.acme.com:8088</span>
                  <span style={{ display: "block", fontSize: "12px", color: "#666", marginTop: "2px" }}>Last sync: Never</span>
                </div>
                <AlertCircle size={20} style={{ color: "#999" }} />
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Available Integrations</h2>
            </div>
            <div className="list">
              {["Kafka", "Elasticsearch", "Splunk", "Datadog", "AWS S3", "Google Cloud Storage", "Azure Blob Storage", "SIEM Solutions"].map((service) => (
                <div key={service} style={{ padding: "12px", borderBottom: "1px solid #ddd", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span>{service}</span>
                  <button style={{ padding: "4px 8px", background: "#3b82f6", color: "white", border: "none", borderRadius: "4px", cursor: "pointer", fontSize: "12px" }}>Add</button>
                </div>
              ))}
            </div>
          </div>
        </section>
      </section>
    </main>
  );
}
