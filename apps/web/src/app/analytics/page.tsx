"use client";

import { BarChart3, TrendingUp, Users, Zap } from "lucide-react";

export default function AnalyticsPage() {
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
          <a href="/"><Users size={18} /> Analyzer</a>
          <a href="/error-breakdown"><TrendingUp size={18} /> Error Breakdown</a>
          <a href="/analytics" className="active"><BarChart3 size={18} /> Analytics</a>
          <a href="/sla"><TrendingUp size={18} /> SLA Tracking</a>
          <a href="/audit"><Zap size={18} /> Audit Logs</a>
          <a href="/enterprise"><Zap size={18} /> Enterprise</a>
          <a href="/integrations"><Zap size={18} /> Integrations</a>
          <a href="/settings"><Zap size={18} /> Settings</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Analytics & KPIs</h1>
            <p>Track protocol performance, error rates, and operational metrics</p>
          </div>
        </header>

        <section className="metrics">
          <div className="panel">
            <h3>Total Traces Analyzed</h3>
            <p className="large-value">1,247</p>
            <span className="trend">↑ 12% vs last week</span>
          </div>
          <div className="panel">
            <h3>Success Rate</h3>
            <p className="large-value">98.4%</p>
            <span className="trend">↓ 0.2% vs last week</span>
          </div>
          <div className="panel">
            <h3>Avg Response Time</h3>
            <p className="large-value">245ms</p>
            <span className="trend">↑ 8ms vs last week</span>
          </div>
          <div className="panel">
            <h3>Active Sessions</h3>
            <p className="large-value">3,521</p>
            <span className="trend">↑ 15% vs last week</span>
          </div>
        </section>

        <section className="contentGrid">
          <div className="panel">
            <div className="panelTitle">
              <h2>Protocol Distribution</h2>
            </div>
            <div className="list">
              <div className="statRow">
                <span>HTTP</span>
                <strong>45.2%</strong>
                <span className="bar" style={{ width: "45%" }}></span>
              </div>
              <div className="statRow">
                <span>DNS</span>
                <strong>23.1%</strong>
                <span className="bar" style={{ width: "23%" }}></span>
              </div>
              <div className="statRow">
                <span>TLS</span>
                <strong>18.7%</strong>
                <span className="bar" style={{ width: "18%" }}></span>
              </div>
              <div className="statRow">
                <span>TCP</span>
                <strong>8.4%</strong>
                <span className="bar" style={{ width: "8%" }}></span>
              </div>
              <div className="statRow">
                <span>Other</span>
                <strong>4.6%</strong>
                <span className="bar" style={{ width: "4%" }}></span>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Error Categories</h2>
            </div>
            <div className="list">
              <div className="statRow">
                <span>Connection Errors</span>
                <strong>142</strong>
              </div>
              <div className="statRow">
                <span>DNS Resolution</span>
                <strong>87</strong>
              </div>
              <div className="statRow">
                <span>TLS Handshake</span>
                <strong>54</strong>
              </div>
              <div className="statRow">
                <span>Timeout Issues</span>
                <strong>31</strong>
              </div>
              <div className="statRow">
                <span>Protocol Errors</span>
                <strong>23</strong>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Top Issues</h2>
            </div>
            <div className="list">
              <article className="errorItem">
                <strong>DNS NXDOMAIN Errors</strong>
                <span>156 occurrences | 12.5% of traces</span>
                <p>Name server returned non-existent domain response</p>
              </article>
              <article className="errorItem">
                <strong>TCP Connection Reset</strong>
                <span>98 occurrences | 7.9% of traces</span>
                <p>Remote peer reset connection during handshake</p>
              </article>
              <article className="errorItem">
                <strong>TLS Certificate Error</strong>
                <span>67 occurrences | 5.4% of traces</span>
                <p>Certificate validation failed or expired</p>
              </article>
            </div>
          </div>
        </section>
      </section>
    </main>
  );
}
