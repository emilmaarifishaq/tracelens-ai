"use client";

import { AlertTriangle, CheckCircle2, TrendingUp, Zap } from "lucide-react";

export default function SLAPage() {
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
          <a href="/error-breakdown"><TrendingUp size={18} /> Error Breakdown</a>
          <a href="/analytics"><Zap size={18} /> Analytics</a>
          <a href="/sla" className="active"><TrendingUp size={18} /> SLA Tracking</a>
          <a href="/audit"><Zap size={18} /> Audit Logs</a>
          <a href="/enterprise"><Zap size={18} /> Enterprise</a>
          <a href="/integrations"><Zap size={18} /> Integrations</a>
          <a href="/settings"><Zap size={18} /> Settings</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>SLA Tracking</h1>
            <p>Monitor service level compliance and breaches</p>
          </div>
        </header>

        <section className="metrics">
          <div className="panel">
            <h3>Overall Compliance</h3>
            <p className="large-value">98.7%</p>
            <span className="trend">Target: 99.0%</span>
          </div>
          <div className="panel">
            <h3>Compliant Policies</h3>
            <p className="large-value">12 / 15</p>
            <span className="trend">3 policies need attention</span>
          </div>
          <div className="panel">
            <h3>Breaches This Month</h3>
            <p className="large-value large-error">3</p>
            <span className="trend">-1 vs last month</span>
          </div>
          <div className="panel">
            <h3>MTTR</h3>
            <p className="large-value">18m</p>
            <span className="trend">Average resolution time</span>
          </div>
        </section>

        <section className="contentGrid">
          <div className="panel">
            <div className="panelTitle">
              <h2>Active SLA Policies</h2>
            </div>
            <div className="list">
              <div className="policy compliant">
                <div>
                  <strong>Registration Success Rate</strong>
                  <span>≥ 99.0% | Current: 99.4%</span>
                </div>
                <CheckCircle2 size={20} className="status-ok" />
              </div>
              <div className="policy compliant">
                <div>
                  <strong>Call Setup Latency</strong>
                  <span>≤ 250ms | Current: 245ms</span>
                </div>
                <CheckCircle2 size={20} className="status-ok" />
              </div>
              <div className="policy warning">
                <div>
                  <strong>Network Availability</strong>
                  <span>≥ 99.9% | Current: 98.8%</span>
                </div>
                <AlertTriangle size={20} className="status-warning" />
              </div>
              <div className="policy warning">
                <div>
                  <strong>Service Response Time</strong>
                  <span>≤ 100ms | Current: 112ms</span>
                </div>
                <AlertTriangle size={20} className="status-warning" />
              </div>
              <div className="policy compliant">
                <div>
                  <strong>DNS Resolution Time</strong>
                  <span>≤ 50ms | Current: 42ms</span>
                </div>
                <CheckCircle2 size={20} className="status-ok" />
              </div>
              <div className="policy compliant">
                <div>
                  <strong>Data Availability</strong>
                  <span>≥ 99.95% | Current: 99.98%</span>
                </div>
                <CheckCircle2 size={20} className="status-ok" />
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Recent Breaches</h2>
            </div>
            <div className="list">
              <article className="errorItem">
                <strong>Network Availability - Breach #3</strong>
                <span>2026-10-06 14:23 UTC | Duration: 45 minutes</span>
                <p>Network availability fell below 99.9% threshold</p>
              </article>
              <article className="errorItem">
                <strong>Service Response Time - Breach #2</strong>
                <span>2026-10-05 09:15 UTC | Duration: 12 minutes</span>
                <p>Average response time exceeded 100ms limit</p>
              </article>
              <article className="errorItem">
                <strong>Network Availability - Breach #1</strong>
                <span>2026-10-02 22:47 UTC | Duration: 58 minutes</span>
                <p>Brief outage detected affecting availability SLA</p>
              </article>
            </div>
          </div>
        </section>
      </section>
    </main>
  );
}
