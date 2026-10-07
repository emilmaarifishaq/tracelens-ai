"use client";

import { Shield, Users, Zap } from "lucide-react";

export default function EnterprisePage() {
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
          <a href="/analytics"><Zap size={18} /> Analytics</a>
          <a href="/sla"><Zap size={18} /> SLA Tracking</a>
          <a href="/audit"><Zap size={18} /> Audit Logs</a>
          <a href="/enterprise" className="active"><Shield size={18} /> Enterprise</a>
          <a href="/integrations"><Zap size={18} /> Integrations</a>
          <a href="/settings"><Zap size={18} /> Settings</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Enterprise Management</h1>
            <p>Multi-tenant management, users, and role-based access control</p>
          </div>
        </header>

        <section className="contentGrid">
          <div className="panel">
            <div className="panelTitle">
              <h2>Tenants</h2>
              <span>3 active tenants</span>
            </div>
            <div className="list">
              <div className="tenantItem">
                <div>
                  <strong>Acme Corp</strong>
                  <span>Enterprise | 24 users | 45.2K traces</span>
                </div>
                <span style={{ fontSize: "12px", color: "#22c55e", padding: "4px 8px", background: "#dcfce7", borderRadius: "4px" }}>ACTIVE</span>
              </div>
              <div className="tenantItem">
                <div>
                  <strong>TechVision Inc</strong>
                  <span>Pro | 8 users | 12.4K traces</span>
                </div>
                <span style={{ fontSize: "12px", color: "#22c55e", padding: "4px 8px", background: "#dcfce7", borderRadius: "4px" }}>ACTIVE</span>
              </div>
              <div className="tenantItem">
                <div>
                  <strong>Global Networks</strong>
                  <span>Enterprise | 18 users | 78.9K traces</span>
                </div>
                <span style={{ fontSize: "12px", color: "#22c55e", padding: "4px 8px", background: "#dcfce7", borderRadius: "4px" }}>ACTIVE</span>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Users (Acme Corp)</h2>
              <span>24 total users</span>
            </div>
            <div className="list">
              <div className="userItem">
                <div>
                  <strong>John Analyst</strong>
                  <span>john@acme.com | Data Analyst | Joined 2026-08-15</span>
                </div>
              </div>
              <div className="userItem">
                <div>
                  <strong>Sarah Operations</strong>
                  <span>sarah@acme.com | Operations Engineer | Joined 2026-09-02</span>
                </div>
              </div>
              <div className="userItem">
                <div>
                  <strong>Admin User</strong>
                  <span>admin@acme.com | Tenant Admin | Joined 2026-07-10</span>
                </div>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Roles & Permissions</h2>
            </div>
            <div className="list">
              <article className="roleItem">
                <strong>Tenant Admin</strong>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "8px" }}>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>read_traces</span>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>modify_rules</span>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>manage_users</span>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>view_dashboards</span>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>admin_access</span>
                </div>
              </article>
              <article className="roleItem">
                <strong>Data Analyst</strong>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "8px" }}>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>read_traces</span>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>view_dashboards</span>
                </div>
              </article>
              <article className="roleItem">
                <strong>Operations</strong>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "8px" }}>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>read_traces</span>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>modify_rules</span>
                  <span style={{ fontSize: "12px", padding: "4px 8px", background: "#dbeafe", color: "#0284c7", borderRadius: "4px" }}>view_dashboards</span>
                </div>
              </article>
            </div>
          </div>
        </section>
      </section>
    </main>
  );
}
