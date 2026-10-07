"use client";

import { Save, Zap } from "lucide-react";
import { useState } from "react";

export default function SettingsPage() {
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

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
          <a href="/enterprise"><Zap size={18} /> Enterprise</a>
          <a href="/integrations"><Zap size={18} /> Integrations</a>
          <a href="/settings" className="active"><Zap size={18} /> Settings</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Settings</h1>
            <p>Configure system and user preferences</p>
          </div>
        </header>

        <section className="contentGrid">
          <div className="panel">
            <div className="panelTitle">
              <h2>API Configuration</h2>
            </div>
            <div className="settingsPanel">
              <label>
                <span>API Base URL</span>
                <input type="text" defaultValue="http://localhost:8000" />
                <p style={{ fontSize: "12px", color: "#666", marginTop: "4px" }}>Backend API endpoint for all requests</p>
              </label>
              <label>
                <span>API Timeout (seconds)</span>
                <input type="number" defaultValue="30" />
              </label>
              <label>
                <span>Trace Upload Max Size (MB)</span>
                <input type="number" defaultValue="500" />
              </label>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Display Settings</h2>
            </div>
            <div className="settingsPanel">
              <label>
                <span>Theme</span>
                <select>
                  <option>Dark (Current)</option>
                  <option>Light</option>
                  <option>Auto</option>
                </select>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input type="checkbox" defaultChecked />
                <span>Enable Animations</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input type="checkbox" defaultChecked />
                <span>Compact Mode</span>
              </label>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Notifications</h2>
            </div>
            <div className="settingsPanel">
              <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input type="checkbox" defaultChecked />
                <span>SLA Breaches</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input type="checkbox" defaultChecked />
                <span>Trace Errors</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input type="checkbox" defaultChecked />
                <span>System Alerts</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input type="checkbox" />
                <span>User Activity</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input type="checkbox" defaultChecked />
                <span>Integration Status</span>
              </label>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Security</h2>
            </div>
            <div className="settingsPanel">
              <label>
                <span>Session Timeout (minutes)</span>
                <input type="number" defaultValue="60" />
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input type="checkbox" defaultChecked />
                <span>Require 2FA for Admin Access</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input type="checkbox" defaultChecked />
                <span>Enable Audit Logging</span>
              </label>
              <button style={{ marginTop: "8px", padding: "8px 12px", background: "#3b82f6", color: "white", border: "none", borderRadius: "4px", cursor: "pointer", fontSize: "14px" }}>
                Change Password
              </button>
            </div>
          </div>

          <div className="panel">
            <div className="panelTitle">
              <h2>Data Management</h2>
            </div>
            <div className="settingsPanel" style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              <button style={{ padding: "8px 12px", background: "#6b7280", color: "white", border: "none", borderRadius: "4px", cursor: "pointer", fontSize: "14px", textAlign: "left" }}>
                Export Settings
              </button>
              <button style={{ padding: "8px 12px", background: "#6b7280", color: "white", border: "none", borderRadius: "4px", cursor: "pointer", fontSize: "14px", textAlign: "left" }}>
                Clear Cache
              </button>
              <button style={{ padding: "8px 12px", background: "#7f1d1d", color: "#fca5a5", border: "none", borderRadius: "4px", cursor: "pointer", fontSize: "14px", textAlign: "left" }}>
                Reset to Defaults
              </button>
            </div>
          </div>
        </section>

        <section style={{ padding: "20px", display: "flex", gap: "16px", alignItems: "center" }}>
          <button
            onClick={handleSave}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "10px 20px",
              background: "linear-gradient(to right, #2563eb, #1d4ed8)",
              color: "white",
              border: "none",
              borderRadius: "6px",
              cursor: "pointer",
              fontSize: "14px",
              fontWeight: "600",
            }}
          >
            <Save size={16} />
            Save Settings
          </button>
          {saved && <p style={{ color: "#22c55e", fontSize: "14px" }}>✓ Saved successfully</p>}
        </section>
      </section>
    </main>
  );
}
