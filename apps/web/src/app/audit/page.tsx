"use client";

import { AlertCircle, Check, X, LogIn, LogOut, Settings } from "lucide-react";

export default function AuditPage() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold mb-2">Audit Logs</h2>
        <p className="text-slate-400">Complete audit trail of all system activities</p>
      </div>

      <div className="flex gap-4 mb-6">
        <input
          type="text"
          placeholder="Search logs..."
          className="flex-1 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm"
        />
        <select className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm">
          <option>All Actions</option>
          <option>Login</option>
          <option>Rule Created</option>
          <option>User Added</option>
        </select>
      </div>

      <div className="space-y-2">
        {[
          {
            time: "2026-10-07 14:32:15",
            user: "john.analyst@acme.com",
            action: "Rule Modified",
            resource: "rule_registration_success",
            result: "success",
            details: "Updated threshold from 98% to 99%",
          },
          {
            time: "2026-10-07 14:28:42",
            user: "admin@acme.com",
            action: "User Added",
            resource: "user_sarah_ops",
            result: "success",
            details: "New analyst user added to tenant",
          },
          {
            time: "2026-10-07 14:15:30",
            user: "system",
            action: "SLA Breach",
            resource: "policy_availability",
            result: "warning",
            details: "Network availability fell below 99.9%",
          },
          {
            time: "2026-10-07 14:02:18",
            user: "john.analyst@acme.com",
            action: "Trace Analyzed",
            resource: "trace_5g_reg_flow",
            result: "success",
            details: "1,245 events decoded, 3 errors found",
          },
          {
            time: "2026-10-07 13:45:55",
            user: "admin@acme.com",
            action: "Settings Updated",
            resource: "tenant_config",
            result: "success",
            details: "HTTP/2 ports updated: 29502,29503,29504",
          },
        ].map((log, idx) => (
          <div
            key={idx}
            className="bg-slate-800 border border-slate-700 rounded-lg p-4 hover:border-slate-600 transition-colors"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-xs text-slate-400">{log.time}</span>
                  {log.result === "success" && (
                    <Check className="w-4 h-4 text-green-400" />
                  )}
                  {log.result === "warning" && (
                    <AlertCircle className="w-4 h-4 text-yellow-400" />
                  )}
                  {log.result === "error" && (
                    <X className="w-4 h-4 text-red-400" />
                  )}
                  <span className="font-medium text-sm">{log.action}</span>
                </div>
                <p className="text-sm text-slate-400 mb-1">
                  User: <span className="text-slate-300">{log.user}</span>
                </p>
                <p className="text-sm text-slate-400 mb-2">
                  Resource: <span className="font-mono text-blue-400">{log.resource}</span>
                </p>
                <p className="text-sm text-slate-500">{log.details}</p>
              </div>
              <div className="ml-4">
                <span
                  className={`text-xs font-medium px-2 py-1 rounded ${
                    log.result === "success"
                      ? "bg-green-600/20 text-green-400"
                      : log.result === "warning"
                      ? "bg-yellow-600/20 text-yellow-400"
                      : "bg-red-600/20 text-red-400"
                  }`}
                >
                  {log.result.toUpperCase()}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
