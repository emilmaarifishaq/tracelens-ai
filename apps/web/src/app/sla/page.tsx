"use client";

import { TrendingUp, AlertTriangle, CheckCircle2 } from "lucide-react";

export default function SLAPage() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold mb-2">SLA Tracking</h2>
        <p className="text-slate-400">Service level agreement compliance and breaches</p>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
          <p className="text-slate-400 text-sm mb-2">Overall Compliance</p>
          <p className="text-4xl font-bold text-green-400">98.7%</p>
          <p className="text-xs text-slate-400 mt-2">Target: 99.0%</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
          <p className="text-slate-400 text-sm mb-2">Compliant Policies</p>
          <p className="text-4xl font-bold">12</p>
          <p className="text-xs text-slate-400 mt-2">/ 15 policies</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
          <p className="text-slate-400 text-sm mb-2">Breaches This Month</p>
          <p className="text-4xl font-bold text-red-400">3</p>
          <p className="text-xs text-slate-400 mt-2">-1 vs last month</p>
        </div>
      </div>

      {/* SLA Policies */}
      <div className="space-y-3">
        <h3 className="text-lg font-semibold">Active SLA Policies</h3>
        {[
          {
            name: "Registration Success Rate",
            metric: "registration_success_rate",
            threshold: ">= 99.0%",
            current: "99.4%",
            status: "compliant",
            measurement: "Hourly",
          },
          {
            name: "Call Setup Latency",
            metric: "call_setup_latency",
            threshold: "<= 250ms",
            current: "245ms",
            status: "compliant",
            measurement: "Hourly",
          },
          {
            name: "Network Availability",
            metric: "network_availability",
            threshold: ">= 99.9%",
            current: "98.8%",
            status: "breach",
            measurement: "Continuous",
          },
          {
            name: "Service Response Time",
            metric: "response_time",
            threshold: "<= 100ms",
            current: "112ms",
            status: "warning",
            measurement: "Real-time",
          },
        ].map((policy, idx) => (
          <div
            key={idx}
            className={`bg-slate-800 border rounded-xl p-6 ${
              policy.status === "breach"
                ? "border-red-700/30"
                : policy.status === "warning"
                ? "border-yellow-700/30"
                : "border-slate-700"
            }`}
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <p className="font-semibold mb-1">{policy.name}</p>
                <p className="text-xs text-slate-400">{policy.metric}</p>
              </div>
              <div className="flex gap-2 items-center">
                {policy.status === "compliant" && (
                  <CheckCircle2 className="w-5 h-5 text-green-400" />
                )}
                {policy.status === "breach" && (
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                )}
                {policy.status === "warning" && (
                  <AlertTriangle className="w-5 h-5 text-yellow-400" />
                )}
                <span
                  className={`text-xs font-medium px-2 py-1 rounded ${
                    policy.status === "compliant"
                      ? "bg-green-600/20 text-green-400"
                      : policy.status === "breach"
                      ? "bg-red-600/20 text-red-400"
                      : "bg-yellow-600/20 text-yellow-400"
                  }`}
                >
                  {policy.status === "compliant"
                    ? "COMPLIANT"
                    : policy.status === "breach"
                    ? "BREACH"
                    : "WARNING"}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <p className="text-xs text-slate-400 mb-1">Threshold</p>
                <p className="text-sm font-semibold">{policy.threshold}</p>
              </div>
              <div>
                <p className="text-xs text-slate-400 mb-1">Current Value</p>
                <p
                  className={`text-sm font-semibold ${
                    policy.status === "compliant"
                      ? "text-green-400"
                      : policy.status === "breach"
                      ? "text-red-400"
                      : "text-yellow-400"
                  }`}
                >
                  {policy.current}
                </p>
              </div>
            </div>

            <p className="text-xs text-slate-400">
              Measurement: {policy.measurement}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}
