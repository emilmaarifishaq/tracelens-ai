"use client";

import { Brain, TrendingUp, AlertTriangle, Zap } from "lucide-react";

export default function MLPage() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold mb-2">ML Features</h2>
        <p className="text-slate-400">
          Machine learning forecasting, anomaly detection, and pattern analysis
        </p>
      </div>

      {/* Forecasting */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <TrendingUp className="w-6 h-6 text-blue-400" />
          <h3 className="text-lg font-semibold">Time-Series Forecasting</h3>
        </div>

        <div className="space-y-6">
          {[
            {
              metric: "Registration Success Rate (24h forecast)",
              current: "99.4%",
              forecast: "99.2%",
              confidence: "94%",
            },
            {
              metric: "Average Call Setup Time (24h forecast)",
              current: "245ms",
              forecast: "258ms",
              confidence: "91%",
            },
          ].map((item, idx) => (
            <div key={idx} className="p-4 bg-slate-700 rounded-lg">
              <p className="text-sm font-medium mb-3">{item.metric}</p>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <p className="text-xs text-slate-400 mb-1">Current</p>
                  <p className="text-lg font-bold">{item.current}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400 mb-1">Forecast</p>
                  <p className="text-lg font-bold text-orange-400">{item.forecast}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400 mb-1">Confidence</p>
                  <p className="text-lg font-bold text-green-400">{item.confidence}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Anomaly Detection */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <AlertTriangle className="w-6 h-6 text-red-400" />
          <h3 className="text-lg font-semibold">Adaptive Anomaly Detection</h3>
        </div>

        <div className="space-y-3">
          {[
            {
              type: "High Registration Failures",
              severity: "Critical",
              threshold: "> 1.5%",
              current: "2.1%",
              status: "TRIGGERED",
            },
            {
              type: "Protocol Timeouts",
              severity: "Warning",
              threshold: "> 500ms",
              current: "485ms",
              status: "NORMAL",
            },
            {
              type: "Call Setup Spike",
              severity: "Info",
              threshold: "> 2x baseline",
              current: "1.2x",
              status: "NORMAL",
            },
          ].map((anomaly, idx) => (
            <div key={idx} className="p-4 bg-slate-700 rounded-lg border-l-4 border-slate-600">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-medium text-sm">{anomaly.type}</p>
                  <p className="text-xs text-slate-400 mt-1">
                    Threshold: {anomaly.threshold}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-xs font-medium mb-1">{anomaly.severity}</p>
                  <p
                    className={`text-sm font-bold ${
                      anomaly.status === "TRIGGERED"
                        ? "text-red-400"
                        : "text-green-400"
                    }`}
                  >
                    {anomaly.current}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Pattern Detection */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <Brain className="w-6 h-6 text-purple-400" />
          <h3 className="text-lg font-semibold">Pattern Detection</h3>
        </div>

        <div className="space-y-3">
          {[
            {
              pattern: "Daily Traffic Cycle",
              type: "Cyclic",
              confidence: "0.92",
              frequency: "Daily",
              impact: "Operational",
            },
            {
              pattern: "Registration Success Trend",
              type: "Trend",
              confidence: "0.87",
              frequency: "Weekly",
              impact: "Strategic",
            },
            {
              pattern: "Latency Burst Events",
              type: "Burst",
              confidence: "0.95",
              frequency: "One-time",
              impact: "Critical",
            },
          ].map((item, idx) => (
            <div key={idx} className="p-4 bg-slate-700 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <p className="font-medium text-sm">{item.pattern}</p>
                <span className="px-2 py-1 bg-blue-600 text-white text-xs rounded">
                  {item.type}
                </span>
              </div>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div>
                  <p className="text-xs text-slate-400">Confidence</p>
                  <p className="font-semibold">{item.confidence}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400">Frequency</p>
                  <p className="font-semibold">{item.frequency}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400">Impact</p>
                  <p className="font-semibold">{item.impact}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Root Cause Clustering */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <Zap className="w-6 h-6 text-yellow-400" />
          <h3 className="text-lg font-semibold">Root Cause Clustering</h3>
        </div>

        <div className="space-y-3">
          {[
            {
              cluster: "NGAP Issues",
              percentage: 45,
              count: 324,
              causes: ["NGAP_20", "NGAP_21", "NGAP_24"],
            },
            {
              cluster: "NAS Protocol",
              percentage: 32,
              count: 230,
              causes: ["NAS_1", "NAS_20"],
            },
            {
              cluster: "GTP Tunneling",
              percentage: 23,
              count: 165,
              causes: ["GTP_1", "GTP_5"],
            },
          ].map((cluster, idx) => (
            <div key={idx} className="p-4 bg-slate-700 rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <p className="font-medium text-sm">{cluster.cluster}</p>
                <p className="text-lg font-bold text-blue-400">{cluster.count}</p>
              </div>
              <div className="w-full bg-slate-600 rounded-full h-2 mb-2">
                <div
                  className="bg-gradient-to-r from-blue-500 to-blue-600 h-2 rounded-full"
                  style={{ width: `${cluster.percentage}%` }}
                ></div>
              </div>
              <div className="flex gap-2 flex-wrap">
                {cluster.causes.map((cause, cidx) => (
                  <span key={cidx} className="text-xs bg-slate-600 px-2 py-1 rounded">
                    {cause}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
