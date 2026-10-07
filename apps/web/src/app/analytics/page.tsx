"use client";

import { BarChart3, TrendingUp, Users, AlertCircle } from "lucide-react";

export default function AnalyticsPage() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold mb-2">Analytics & Insights</h2>
        <p className="text-slate-400">
          Key Performance Indicators and detailed metrics
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* KPI Cards */}
        {[
          {
            title: "Registration Success Rate",
            value: "99.4%",
            target: "99.0%",
            status: "above",
            icon: <TrendingUp className="w-6 h-6" />,
          },
          {
            title: "Average Call Setup Time",
            value: "245ms",
            target: "200ms",
            status: "below",
            icon: <AlertCircle className="w-6 h-6" />,
          },
          {
            title: "Active UE Sessions",
            value: "12,847",
            trend: "+5.3% vs yesterday",
            icon: <Users className="w-6 h-6" />,
          },
          {
            title: "Protocol Errors",
            value: "142",
            trend: "-8.2% vs yesterday",
            icon: <BarChart3 className="w-6 h-6" />,
          },
        ].map((kpi, idx) => (
          <div key={idx} className="bg-slate-800 border border-slate-700 rounded-xl p-6">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-2">{kpi.title}</p>
                <p className="text-3xl font-bold mb-2">{kpi.value}</p>
                {kpi.target && (
                  <p
                    className={`text-sm ${
                      kpi.status === "above" ? "text-green-400" : "text-orange-400"
                    }`}
                  >
                    Target: {kpi.target}
                  </p>
                )}
                {kpi.trend && <p className="text-sm text-slate-400">{kpi.trend}</p>}
              </div>
              <div className="text-blue-400">{kpi.icon}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Detailed Metrics */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4">Protocol Breakdown</h3>
        <div className="space-y-3">
          {[
            { name: "NAS (5G)", percentage: 42, count: 5400 },
            { name: "NGAP", percentage: 28, count: 3600 },
            { name: "GTP-U", percentage: 18, count: 2300 },
            { name: "PFCP", percentage: 12, count: 1500 },
          ].map((proto, idx) => (
            <div key={idx}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm font-medium">{proto.name}</p>
                <span className="text-sm text-slate-400">{proto.count} events</span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-blue-500 to-blue-600 h-2 rounded-full"
                  style={{ width: `${proto.percentage}%` }}
                ></div>
              </div>
              <p className="text-xs text-slate-400 mt-1">{proto.percentage}%</p>
            </div>
          ))}
        </div>
      </div>

      {/* Time Series Data */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4">Success Rate Trend (Last 7 Days)</h3>
        <div className="h-48 flex items-end gap-4 justify-around">
          {[98.2, 98.9, 99.1, 98.7, 99.4, 99.2, 99.4].map((rate, day) => (
            <div key={day} className="flex flex-col items-center gap-2 flex-1">
              <div className="flex-1 flex items-end">
                <div
                  className="w-full bg-gradient-to-t from-blue-500 to-blue-400 rounded-t"
                  style={{ height: `${(rate / 100) * 100}%` }}
                ></div>
              </div>
              <p className="text-xs text-slate-400">{rate}%</p>
              <p className="text-xs text-slate-500">Day {day + 1}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
