"use client";

import { Zap, Plus, CheckCircle2, AlertCircle, Trash2 } from "lucide-react";

export default function IntegrationsPage() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold mb-2">Integrations</h2>
        <p className="text-slate-400">
          Connect external systems and manage data flows
        </p>
      </div>

      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold">Active Integrations</h3>
        <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition-colors">
          <Plus className="w-4 h-4" />
          Add Integration
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {[
          {
            name: "Kafka Cluster",
            type: "kafka",
            status: "connected",
            config: "brokers: kafka1:9092, kafka2:9092",
            lastSync: "2 seconds ago",
          },
          {
            name: "Elasticsearch",
            type: "elasticsearch",
            status: "connected",
            config: "host: elastic.internal:9200",
            lastSync: "5 seconds ago",
          },
          {
            name: "Datadog",
            type: "datadog",
            status: "error",
            config: "org: acme, api-key: ***",
            lastSync: "15 minutes ago (failed)",
          },
          {
            name: "Splunk",
            type: "splunk",
            status: "disconnected",
            config: "hec: splunk.acme.com:8088",
            lastSync: "Never",
          },
        ].map((integration, idx) => (
          <div
            key={idx}
            className={`bg-slate-800 border rounded-xl p-6 ${
              integration.status === "error"
                ? "border-red-700/30"
                : integration.status === "disconnected"
                ? "border-slate-700"
                : "border-slate-700"
            }`}
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <p className="font-semibold text-lg">{integration.name}</p>
                <p className="text-sm text-slate-400 mt-1 font-mono">
                  {integration.type}
                </p>
              </div>
              <button className="p-2 hover:bg-slate-700 rounded-lg transition-colors">
                <Trash2 className="w-4 h-4 text-red-400" />
              </button>
            </div>

            <div className="space-y-3 mb-4">
              <div>
                <p className="text-xs text-slate-400 mb-1">Configuration</p>
                <p className="text-sm text-slate-300 font-mono break-words">
                  {integration.config}
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-400 mb-1">Last Sync</p>
                <p className="text-sm text-slate-300">{integration.lastSync}</p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {integration.status === "connected" && (
                <>
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  <span className="text-sm text-green-400">Connected</span>
                </>
              )}
              {integration.status === "error" && (
                <>
                  <AlertCircle className="w-4 h-4 text-red-400" />
                  <span className="text-sm text-red-400">Error</span>
                </>
              )}
              {integration.status === "disconnected" && (
                <>
                  <AlertCircle className="w-4 h-4 text-slate-400" />
                  <span className="text-sm text-slate-400">Disconnected</span>
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Available Integrations */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Available Integrations</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            "Kafka",
            "Elasticsearch",
            "Splunk",
            "Datadog",
            "AWS S3",
            "Google Cloud Storage",
            "Azure Blob Storage",
            "SIEM Solutions",
          ].map((service, idx) => (
            <div
              key={idx}
              className="bg-slate-800 border border-slate-700 rounded-lg p-4 flex items-center justify-between hover:border-slate-600 transition-colors cursor-pointer"
            >
              <p className="font-medium">{service}</p>
              <Plus className="w-4 h-4 text-slate-400" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
