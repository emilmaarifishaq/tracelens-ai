"use client";

import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle2,
  TrendingUp,
  Users,
  Shield,
  Zap,
  BarChart3,
  Clock,
  AlertCircle,
  ArrowRight,
} from "lucide-react";
import Link from "next/link";
import { useState, useEffect } from "react";

interface StatCard {
  title: string;
  value: string | number;
  change: string;
  icon: React.ReactNode;
  color: string;
}

interface RecentActivity {
  id: string;
  type: string;
  description: string;
  timestamp: string;
  severity: "info" | "warning" | "error";
}

export default function Dashboard() {
  const [stats, setStats] = useState<StatCard[]>([]);
  const [activities, setActivities] = useState<RecentActivity[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate fetching data from backend
    setTimeout(() => {
      setStats([
        {
          title: "Total Traces Analyzed",
          value: "2,847",
          change: "+12% from last week",
          icon: <Activity className="w-6 h-6" />,
          color: "from-blue-500 to-blue-600",
        },
        {
          title: "Success Rate",
          value: "99.4%",
          change: "+0.5% improvement",
          icon: <CheckCircle2 className="w-6 h-6" />,
          color: "from-green-500 to-green-600",
        },
        {
          title: "Active Tenants",
          value: "45",
          change: "+3 new this month",
          icon: <Shield className="w-6 h-6" />,
          color: "from-purple-500 to-purple-600",
        },
        {
          title: "SLA Compliance",
          value: "98.7%",
          change: "-0.1% below target",
          icon: <TrendingUp className="w-6 h-6" />,
          color: "from-orange-500 to-orange-600",
        },
      ]);

      setActivities([
        {
          id: "1",
          type: "Trace Analyzed",
          description: "5G registration flow analyzed - 1,245 events decoded",
          timestamp: "2 minutes ago",
          severity: "info",
        },
        {
          id: "2",
          type: "Anomaly Detected",
          description: "Unusual protocol pattern detected in NAS layer",
          timestamp: "15 minutes ago",
          severity: "warning",
        },
        {
          id: "3",
          type: "SLA Breach",
          description: "Registration success rate fell below 99% threshold",
          timestamp: "1 hour ago",
          severity: "error",
        },
        {
          id: "4",
          type: "Forecast Alert",
          description: "Predicted latency spike in next 2 hours",
          timestamp: "3 hours ago",
          severity: "warning",
        },
        {
          id: "5",
          type: "User Added",
          description: "New analyst user created for Acme Corp tenant",
          timestamp: "5 hours ago",
          severity: "info",
        },
      ]);

      setLoading(false);
    }, 500);
  }, []);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold mb-2">Welcome Back</h2>
        <p className="text-slate-400">
          Here's your enterprise trace analysis dashboard
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, idx) => (
          <div
            key={idx}
            className="bg-slate-800 border border-slate-700 rounded-xl p-6 hover:border-slate-600 transition-colors"
          >
            <div className={`inline-flex p-3 rounded-lg bg-gradient-to-br ${stat.color} mb-4`}>
              <div className="text-white">{stat.icon}</div>
            </div>
            <p className="text-slate-400 text-sm mb-1">{stat.title}</p>
            <p className="text-3xl font-bold mb-2">{stat.value}</p>
            <p className="text-sm text-green-400">{stat.change}</p>
          </div>
        ))}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Quick Actions */}
        <div className="lg:col-span-1 space-y-4">
          <h3 className="text-lg font-semibold">Quick Actions</h3>

          <div className="space-y-3">
            {[
              {
                title: "Upload Trace",
                icon: <Zap className="w-5 h-5" />,
                href: "/traces",
                color: "from-blue-500 to-blue-600",
              },
              {
                title: "View Analytics",
                icon: <BarChart3 className="w-5 h-5" />,
                href: "/analytics",
                color: "from-purple-500 to-purple-600",
              },
              {
                title: "Manage Enterprise",
                icon: <Shield className="w-5 h-5" />,
                href: "/enterprise",
                color: "from-pink-500 to-pink-600",
              },
              {
                title: "Check SLA Status",
                icon: <TrendingUp className="w-5 h-5" />,
                href: "/sla",
                color: "from-green-500 to-green-600",
              },
            ].map((action, idx) => (
              <Link
                key={idx}
                href={action.href}
                className="flex items-center gap-3 px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg hover:border-slate-600 transition-all group"
              >
                <div className={`p-2 rounded-lg bg-gradient-to-br ${action.color} text-white`}>
                  {action.icon}
                </div>
                <div className="flex-1">
                  <p className="text-sm font-medium">{action.title}</p>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-slate-200 transition-colors" />
              </Link>
            ))}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Recent Activity</h3>
            <Link
              href="/audit"
              className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
            >
              View All
            </Link>
          </div>

          <div className="space-y-3 max-h-96 overflow-y-auto">
            {activities.map((activity) => (
              <div
                key={activity.id}
                className="flex items-start gap-4 p-4 bg-slate-800 border border-slate-700 rounded-lg hover:border-slate-600 transition-colors"
              >
                <div className="mt-1">
                  {activity.severity === "info" && (
                    <Activity className="w-5 h-5 text-blue-400" />
                  )}
                  {activity.severity === "warning" && (
                    <AlertCircle className="w-5 h-5 text-yellow-400" />
                  )}
                  {activity.severity === "error" && (
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                  )}
                </div>
                <div className="flex-1">
                  <p className="text-sm font-medium">{activity.type}</p>
                  <p className="text-sm text-slate-400 mt-1">
                    {activity.description}
                  </p>
                  <p className="text-xs text-slate-500 mt-2">{activity.timestamp}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Features Overview */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Platform Features</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            {
              title: "Trace Analysis",
              desc: "Decode and analyze PCAP files",
              icon: <Zap className="w-6 h-6" />,
            },
            {
              title: "AI Insights",
              desc: "AI-powered root cause analysis",
              icon: <Brain className="w-6 h-6" />,
            },
            {
              title: "ML Forecasting",
              desc: "Predict metrics and anomalies",
              icon: <TrendingUp className="w-6 h-6" />,
            },
            {
              title: "Enterprise Control",
              desc: "Multi-tenant, RBAC, audit logs",
              icon: <Shield className="w-6 h-6" />,
            },
          ].map((feature, idx) => (
            <div
              key={idx}
              className="p-4 bg-slate-800 border border-slate-700 rounded-lg hover:border-slate-600 transition-colors"
            >
              <div className="text-blue-400 mb-3">{feature.icon}</div>
              <p className="font-medium text-sm mb-1">{feature.title}</p>
              <p className="text-xs text-slate-400">{feature.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* System Status */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold mb-2">System Status</h3>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-green-500 rounded-full"></div>
              <p className="text-sm text-slate-400">All systems operational</p>
            </div>
          </div>
          <div className="text-right">
            <p className="text-2xl font-bold text-green-400">99.99%</p>
            <p className="text-xs text-slate-400">Uptime (30 days)</p>
          </div>
        </div>
      </div>
    </div>
  );
}
