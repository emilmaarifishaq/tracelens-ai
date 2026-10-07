"use client";

import { useState } from "react";
import {
  BarChart3,
  Brain,
  Database,
  FileUp,
  LogOut,
  Menu,
  Settings,
  Shield,
  Zap,
  Home,
  TrendingUp,
  AlertCircle,
} from "lucide-react";
import Link from "next/link";
import "./styles.css";

interface NavItem {
  name: string;
  href: string;
  icon: React.ReactNode;
  badge?: string;
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const navItems: NavItem[] = [
    { name: "Dashboard", href: "/", icon: <Home className="w-5 h-5" /> },
    { name: "Trace Analysis", href: "/traces", icon: <FileUp className="w-5 h-5" />, badge: "NEW" },
    { name: "Analytics", href: "/analytics", icon: <BarChart3 className="w-5 h-5" /> },
    { name: "ML Features", href: "/ml", icon: <Brain className="w-5 h-5" /> },
    { name: "SLA Tracking", href: "/sla", icon: <TrendingUp className="w-5 h-5" /> },
    { name: "Audit Logs", href: "/audit", icon: <AlertCircle className="w-5 h-5" /> },
    { name: "Enterprise", href: "/enterprise", icon: <Shield className="w-5 h-5" /> },
    { name: "Integrations", href: "/integrations", icon: <Zap className="w-5 h-5" /> },
    { name: "Settings", href: "/settings", icon: <Settings className="w-5 h-5" /> },
  ];

  return (
    <html lang="en">
      <head>
        <title>TraceLens AI - Enterprise Dashboard</title>
        <meta name="description" content="Advanced trace analysis and AI-powered insights" />
      </head>
      <body className="bg-slate-900 text-slate-100">
        <div className="flex h-screen overflow-hidden">
          {/* Sidebar */}
          <aside className={`${sidebarOpen ? "w-64" : "w-20"} bg-slate-800 border-r border-slate-700 transition-all duration-300 flex flex-col`}>
            {/* Logo */}
            <div className="p-6 border-b border-slate-700 flex items-center justify-between">
              {sidebarOpen && (
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                    <Zap className="w-5 h-5 text-white" />
                  </div>
                  <span className="font-bold text-lg">TraceLens</span>
                </div>
              )}
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="text-slate-400 hover:text-slate-200 transition-colors"
              >
                <Menu className="w-5 h-5" />
              </button>
            </div>

            {/* Navigation */}
            <nav className="flex-1 overflow-y-auto p-4 space-y-2">
              {navItems.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="flex items-center gap-3 px-4 py-3 rounded-lg transition-colors hover:bg-slate-700 text-slate-300 hover:text-white"
                  title={!sidebarOpen ? item.name : ""}
                >
                  {item.icon}
                  {sidebarOpen && (
                    <>
                      <span className="text-sm font-medium">{item.name}</span>
                      {item.badge && (
                        <span className="ml-auto text-xs bg-blue-600 text-white px-2 py-1 rounded">
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}
                </Link>
              ))}
            </nav>

            {/* Footer */}
            <div className="p-4 border-t border-slate-700">
              <button className="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors hover:bg-slate-700 text-slate-300 hover:text-white text-sm">
                <LogOut className="w-5 h-5" />
                {sidebarOpen && <span>Logout</span>}
              </button>
            </div>
          </aside>

          {/* Main Content */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Top Bar */}
            <header className="bg-slate-800 border-b border-slate-700 px-8 py-4 flex items-center justify-between">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                TraceLens AI
              </h1>
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <p className="text-sm font-medium">Admin User</p>
                  <p className="text-xs text-slate-400">Enterprise Tier</p>
                </div>
                <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full"></div>
              </div>
            </header>

            {/* Page Content */}
            <main className="flex-1 overflow-y-auto p-8">
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}

