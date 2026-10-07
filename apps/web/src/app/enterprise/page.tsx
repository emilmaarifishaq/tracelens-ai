"use client";

import { Shield, Users, Plus, Edit2, Trash2 } from "lucide-react";

export default function EnterprisePage() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold mb-2">Enterprise Management</h2>
        <p className="text-slate-400">
          Multi-tenant management, users, and role-based access control
        </p>
      </div>

      {/* Tenants */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Tenants</h3>
          <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition-colors">
            <Plus className="w-4 h-4" />
            New Tenant
          </button>
        </div>

        {[
          {
            name: "Acme Corp",
            tier: "Enterprise",
            users: 24,
            traces: "45.2K",
            status: "active",
          },
          {
            name: "TechVision Inc",
            tier: "Pro",
            users: 8,
            traces: "12.4K",
            status: "active",
          },
          {
            name: "Global Networks",
            tier: "Enterprise",
            users: 18,
            traces: "78.9K",
            status: "active",
          },
        ].map((tenant, idx) => (
          <div
            key={idx}
            className="bg-slate-800 border border-slate-700 rounded-xl p-6"
          >
            <div className="flex items-center justify-between mb-4">
              <div>
                <p className="font-semibold text-lg">{tenant.name}</p>
                <p className="text-sm text-slate-400 mt-1">
                  {tenant.tier} • {tenant.users} users • {tenant.traces} traces
                </p>
              </div>
              <div className="flex gap-2">
                <button className="p-2 hover:bg-slate-700 rounded-lg transition-colors">
                  <Edit2 className="w-4 h-4 text-blue-400" />
                </button>
                <button className="p-2 hover:bg-slate-700 rounded-lg transition-colors">
                  <Trash2 className="w-4 h-4 text-red-400" />
                </button>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-green-500 rounded-full"></div>
              <span className="text-sm text-green-400">{tenant.status}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Users */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Users (Acme Corp)</h3>
          <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition-colors">
            <Plus className="w-4 h-4" />
            Add User
          </button>
        </div>

        {[
          {
            name: "John Analyst",
            email: "john@acme.com",
            role: "Data Analyst",
            joined: "2026-08-15",
          },
          {
            name: "Sarah Operations",
            email: "sarah@acme.com",
            role: "Operations Engineer",
            joined: "2026-09-02",
          },
          {
            name: "Admin User",
            email: "admin@acme.com",
            role: "Tenant Admin",
            joined: "2026-07-10",
          },
        ].map((user, idx) => (
          <div
            key={idx}
            className="bg-slate-800 border border-slate-700 rounded-xl p-6 flex items-center justify-between"
          >
            <div>
              <p className="font-semibold">{user.name}</p>
              <p className="text-sm text-slate-400 mt-1">
                {user.email} • {user.role} • Joined {user.joined}
              </p>
            </div>
            <div className="flex gap-2">
              <button className="p-2 hover:bg-slate-700 rounded-lg transition-colors">
                <Edit2 className="w-4 h-4 text-blue-400" />
              </button>
              <button className="p-2 hover:bg-slate-700 rounded-lg transition-colors">
                <Trash2 className="w-4 h-4 text-red-400" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Roles & Permissions */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Roles & Permissions</h3>
        {[
          {
            role: "Tenant Admin",
            permissions: [
              "read_traces",
              "modify_rules",
              "manage_users",
              "view_dashboards",
              "admin_access",
            ],
          },
          {
            role: "Data Analyst",
            permissions: ["read_traces", "view_dashboards"],
          },
          {
            role: "Operations",
            permissions: ["read_traces", "modify_rules", "view_dashboards"],
          },
        ].map((item, idx) => (
          <div
            key={idx}
            className="bg-slate-800 border border-slate-700 rounded-xl p-6"
          >
            <p className="font-semibold mb-3">{item.role}</p>
            <div className="flex flex-wrap gap-2">
              {item.permissions.map((perm, pidx) => (
                <span
                  key={pidx}
                  className="px-3 py-1 bg-blue-600/20 text-blue-400 rounded-full text-sm"
                >
                  {perm}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
