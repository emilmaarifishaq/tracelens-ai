"use client";

import { Settings, Save, Bell, Lock, Palette } from "lucide-react";
import { useState } from "react";

export default function SettingsPage() {
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold mb-2">Settings</h2>
        <p className="text-slate-400">Configure system and user preferences</p>
      </div>

      {/* API Configuration */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <Settings className="w-6 h-6 text-blue-400" />
          <h3 className="text-lg font-semibold">API Configuration</h3>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">API Base URL</label>
            <input
              type="text"
              defaultValue="http://localhost:8000"
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm"
            />
            <p className="text-xs text-slate-400 mt-1">
              Backend API endpoint for all requests
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">API Timeout (seconds)</label>
            <input
              type="number"
              defaultValue="30"
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Trace Upload Max Size (MB)</label>
            <input
              type="number"
              defaultValue="500"
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm"
            />
          </div>
        </div>
      </div>

      {/* Display Settings */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <Palette className="w-6 h-6 text-purple-400" />
          <h3 className="text-lg font-semibold">Display Settings</h3>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Theme</label>
            <select className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm">
              <option>Dark (Current)</option>
              <option>Light</option>
              <option>Auto</option>
            </select>
          </div>

          <div>
            <label className="flex items-center gap-2">
              <input type="checkbox" defaultChecked className="rounded" />
              <span className="text-sm">Enable Animations</span>
            </label>
          </div>

          <div>
            <label className="flex items-center gap-2">
              <input type="checkbox" defaultChecked className="rounded" />
              <span className="text-sm">Compact Mode</span>
            </label>
          </div>
        </div>
      </div>

      {/* Notification Settings */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <Bell className="w-6 h-6 text-yellow-400" />
          <h3 className="text-lg font-semibold">Notifications</h3>
        </div>

        <div className="space-y-3">
          {[
            { label: "SLA Breaches", checked: true },
            { label: "Trace Errors", checked: true },
            { label: "System Alerts", checked: true },
            { label: "User Activity", checked: false },
            { label: "Integration Status", checked: true },
          ].map((item, idx) => (
            <label key={idx} className="flex items-center gap-2">
              <input
                type="checkbox"
                defaultChecked={item.checked}
                className="rounded"
              />
              <span className="text-sm">{item.label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Security Settings */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <Lock className="w-6 h-6 text-green-400" />
          <h3 className="text-lg font-semibold">Security</h3>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Session Timeout (minutes)</label>
            <input
              type="number"
              defaultValue="60"
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm"
            />
          </div>

          <div>
            <label className="flex items-center gap-2">
              <input type="checkbox" defaultChecked className="rounded" />
              <span className="text-sm">Require 2FA for Admin Access</span>
            </label>
          </div>

          <div>
            <label className="flex items-center gap-2">
              <input type="checkbox" defaultChecked className="rounded" />
              <span className="text-sm">Enable Audit Logging</span>
            </label>
          </div>

          <button className="text-sm text-blue-400 hover:text-blue-300 mt-4">
            Change Password
          </button>
        </div>
      </div>

      {/* Data Settings */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-6">Data Management</h3>

        <div className="space-y-3">
          <button className="w-full px-4 py-2 text-left bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors">
            Export Settings
          </button>
          <button className="w-full px-4 py-2 text-left bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors">
            Clear Cache
          </button>
          <button className="w-full px-4 py-2 text-left bg-red-900/20 hover:bg-red-900/30 text-red-400 rounded-lg transition-colors">
            Reset to Defaults
          </button>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex items-center gap-4">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-2 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 rounded-lg font-medium transition-all"
        >
          <Save className="w-4 h-4" />
          Save Settings
        </button>
        {saved && <p className="text-sm text-green-400">✓ Saved successfully</p>}
      </div>
    </div>
  );
}
