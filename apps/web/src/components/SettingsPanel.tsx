"use client";

import { Lock, Settings, Zap } from "lucide-react";
import { useState } from "react";

interface AIProviderConfig {
  apiKey: string;
  provider: "openai" | "rule-engine";
  model: string;
  webSearchEnabled: boolean;
  baseUrl?: string;
}

interface SettingsPanelProps {
  config: AIProviderConfig;
  onConfigChange: (config: AIProviderConfig) => void;
  onClose: () => void;
}

export function SettingsPanel({
  config,
  onConfigChange,
  onClose,
}: SettingsPanelProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [apiKey, setApiKey] = useState(config.apiKey);
  const [showApiKey, setShowApiKey] = useState(false);
  const [provider, setProvider] = useState<"openai" | "rule-engine">(
    config.provider
  );
  const [model, setModel] = useState(config.model);
  const [webSearchEnabled, setWebSearchEnabled] = useState(
    config.webSearchEnabled
  );
  const [baseUrl, setBaseUrl] = useState(config.baseUrl || "");
  const [status, setStatus] = useState<"idle" | "saved" | "error">("idle");

  const handleSave = () => {
    if (provider === "openai" && !apiKey.trim()) {
      setStatus("error");
      return;
    }

    const newConfig: AIProviderConfig = {
      apiKey,
      provider,
      model,
      webSearchEnabled,
      baseUrl: baseUrl || undefined,
    };

    onConfigChange(newConfig);
    setStatus("saved");
    setTimeout(() => {
      setStatus("idle");
      setIsOpen(false);
    }, 1500);
  };

  const hasApiKey = apiKey.trim().length > 0;
  const isConfigured = provider === "rule-engine" || hasApiKey;

  return (
    <>
      {/* Settings Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
        title="AI Configuration"
      >
        <Settings size={18} />
        <span className="text-sm font-medium">Settings</span>
      </button>

      {/* Modal Overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/50 dark:bg-black/70 z-40"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Settings Panel */}
      {isOpen && (
        <div className="fixed right-6 top-24 w-96 bg-white dark:bg-gray-900 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 z-50 max-h-[80vh] overflow-y-auto">
          <div className="sticky top-0 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 p-4 flex justify-between items-center">
            <h2 className="text-lg font-bold">AI Configuration</h2>
            <button
              onClick={() => setIsOpen(false)}
              className="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
            >
              ✕
            </button>
          </div>

          <div className="p-4 space-y-5">
            {/* Status Indicator */}
            <div className="flex items-center gap-2 p-3 rounded-lg bg-blue-50 dark:bg-blue-900/30">
              <Zap size={16} className="text-blue-600 dark:text-blue-400" />
              <div>
                <div className="text-sm font-semibold text-blue-900 dark:text-blue-200">
                  {isConfigured ? "AI Enabled ✓" : "Rule Engine (Offline)"}
                </div>
                <div className="text-xs text-blue-700 dark:text-blue-300">
                  {isConfigured
                    ? "AI analysis available for all traces"
                    : "Using local rules only - no AI"}
                </div>
              </div>
            </div>

            {/* Provider Selection */}
            <div>
              <label className="block text-sm font-semibold mb-2">
                Analysis Mode
              </label>
              <div className="space-y-2">
                <label className="flex items-center gap-2 p-2 rounded border border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800">
                  <input
                    type="radio"
                    name="provider"
                    value="rule-engine"
                    checked={provider === "rule-engine"}
                    onChange={() => setProvider("rule-engine")}
                    className="cursor-pointer"
                  />
                  <div>
                    <div className="font-medium">Rule Engine (Offline)</div>
                    <div className="text-xs text-gray-500">
                      Local rules only, no API key needed
                    </div>
                  </div>
                </label>

                <label className="flex items-center gap-2 p-2 rounded border border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800">
                  <input
                    type="radio"
                    name="provider"
                    value="openai"
                    checked={provider === "openai"}
                    onChange={() => setProvider("openai")}
                    className="cursor-pointer"
                  />
                  <div>
                    <div className="font-medium">OpenAI (AI-Assisted)</div>
                    <div className="text-xs text-gray-500">
                      Enhanced explanations with ChatGPT/Claude
                    </div>
                  </div>
                </label>
              </div>
            </div>

            {/* API Key Input (only for OpenAI) */}
            {provider === "openai" && (
              <>
                <div>
                  <label className="block text-sm font-semibold mb-2">
                    <div className="flex items-center gap-2">
                      <Lock size={16} />
                      API Key
                    </div>
                  </label>
                  <input
                    type={showApiKey ? "text" : "password"}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder="sk-... (OpenAI API key)"
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 dark:bg-gray-800 text-sm font-mono"
                  />
                  <button
                    onClick={() => setShowApiKey(!showApiKey)}
                    className="mt-2 text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
                  >
                    {showApiKey ? "Hide" : "Show"}
                  </button>
                  <div className="mt-2 text-xs text-gray-500 dark:text-gray-400 space-y-1">
                    <p>
                      🔐 Your API key is only stored in browser memory (not
                      saved)
                    </p>
                    <p>
                      Get one:{" "}
                      <a
                        href="https://platform.openai.com/api-keys"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 dark:text-blue-400 hover:underline"
                      >
                        OpenAI Platform
                      </a>
                    </p>
                  </div>
                </div>

                {/* Model Selection */}
                <div>
                  <label className="block text-sm font-semibold mb-2">
                    Model
                  </label>
                  <select
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 dark:bg-gray-800 text-sm"
                  >
                    <option value="gpt-4o">GPT-4o (Recommended)</option>
                    <option value="gpt-4-turbo">GPT-4 Turbo</option>
                    <option value="gpt-3.5-turbo">GPT-3.5 Turbo</option>
                    <option value="claude-3-sonnet-20240229">
                      Claude 3 Sonnet
                    </option>
                    <option value="claude-3-opus-20240229">
                      Claude 3 Opus
                    </option>
                  </select>
                </div>

                {/* Web Search Toggle */}
                <div className="flex items-center gap-3 p-3 rounded-lg border border-gray-200 dark:border-gray-700">
                  <input
                    type="checkbox"
                    id="webSearch"
                    checked={webSearchEnabled}
                    onChange={(e) => setWebSearchEnabled(e.target.checked)}
                    className="cursor-pointer"
                  />
                  <label htmlFor="webSearch" className="cursor-pointer flex-1">
                    <div className="font-medium text-sm">Enable Web Search</div>
                    <div className="text-xs text-gray-500">
                      Let AI look up protocol specs online
                    </div>
                  </label>
                </div>

                {/* Base URL (Advanced) */}
                <details className="text-sm">
                  <summary className="font-semibold cursor-pointer text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-gray-100">
                    ⚙️ Advanced Settings
                  </summary>
                  <div className="mt-3 p-3 rounded bg-gray-50 dark:bg-gray-800">
                    <label className="block text-xs font-medium mb-2">
                      Base URL (optional)
                    </label>
                    <input
                      type="text"
                      value={baseUrl}
                      onChange={(e) => setBaseUrl(e.target.value)}
                      placeholder="https://api.openai.com/v1"
                      className="w-full px-2 py-1 rounded border border-gray-300 dark:border-gray-600 dark:bg-gray-700 text-xs font-mono"
                    />
                    <div className="text-xs text-gray-500 mt-1">
                      For custom or self-hosted endpoints
                    </div>
                  </div>
                </details>
              </>
            )}

            {/* Info Box */}
            <div className="p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/30">
              <div className="text-xs font-semibold text-yellow-900 dark:text-yellow-200 mb-1">
                💡 How it works:
              </div>
              <ul className="text-xs text-yellow-800 dark:text-yellow-300 space-y-1">
                <li>
                  • Upload PCAP → Trace decoded locally (rule engine always
                  works)
                </li>
                <li>
                  • Click "Explain with AI" → Sends masked data to your AI
                  provider
                </li>
                <li>• AI explains root cause based on structured data</li>
                <li>• Your PCAP bytes never leave your machine</li>
              </ul>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-2 pt-4 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={() => setIsOpen(false)}
                className="flex-1 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 text-sm font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={provider === "openai" && !hasApiKey}
                className={`flex-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  status === "saved"
                    ? "bg-green-500 text-white"
                    : status === "error"
                      ? "bg-red-500 text-white"
                      : "bg-blue-600 text-white hover:bg-blue-700"
                } ${
                  provider === "openai" && !hasApiKey
                    ? "opacity-50 cursor-not-allowed"
                    : ""
                }`}
              >
                {status === "saved" ? "✓ Saved" : status === "error" ? "✗ Error" : "Save"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
