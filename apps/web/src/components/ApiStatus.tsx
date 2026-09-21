"use client";

import { useState, useEffect } from "react";
import { AlertCircle, CheckCircle2, Loader } from "lucide-react";

interface ApiStatusProps {
  apiBaseUrl?: string;
}

export function ApiStatus({ apiBaseUrl }: ApiStatusProps) {
  const [status, setStatus] = useState<"checking" | "connected" | "disconnected">("checking");
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  useEffect(() => {
    const checkApi = async () => {
      try {
        const url =
          apiBaseUrl ||
          `${typeof window !== "undefined" ? window.location.protocol : "http:"}//${typeof window !== "undefined" ? window.location.hostname : "localhost"}:8000`;

        const response = await fetch(`${url}/health`, {
          method: "GET",
          cache: "no-store",
        });

        if (response.ok) {
          setStatus("connected");
        } else {
          setStatus("disconnected");
        }
      } catch {
        setStatus("disconnected");
      } finally {
        setLastChecked(new Date());
      }
    };

    // Check immediately
    checkApi();

    // Check every 5 seconds
    const interval = setInterval(checkApi, 5000);
    return () => clearInterval(interval);
  }, [apiBaseUrl]);

  const getStatusDisplay = () => {
    switch (status) {
      case "connected":
        return (
          <div className="flex items-center gap-2 text-sm text-green-600 dark:text-green-400">
            <CheckCircle2 size={16} />
            <span>API Connected</span>
          </div>
        );
      case "disconnected":
        return (
          <div className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400">
            <AlertCircle size={16} />
            <span>API Disconnected</span>
          </div>
        );
      case "checking":
        return (
          <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
            <Loader size={16} className="animate-spin" />
            <span>Checking API...</span>
          </div>
        );
    }
  };

  return (
    <div className="flex flex-col items-end gap-1">
      {getStatusDisplay()}
      {lastChecked && (
        <span className="text-xs text-gray-400 dark:text-gray-500">
          {Math.floor((Date.now() - lastChecked.getTime()) / 1000)}s ago
        </span>
      )}
    </div>
  );
}
