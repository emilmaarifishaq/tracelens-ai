"use client";

import { useState, useEffect, useRef } from "react";
import { AlertCircle, CheckCircle2, Loader, Wrench } from "lucide-react";

interface ApiStatusProps {
  apiBaseUrl?: string;
}

interface SystemHealth {
  api: "ok" | "error";
  tshark_available: boolean;
}

export function ApiStatus({ apiBaseUrl }: ApiStatusProps) {
  const [status, setStatus] = useState<"checking" | "connected" | "disconnected">("checking");
  const [tsharkAvailable, setTsharkAvailable] = useState<boolean | null>(null);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const consecutiveFailuresRef = useRef(0);

  useEffect(() => {
    // A single missed health check doesn't mean the API is actually down --
    // a large trace decode can briefly hold Python's GIL long enough (CPU-bound
    // JSON parsing/analysis, not I/O) to delay this lightweight request even
    // though the backend is working fine and the decode finishes normally.
    // Require a few consecutive misses before showing "Disconnected" so a
    // momentary blip during heavy analysis doesn't look like an outage.
    const FAILURE_THRESHOLD = 3;

    const checkSystem = async () => {
      try {
        const url =
          apiBaseUrl ||
          `${typeof window !== "undefined" ? window.location.protocol : "http:"}//${typeof window !== "undefined" ? window.location.hostname : "localhost"}:8000`;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        let response: Response;
        try {
          response = await fetch(`${url}/system/health`, {
            method: "GET",
            cache: "no-store",
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timeoutId);
        }

        if (response.ok) {
          const data = (await response.json()) as SystemHealth;
          consecutiveFailuresRef.current = 0;
          setStatus("connected");
          setTsharkAvailable(data.tshark_available);
        } else {
          consecutiveFailuresRef.current += 1;
          if (consecutiveFailuresRef.current >= FAILURE_THRESHOLD) {
            setStatus("disconnected");
            setTsharkAvailable(null);
          }
        }
      } catch {
        consecutiveFailuresRef.current += 1;
        if (consecutiveFailuresRef.current >= FAILURE_THRESHOLD) {
          setStatus("disconnected");
          setTsharkAvailable(null);
        }
      } finally {
        setLastChecked(new Date());
      }
    };

    // Check immediately
    checkSystem();

    // Check every 5 seconds
    const interval = setInterval(checkSystem, 5000);
    return () => clearInterval(interval);
  }, [apiBaseUrl]);

  const getApiStatusDisplay = () => {
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

  const getTsharkStatusDisplay = () => {
    if (tsharkAvailable === null) {
      return null;
    }

    if (tsharkAvailable) {
      return (
        <div className="flex items-center gap-2 text-sm text-green-600 dark:text-green-400">
          <CheckCircle2 size={16} />
          <span>TShark Available</span>
        </div>
      );
    } else {
      return (
        <div className="flex items-center gap-2 text-sm text-orange-600 dark:text-orange-400">
          <AlertCircle size={16} />
          <span>TShark Not Found</span>
        </div>
      );
    }
  };

  return (
    <div className="flex flex-col items-end gap-1.5">
      <div className="flex flex-col gap-1">
        {getApiStatusDisplay()}
        {getTsharkStatusDisplay()}
      </div>
      {lastChecked && (
        <span className="text-xs text-gray-400 dark:text-gray-500">
          {Math.floor((Date.now() - lastChecked.getTime()) / 1000)}s ago
        </span>
      )}
    </div>
  );
}
