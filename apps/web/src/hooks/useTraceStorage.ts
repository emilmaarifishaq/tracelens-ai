import { useEffect, useState } from "react";

export interface TraceData {
  trace_id: string;
  filename: string;
  event_count: number;
  events: Array<Record<string, unknown>>;
  errors: Array<Record<string, unknown>>;
  warnings?: string[];
  ai_context: {
    trace_summary?: {
      event_count?: number;
      error_count?: number;
      protocols?: string[];
      participants?: Array<{ address: string; label: string }>;
      procedures?: Array<Record<string, unknown>>;
      procedure_groups?: Array<Record<string, unknown>>;
      failure_timeline?: Array<Record<string, unknown>>;
      host_flows?: Array<Record<string, unknown>>;
      session_drilldowns?: Array<Record<string, unknown>>;
      protocol_statistics?: Record<string, unknown>;
    };
  };
  settings?: {
    http2_ports?: number[];
    show_heartbeats?: boolean;
    hide_duplicate_pfcp?: boolean;
  };
  cached_at?: number;
}

const TRACE_STORAGE_KEY = "tracelens_cached_trace";
const CACHE_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

export function useTraceStorage() {
  const [cachedTrace, setCachedTrace] = useState<TraceData | null>(null);
  const [isCached, setIsCached] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Load from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(TRACE_STORAGE_KEY);
      if (stored) {
        const trace = JSON.parse(stored) as TraceData;
        const now = Date.now();
        const cachedAt = trace.cached_at || 0;

        // Check if cache is expired
        if (now - cachedAt < CACHE_EXPIRY_MS) {
          setCachedTrace(trace);
          setIsCached(true);
        } else {
          // Cache expired, remove it
          localStorage.removeItem(TRACE_STORAGE_KEY);
          setIsCached(false);
        }
      }
    } catch (error) {
      console.error("Error loading cached trace:", error);
      setIsCached(false);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Save trace to localStorage
  const saveTrace = (trace: TraceData) => {
    try {
      const traceWithTimestamp = {
        ...trace,
        cached_at: Date.now(),
      };
      localStorage.setItem(TRACE_STORAGE_KEY, JSON.stringify(traceWithTimestamp));
      setCachedTrace(traceWithTimestamp);
      setIsCached(true);
    } catch (error) {
      console.error("Error saving trace to cache:", error);
    }
  };

  // Clear cache
  const clearCache = () => {
    try {
      localStorage.removeItem(TRACE_STORAGE_KEY);
      setCachedTrace(null);
      setIsCached(false);
    } catch (error) {
      console.error("Error clearing cache:", error);
    }
  };

  // Get cache info
  const getCacheInfo = () => {
    if (!cachedTrace) return null;
    return {
      filename: cachedTrace.filename,
      eventCount: cachedTrace.event_count,
      cachedAt: new Date(cachedTrace.cached_at || 0).toLocaleString(),
    };
  };

  return {
    cachedTrace,
    isCached,
    isLoading,
    saveTrace,
    clearCache,
    getCacheInfo,
  };
}
