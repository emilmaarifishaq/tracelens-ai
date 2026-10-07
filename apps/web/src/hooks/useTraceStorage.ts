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

const TRACE_DB_NAME = "tracelens_db";
const TRACE_STORE_NAME = "traces";
const CACHE_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

let dbInstance: IDBDatabase | null = null;

async function getDatabase(): Promise<IDBDatabase> {
  if (dbInstance) return dbInstance;

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(TRACE_DB_NAME, 1);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      dbInstance = request.result;
      resolve(request.result);
    };

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(TRACE_STORE_NAME)) {
        db.createObjectStore(TRACE_STORE_NAME);
      }
    };
  });
}

async function loadTraceFromDB(): Promise<TraceData | null> {
  try {
    const db = await getDatabase();
    return new Promise((resolve) => {
      const transaction = db.transaction(TRACE_STORE_NAME, "readonly");
      const store = transaction.objectStore(TRACE_STORE_NAME);
      const request = store.get("cached_trace");

      request.onsuccess = () => {
        const trace = request.result as TraceData | undefined;
        if (trace) {
          const now = Date.now();
          const cachedAt = trace.cached_at || 0;

          if (now - cachedAt < CACHE_EXPIRY_MS) {
            resolve(trace);
          } else {
            resolve(null);
          }
        } else {
          resolve(null);
        }
      };

      request.onerror = () => resolve(null);
    });
  } catch (error) {
    console.error("Error loading trace from IndexedDB:", error);
    return null;
  }
}

async function saveTraceToDB(trace: TraceData): Promise<void> {
  try {
    const db = await getDatabase();
    const traceWithTimestamp = {
      ...trace,
      cached_at: Date.now(),
    };

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(TRACE_STORE_NAME, "readwrite");
      const store = transaction.objectStore(TRACE_STORE_NAME);
      const request = store.put(traceWithTimestamp, "cached_trace");

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error("Error saving trace to IndexedDB:", error);
    throw error;
  }
}

async function clearTraceDB(): Promise<void> {
  try {
    const db = await getDatabase();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(TRACE_STORE_NAME, "readwrite");
      const store = transaction.objectStore(TRACE_STORE_NAME);
      const request = store.delete("cached_trace");

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error("Error clearing IndexedDB:", error);
    throw error;
  }
}

export function useTraceStorage() {
  const [cachedTrace, setCachedTrace] = useState<TraceData | null>(null);
  const [isCached, setIsCached] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Load from IndexedDB on mount
  useEffect(() => {
    (async () => {
      try {
        const trace = await loadTraceFromDB();
        if (trace) {
          setCachedTrace(trace);
          setIsCached(true);
        } else {
          setIsCached(false);
        }
      } catch (error) {
        console.error("Error loading cached trace:", error);
        setIsCached(false);
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  // Save trace to IndexedDB
  const saveTrace = async (trace: TraceData) => {
    try {
      await saveTraceToDB(trace);
      setCachedTrace(trace);
      setIsCached(true);
    } catch (error) {
      console.error("Error saving trace to cache:", error);
    }
  };

  // Clear cache
  const clearCache = async () => {
    try {
      await clearTraceDB();
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
