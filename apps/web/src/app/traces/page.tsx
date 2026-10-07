"use client";

import { useState } from "react";
import { FileUp, AlertCircle, CheckCircle2, Loader } from "lucide-react";

export default function TracesPage() {
  const [files, setFiles] = useState<File[]>([]);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setFiles(Array.from(e.target.files));
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!files.length) {
      setError("Please select at least one PCAP file");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      files.forEach((file) => formData.append("files", file));

      const response = await fetch(`${API_BASE}/traces`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      const data = await response.json();
      setResult(data);
      setFiles([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold mb-2">Trace Analysis</h2>
        <p className="text-slate-400">
          Upload PCAP files for AI-powered protocol analysis
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Section */}
        <div className="lg:col-span-1">
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
            <h3 className="text-lg font-semibold mb-4">Upload Files</h3>

            <div className="border-2 border-dashed border-slate-600 rounded-lg p-8 text-center hover:border-slate-500 transition-colors cursor-pointer">
              <input
                type="file"
                multiple
                accept=".pcap,.pcapng,.cap,.zip,.tar,.7z"
                onChange={handleFileChange}
                className="hidden"
                id="file-input"
              />
              <label htmlFor="file-input" className="cursor-pointer block">
                <FileUp className="w-8 h-8 text-blue-400 mx-auto mb-2" />
                <p className="font-medium mb-1">Drop files here or click</p>
                <p className="text-sm text-slate-400">
                  PCAP, PCAPNG, CAP, ZIP, TAR, 7Z
                </p>
              </label>
            </div>

            {files.length > 0 && (
              <div className="mt-4 space-y-2">
                <p className="text-sm font-medium">Selected files:</p>
                {files.map((file, idx) => (
                  <p key={idx} className="text-sm text-slate-400 truncate">
                    ✓ {file.name}
                  </p>
                ))}
              </div>
            )}

            {error && (
              <div className="mt-4 p-3 bg-red-900/20 border border-red-700 rounded-lg flex gap-2">
                <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-red-300">{error}</p>
              </div>
            )}

            <button
              onClick={handleUpload}
              disabled={!files.length || loading}
              className="w-full mt-4 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium py-2 rounded-lg transition-all"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader className="w-4 h-4 animate-spin" />
                  Analyzing...
                </span>
              ) : (
                "Analyze Traces"
              )}
            </button>
          </div>
        </div>

        {/* Results Section */}
        <div className="lg:col-span-2">
          {result ? (
            <div className="space-y-4">
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <CheckCircle2 className="w-6 h-6 text-green-400" />
                  <h3 className="text-lg font-semibold">Analysis Results</h3>
                </div>

                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div>
                    <p className="text-sm text-slate-400 mb-1">Trace ID</p>
                    <p className="font-mono text-sm">{result.trace_id}</p>
                  </div>
                  <div>
                    <p className="text-sm text-slate-400 mb-1">File</p>
                    <p className="text-sm truncate">{result.filename}</p>
                  </div>
                  <div>
                    <p className="text-sm text-slate-400 mb-1">Events Decoded</p>
                    <p className="text-2xl font-bold text-blue-400">
                      {result.event_count}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-slate-400 mb-1">Errors Found</p>
                    <p className="text-2xl font-bold text-orange-400">
                      {result.errors?.length || 0}
                    </p>
                  </div>
                </div>

                {result.ai_context?.trace_summary?.protocols && (
                  <div>
                    <p className="text-sm font-medium mb-2">Protocols Detected</p>
                    <div className="flex flex-wrap gap-2">
                      {result.ai_context.trace_summary.protocols.map(
                        (proto: string, idx: number) => (
                          <span
                            key={idx}
                            className="px-3 py-1 bg-slate-700 rounded-full text-sm"
                          >
                            {proto}
                          </span>
                        )
                      )}
                    </div>
                  </div>
                )}
              </div>

              {result.errors && result.errors.length > 0 && (
                <div className="bg-slate-800 border border-red-700/30 rounded-xl p-6">
                  <h4 className="font-semibold mb-4 text-red-400">Errors Detected</h4>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {result.errors.slice(0, 10).map((err: any, idx: number) => (
                      <div key={idx} className="text-sm text-slate-300">
                        • {err.cause || JSON.stringify(err).substring(0, 50)}
                      </div>
                    ))}
                    {result.errors.length > 10 && (
                      <p className="text-sm text-slate-400">
                        +{result.errors.length - 10} more errors
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center">
              <p className="text-slate-400">Upload a PCAP file to see analysis results</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
