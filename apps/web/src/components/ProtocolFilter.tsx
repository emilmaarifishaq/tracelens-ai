"use client";

import { ChevronDown } from "lucide-react";
import { useState } from "react";

interface ProtocolStats {
  count: number;
  first_frame: number;
  last_frame: number;
  error_count: number;
  ports: string[];
}

interface ProtocolFilterProps {
  protocols: string[];
  protocolStats?: Record<string, ProtocolStats>;
  selectedProtocols: Set<string>;
  onProtocolChange: (protocol: string, selected: boolean) => void;
  onSelectAll: () => void;
  onClearAll: () => void;
}

const PROTOCOL_CATEGORIES: Record<string, string[]> = {
  "Telecom Signaling": [
    "GTPv2-C",
    "GTPv1-C",
    "GTP-U",
    "Diameter",
    "S1AP",
    "NGAP",
    "PFCP",
    "RADIUS",
  ],
  "Application": [
    "HTTP",
    "HTTPS",
    "HTTP/2",
    "DNS",
    "SIP",
    "RTP",
    "SMTP",
    "POP3",
    "IMAP",
    "MQTT",
    "QUIC",
  ],
  "Transport": ["TCP", "UDP", "SCTP", "DCCP"],
  "Network": ["IPv4", "IPv6", "ICMP", "ICMPv6", "ARP"],
  "Security": ["TLS", "DTLS", "SSH", "IPSec"],
  "Management": ["SNMP", "LDAP", "NTP", "BGP", "OSPF"],
  "Other": ["DHCP"],
};

export function ProtocolFilter({
  protocols,
  protocolStats,
  selectedProtocols,
  onProtocolChange,
  onSelectAll,
  onClearAll,
}: ProtocolFilterProps) {
  const [isOpen, setIsOpen] = useState(false);

  const categorizedProtocols = categorizeProtocols(protocols);
  const selectedCount = selectedProtocols.size;
  const totalCount = protocols.length;

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
      >
        <span className="text-sm font-medium">
          Protocols {selectedCount > 0 && selectedCount < totalCount && `(${selectedCount})`}
        </span>
        <ChevronDown
          size={16}
          className={`transition-transform ${isOpen ? "rotate-180" : ""}`}
        />
      </button>

      {isOpen && (
        <div className="absolute top-full left-0 mt-2 w-72 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg z-50 max-h-96 overflow-y-auto">
          {/* Actions */}
          <div className="sticky top-0 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 p-3 flex gap-2">
            <button
              onClick={() => {
                onSelectAll();
                setIsOpen(false);
              }}
              className="flex-1 px-3 py-1 text-xs font-medium bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors"
            >
              Select All
            </button>
            <button
              onClick={() => {
                onClearAll();
                setIsOpen(false);
              }}
              className="flex-1 px-3 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
            >
              Clear All
            </button>
          </div>

          {/* Protocols by Category */}
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {Object.entries(categorizedProtocols).map(([category, prots]) => (
              <div key={category} className="p-3">
                <div className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-2">
                  {category}
                </div>
                <div className="space-y-2">
                  {prots.map((protocol) => {
                    const stats = protocolStats?.[protocol];
                    const isSelected = selectedProtocols.has(protocol);

                    return (
                      <label
                        key={protocol}
                        className="flex items-start gap-2 p-2 rounded hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer transition-colors"
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={(e) =>
                            onProtocolChange(protocol, e.target.checked)
                          }
                          className="mt-1 cursor-pointer"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                            {protocol}
                          </div>
                          {stats && (
                            <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                              <div>Count: {stats.count}</div>
                              {stats.error_count > 0 && (
                                <div className="text-red-600 dark:text-red-400">
                                  Errors: {stats.error_count}
                                </div>
                              )}
                              {stats.ports.length > 0 && (
                                <div>Ports: {stats.ports.slice(0, 3).join(", ")}</div>
                              )}
                            </div>
                          )}
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {/* Summary */}
          <div className="sticky bottom-0 bg-gray-50 dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 px-3 py-2">
            <div className="text-xs text-gray-600 dark:text-gray-400">
              {selectedCount} of {totalCount} protocols selected
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function categorizeProtocols(protocols: string[]): Record<string, string[]> {
  const categorized: Record<string, string[]> = {};

  for (const [category, categoryProtocols] of Object.entries(PROTOCOL_CATEGORIES)) {
    const protocolsInCategory = protocols.filter((p) =>
      categoryProtocols.includes(p)
    );
    if (protocolsInCategory.length > 0) {
      categorized[category] = protocolsInCategory;
    }
  }

  const uncategorized = protocols.filter(
    (p) =>
      !Object.values(PROTOCOL_CATEGORIES).some((prots) => prots.includes(p))
  );
  if (uncategorized.length > 0) {
    categorized["Other"] = uncategorized;
  }

  return categorized;
}
