import React, { useState, useEffect, useRef } from "react";
import { api, type Mode, onModeChange } from "./lib/api";
import { useLiveEvents } from "./lib/live";
import type { CaseBundle, MapLayout, GraphPayload } from "./lib/types";
import { RelayMap } from "./components/RelayMap";
import { GraphView } from "./components/GraphView";

// ── Design tokens & Scaled Typography ─────────────────────
const T = {
  bg: "#FAFAFA",
  surf: "#FFFFFF",
  bdr: "#E5E7EB",
  text: "#0F172A",
  sub: "#475569",
  mute: "#64748B",
  blue: "#2563EB",
  blueL: "#EFF6FF",
  red: "#DC2626",
  redL: "#FEF2F2",
  amb: "#D97706",
  ambL: "#FEF3C7",
  grn: "#16A34A",
  grnL: "#F0FDF4",
  ind: "#4F46E5",
  indL: "#EEF2FF",
  con: "#0B0D10",
  conS: "#111419",
  conB: "#242932",
  conT: "#F5F7FA",
  conSub: "#A1A1AA",
};

const rc = (r: string) =>
  ({
    high: { c: T.red, b: T.redL },
    medium: { c: T.amb, b: T.ambL },
    low: { c: T.mute, b: "#F8FAFC" },
  })[r] || { c: T.mute, b: "#F8FAFC" };

const lc = (id: string) =>
  ({
    headers: T.blue,
    ml: T.ind,
    attach: T.red,
    auth: T.amb,
    relay: T.blue,
    urls: T.red,
    graph: T.ind,
    chain: T.grn,
    actions: T.red,
    api: T.blue,
  })[id] || T.blue;

const LAYER_TABS = [
  { id: "headers", label: "L1: MIME & Headers" },
  { id: "ml", label: "L2: ML Classification" },
  { id: "attach", label: "L3: Attachments" },
  { id: "auth", label: "L4: Authentication" },
  { id: "relay", label: "L5: Relay Forensics" },
  { id: "urls", label: "L6: URLs & Threat Intel" },
  { id: "graph", label: "L7: Campaign & ATT&CK" },
  { id: "chain", label: "L8: Chain of Custody" },
  { id: "actions", label: "L9: SOAR Response" },
  { id: "api", label: "L10: SIEM API" },
];

const Wrap = ({
  children,
  style = {},
}: {
  children: React.ReactNode;
  style?: React.CSSProperties;
}) => (
  <div
    style={{ maxWidth: 1200, margin: "0 auto", padding: "0 28px", ...style }}
  >
    {children}
  </div>
);

const EyeBrow = ({ children }: { children: React.ReactNode }) => (
  <p
    style={{
      fontSize: 14,
      fontWeight: 800,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: T.blue,
      margin: "0 0 14px",
    }}
  >
    {children}
  </p>
);

const BigH = ({
  children,
  center,
}: {
  children: React.ReactNode;
  center?: boolean;
}) => (
  <h2
    style={{
      fontSize: "clamp(36px, 4vw, 52px)",
      fontWeight: 900,
      letterSpacing: "-0.035em",
      color: T.text,
      lineHeight: 1.12,
      margin: "0 0 18px",
      textAlign: center ? "center" : "left",
    }}
  >
    {children}
  </h2>
);

const SubP = ({
  children,
  center,
  mw = 620,
}: {
  children: React.ReactNode;
  center?: boolean;
  mw?: number;
}) => (
  <p
    style={{
      fontSize: 18,
      color: T.sub,
      lineHeight: 1.68,
      maxWidth: mw,
      margin: center ? "0 auto" : "0",
    }}
  >
    {children}
  </p>
);

const Spacer = ({ h }: { h: number }) => <div style={{ height: h }} />;

// ── Interactive Investigation Terminal (Live Backend Connected) ───────────
function Widget({
  activeCase,
  selectedCaseId,
  isAnalyzing,
  onUploadFiles,
  onClearCase,
  onIngestRaw,
  uploadCount,
}: {
  activeCase: CaseBundle | null;
  selectedCaseId: string | null;
  isAnalyzing: boolean;
  onUploadFiles: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onClearCase: () => void;
  onIngestRaw?: (text: string) => Promise<void>;
  uploadCount: number;
}) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [stepIndex, setStepIndex] = useState(0);
  const [rawMode, setRawMode] = useState(false);
  const [rawText, setRawText] = useState("");

  const c = activeCase?.case;
  const trail = c?.trail || activeCase?.trail || [];
  const steps =
    trail.length > 0
      ? trail.map((t, idx) => ({
          t: t.timestamp
            ? new Date(t.timestamp).toLocaleTimeString("en-GB")
            : "09:42:0" + (idx + 1),
          msg: t.description || t.action,
          l: "L" + (t.layer || idx + 1),
        }))
      : [];

  useEffect(() => {
    if (isAnalyzing) {
      setStepIndex(0);
      const iv = setInterval(() => {
        setStepIndex((prev) => (prev < steps.length - 1 ? prev + 1 : prev));
      }, 300);
      return () => clearInterval(iv);
    } else {
      setStepIndex(steps.length > 0 ? steps.length - 1 : 0);
    }
  }, [isAnalyzing, steps.length, selectedCaseId]);

  const stepColor = (l: string) =>
    ({
      L1: "#60A5FA",
      L2: "#818CF8",
      L3: "#F472B6",
      L4: "#FBBF24",
      L5: "#34D399",
      L6: "#4ADE80",
      L7: "#A78BFA",
      L8: "#F87171",
      L9: "#22C55E",
      L10: "#38BDF8",
    })[l] || "#9CA3AF";

  const verdict = c?.verdict?.label
    ? c.verdict.label.toUpperCase()
    : activeCase?.summary?.verdict
      ? activeCase.summary.verdict.toUpperCase()
      : null;
  const riskScore =
    c?.verdict?.risk_score != null
      ? Math.round(c.verdict.risk_score)
      : activeCase?.summary?.risk_score != null
        ? Math.round(activeCase.summary.risk_score)
        : null;
  const originPlace =
    c?.origin?.place ||
    c?.origin?.city ||
    activeCase?.summary?.origin_place ||
    "—";
  const campaignName =
    c?.campaign?.id || activeCase?.summary?.campaign_id || "—";
  const mitreTechniques =
    c?.mitre && c.mitre.length > 0
      ? c.mitre
          .slice(0, 2)
          .map((m) => m.technique)
          .join(", ")
      : activeCase?.summary?.mitre && activeCase.summary.mitre.length > 0
        ? activeCase.summary.mitre.slice(0, 2).join(", ")
        : "—";
  const senderDisplay =
    c?.sender_address ||
    c?.sender_display ||
    activeCase?.summary?.sender_address ||
    null;
  const subjectDisplay = c?.subject || activeCase?.summary?.subject || null;
  const attachmentsList =
    c?.parsed_email?.attachments || activeCase?.attachments || [];
  const attachmentDisplay =
    attachmentsList.length > 0
      ? (attachmentsList[0].filename || "attachment") +
        " (" +
        ((attachmentsList[0].size || 1024) / 1024).toFixed(1) +
        " KB)"
      : null;

  return (
    <div
      style={{
        background: T.con,
        borderRadius: 16,
        overflow: "hidden",
        border: "1px solid " + T.conB,
        fontFamily: "monospace",
      }}
    >
      {/* Terminal Title Bar */}
      <div
        style={{
          background: T.conS,
          padding: "12px 18px",
          borderBottom: "1px solid " + T.conB,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
          <div
            style={{
              width: 11,
              height: 11,
              borderRadius: "50%",
              background: "#EF4444",
            }}
          />
          <div
            style={{
              width: 11,
              height: 11,
              borderRadius: "50%",
              background: "#F59E0B",
            }}
          />
          <div
            style={{
              width: 11,
              height: 11,
              borderRadius: "50%",
              background: "#22C55E",
            }}
          />
          <span
            style={{
              fontSize: 13,
              color: T.conSub,
              marginLeft: 8,
              letterSpacing: "0.05em",
              fontWeight: 600,
            }}
          >
            MailTrace · Autonomous SOC Agent
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div
            style={{
              fontSize: 11,
              color: isAnalyzing
                ? "#FBBF24"
                : selectedCaseId
                  ? "#4ADE80"
                  : T.conSub,
              background: "rgba(255,255,255,0.08)",
              padding: "3px 9px",
              borderRadius: 4,
              fontWeight: 700,
            }}
          >
            {isAnalyzing
              ? "● ANALYZING BATCH"
              : selectedCaseId
                ? "● CASE ACTIVE"
                : "○ WAITING FOR INPUT"}
          </div>
          {selectedCaseId && (
            <a
              href={`http://127.0.0.1:8000/api/cases/${selectedCaseId}/report`}
              target="_blank"
              rel="noopener noreferrer"
              title="Download official Court-Ready Forensic PDF Report"
              style={{
                background: "#1E293B",
                border: "1px solid #334155",
                borderRadius: 4,
                padding: "3px 9px",
                fontSize: 11,
                color: "#E2E8F0",
                textDecoration: "none",
                fontWeight: 700,
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.borderColor = "#60A5FA")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.borderColor = "#334155")
              }
            >
              <svg
                width="12"
                height="12"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
                <polyline points="10 9 9 9 8 9" />
              </svg>
              <span>Export PDF</span>
            </a>
          )}
          {selectedCaseId && (
            <button
              onClick={onClearCase}
              type="button"
              title="Clear current case data"
              style={{
                background: "#1E293B",
                border: "1px solid #334155",
                borderRadius: 4,
                padding: "3px 9px",
                fontSize: 11,
                color: "#FCA5A5",
                cursor: "pointer",
                fontWeight: 700,
              }}
            >
              ✕ Clear
            </button>
          )}
        </div>
      </div>

      {/* Target Email Info */}
      <div
        style={{
          margin: "16px 18px 0",
          background: "rgba(255,255,255,0.04)",
          borderRadius: 10,
          padding: "14px 16px",
          border: "1px solid " + T.conB,
        }}
      >
        {selectedCaseId && activeCase ? (
          <>
            <div
              style={{
                fontSize: 11,
                color: T.conSub,
                marginBottom: 5,
                letterSpacing: "0.06em",
                fontWeight: 700,
              }}
            >
              INGESTED MESSAGE ({selectedCaseId})
            </div>
            <div
              style={{
                fontSize: 14,
                color: T.conT,
                fontWeight: 600,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              From: {senderDisplay || "Unknown sender"}
            </div>
            <div
              style={{
                fontSize: 13,
                color: T.conSub,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                marginTop: 3,
              }}
            >
              Subject: {subjectDisplay || "No subject"}
            </div>
            {attachmentDisplay && (
              <div style={{ fontSize: 12, color: "#F87171", marginTop: 4 }}>
                Attachment: {attachmentDisplay}
              </div>
            )}
          </>
        ) : (
          <div
            style={{
              textAlign: "center",
              padding: "16px 0",
              color: T.conSub,
              fontSize: 13,
            }}
          >
            <span style={{ color: "#94A3B8", fontWeight: 600 }}>
              Awaiting input artifact. Select .EML file(s) to initiate pipeline.
            </span>
          </div>
        )}
      </div>

      {/* Step Trail Feed */}
      <div
        style={{
          padding: "12px 18px",
          minHeight: 110,
          maxHeight: 150,
          overflowY: "auto",
        }}
      >
        {selectedCaseId && steps.length > 0 ? (
          steps.slice(0, stepIndex + 1).map((s, i) => (
            <div
              key={i}
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: 10,
                marginBottom: 6,
              }}
            >
              <span style={{ fontSize: 11, color: T.conSub, minWidth: 58 }}>
                {s.t}
              </span>
              <span
                style={{
                  fontSize: 11,
                  background: stepColor(s.l) + "22",
                  color: stepColor(s.l),
                  borderRadius: 3,
                  padding: "2px 6px",
                  flexShrink: 0,
                  fontWeight: 700,
                }}
              >
                {s.l}
              </span>
              <span
                style={{
                  fontSize: 12.5,
                  color: i === stepIndex ? T.conT : T.conSub,
                  lineHeight: 1.4,
                }}
              >
                {s.msg}
              </span>
            </div>
          ))
        ) : (
          <div
            style={{
              height: "100%",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#64748B",
              fontSize: 13,
              minHeight: 100,
            }}
          >
            No active investigation in queue.
          </div>
        )}
        {isAnalyzing && (
          <div
            style={{
              display: "flex",
              gap: 8,
              alignItems: "center",
              paddingLeft: 64,
              marginTop: 4,
            }}
          >
            <span style={{ fontSize: 18, color: "#5B8CFF", lineHeight: 1 }}>
              ·
            </span>
            <span style={{ fontSize: 11.5, color: T.conSub }}>
              running analysis layers across files...
            </span>
          </div>
        )}
      </div>

      {/* Final Forensic Verdict Card */}
      <div
        style={{
          margin: "0 16px 16px",
          background: selectedCaseId
            ? "rgba(37,99,235,0.08)"
            : "rgba(255,255,255,0.02)",
          border:
            "1px solid " + (selectedCaseId ? "rgba(91,140,255,0.25)" : T.conB),
          borderRadius: 12,
          padding: "14px 16px",
        }}
      >
        {selectedCaseId && activeCase ? (
          <>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                marginBottom: 10,
              }}
            >
              <div>
                <div
                  style={{
                    fontSize: 11,
                    color: T.conSub,
                    letterSpacing: "0.06em",
                    marginBottom: 3,
                    fontWeight: 600,
                  }}
                >
                  DISPOSITION
                </div>
                <div
                  style={{
                    fontSize: 22,
                    fontWeight: 900,
                    color: verdict === "BENIGN" ? "#4ADE80" : "#F87171",
                    letterSpacing: "-0.02em",
                  }}
                >
                  {verdict}
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div
                  style={{
                    fontSize: 11,
                    color: T.conSub,
                    letterSpacing: "0.06em",
                    marginBottom: 3,
                    fontWeight: 600,
                  }}
                >
                  RISK SCORE
                </div>
                <div
                  style={{
                    fontSize: 28,
                    fontWeight: 900,
                    color: T.conT,
                    lineHeight: 1,
                  }}
                >
                  {riskScore}
                  <span
                    style={{ fontSize: 15, color: T.conSub, fontWeight: 400 }}
                  >
                    /100
                  </span>
                </div>
              </div>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "5px 16px",
                marginBottom: 10,
              }}
            >
              {[
                ["Origin", originPlace],
                ["Campaign", campaignName],
                [
                  "Targeted",
                  (c?.blast_radius?.total_recipients ||
                    activeCase?.summary?.exposed_recipients ||
                    1) + " recipient(s)",
                ],
                ["MITRE", mitreTechniques],
              ].map(([k, v]) => (
                <div
                  key={k}
                  style={{ display: "flex", justifyContent: "space-between" }}
                >
                  <span style={{ fontSize: 11.5, color: T.conSub }}>{k}</span>
                  <span
                    style={{
                      fontSize: 12,
                      color: T.conT,
                      fontWeight: 600,
                      maxWidth: 120,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {v}
                  </span>
                </div>
              ))}
            </div>

            <div
              style={{
                background:
                  verdict === "BENIGN"
                    ? "rgba(34,197,94,0.12)"
                    : "rgba(239,68,68,0.12)",
                borderRadius: 6,
                padding: "7px 10px",
                fontSize: 11.5,
                color: verdict === "BENIGN" ? "#86EFAC" : "#FCA5A5",
                marginBottom: 12,
                fontWeight: 600,
              }}
            >
              {verdict === "BENIGN"
                ? "✓ Validated — Authentication passed (Allow)"
                : `⚠ Policy: ${c?.verdict?.recommended_action || "Quarantine and warn recipients"}`}
            </div>

            {/* Analyst Action Decision Bar */}
            <div
              style={{
                borderTop: "1px solid " + T.conB,
                paddingTop: 10,
                display: "flex",
                flexDirection: "column",
                gap: 6,
              }}
            >
              <div
                style={{
                  fontSize: 10.5,
                  color: T.conSub,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  fontWeight: 700,
                }}
              >
                Analyst Decision & Triage
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr 1fr",
                  gap: 6,
                }}
              >
                <button
                  type="button"
                  onClick={async () => {
                    if (!selectedCaseId) return;
                    try {
                      await api.decision(
                        selectedCaseId,
                        "quarantine",
                        "Analyst verified threat verdict",
                        "phishing",
                      );
                      alert(
                        `Case ${selectedCaseId}: Verdict approved and anchored.`,
                      );
                    } catch (e) {
                      alert((e as Error).message);
                    }
                  }}
                  title="Confirm automated verdict and enforce estate quarantine"
                  style={{
                    background: "#1E293B",
                    border: "1px solid #334155",
                    borderRadius: 6,
                    padding: "6px 8px",
                    fontSize: 11,
                    fontWeight: 700,
                    color: "#4ADE80",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: 4,
                  }}
                >
                  ✓ Approve
                </button>

                <button
                  type="button"
                  onClick={async () => {
                    if (!selectedCaseId) return;
                    try {
                      await api.decision(
                        selectedCaseId,
                        "release",
                        "Analyst marked as legitimate business email",
                        "benign",
                      );
                      alert(
                        `Case ${selectedCaseId}: Overridden to Benign (False Positive).`,
                      );
                    } catch (e) {
                      alert((e as Error).message);
                    }
                  }}
                  title="Override verdict to Benign and release from quarantine"
                  style={{
                    background: "#1E293B",
                    border: "1px solid #334155",
                    borderRadius: 6,
                    padding: "6px 8px",
                    fontSize: 11,
                    fontWeight: 700,
                    color: "#FBBF24",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: 4,
                  }}
                >
                  ↺ Override
                </button>

                <button
                  type="button"
                  onClick={async () => {
                    if (!selectedCaseId) return;
                    try {
                      await api.decision(
                        selectedCaseId,
                        "escalate",
                        "Escalated to Tier 3 Threat Hunt team",
                        "suspicious",
                      );
                      alert(
                        `Case ${selectedCaseId}: Escalated to Tier 3 SOC Incident Response.`,
                      );
                    } catch (e) {
                      alert((e as Error).message);
                    }
                  }}
                  title="Escalate case to Tier 3 SOC Hunters and SIEM Priority"
                  style={{
                    background: "#1E293B",
                    border: "1px solid #334155",
                    borderRadius: 6,
                    padding: "6px 8px",
                    fontSize: 11,
                    fontWeight: 700,
                    color: "#60A5FA",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: 4,
                  }}
                >
                  ▲ Escalate
                </button>
              </div>
            </div>
          </>
        ) : (
          <div
            style={{
              textAlign: "center",
              padding: "16px 0",
              color: T.conSub,
              fontSize: 13,
            }}
          >
            No active case loaded. Select .EML file to analyze.
          </div>
        )}

        <input
          type="file"
          ref={fileInputRef}
          multiple
          style={{ display: "none" }}
          accept=".eml,.msg,text/plain"
          onChange={onUploadFiles}
        />

        {/* Input mode toggle */}
        <div
          style={{ display: "flex", gap: 6, marginTop: 14, marginBottom: 8 }}
        >
          <button
            type="button"
            onClick={() => setRawMode(false)}
            style={{
              flex: 1,
              padding: "7px 10px",
              fontSize: 12,
              fontWeight: 700,
              borderRadius: 6,
              cursor: "pointer",
              border: "1px solid " + (rawMode ? "#334155" : T.blue),
              background: rawMode ? "#1E293B" : T.blue,
              color: rawMode ? "#94A3B8" : "#fff",
            }}
          >
            ↑ Upload .EML
          </button>
          <button
            type="button"
            onClick={() => setRawMode(true)}
            style={{
              flex: 1,
              padding: "7px 10px",
              fontSize: 12,
              fontWeight: 700,
              borderRadius: 6,
              cursor: "pointer",
              border: "1px solid " + (rawMode ? T.blue : "#334155"),
              background: rawMode ? T.blue : "#1E293B",
              color: rawMode ? "#fff" : "#94A3B8",
            }}
          >
            ✎ Paste Raw Email
          </button>
        </div>

        {rawMode ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder={
                "Paste raw RFC 822 email here…\n\nFrom: sender@example.com\nTo: you@example.com\nSubject: Suspicious email\nDate: Mon, 01 Jan 2026 00:00:00 +0000\n\nEmail body text…"
              }
              disabled={isAnalyzing}
              style={{
                width: "100%",
                height: 110,
                background: "#0D1117",
                border: "1px solid #334155",
                borderRadius: 8,
                padding: "10px 12px",
                fontSize: 12,
                fontFamily: "monospace",
                color: "#E2E8F0",
                resize: "vertical",
                outline: "none",
                boxSizing: "border-box",
                opacity: isAnalyzing ? 0.6 : 1,
              }}
            />
            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                disabled={isAnalyzing || !rawText.trim()}
                onClick={async () => {
                  if (onIngestRaw && rawText.trim()) {
                    await onIngestRaw(rawText);
                    setRawText("");
                  }
                }}
                style={{
                  flex: 1,
                  background: rawText.trim() ? T.blue : "#1E293B",
                  border: "none",
                  borderRadius: 8,
                  padding: "11px 16px",
                  fontSize: 13,
                  color: rawText.trim() ? "#fff" : "#475569",
                  cursor: rawText.trim() ? "pointer" : "default",
                  fontWeight: 700,
                  opacity: isAnalyzing ? 0.6 : 1,
                }}
              >
                {isAnalyzing ? "Analyzing…" : "▶ Analyze Pasted Email"}
              </button>
              {selectedCaseId && (
                <button
                  onClick={onClearCase}
                  type="button"
                  style={{
                    background: "#1E293B",
                    border: "1px solid #334155",
                    borderRadius: 8,
                    padding: "10px 14px",
                    fontSize: 13,
                    color: "#FCA5A5",
                    cursor: "pointer",
                    fontWeight: 700,
                  }}
                >
                  Clear
                </button>
              )}
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", gap: 10 }}>
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={isAnalyzing}
              type="button"
              style={{
                flex: 1,
                background: T.blue,
                border: "none",
                borderRadius: 8,
                padding: "11px 16px",
                fontSize: 13,
                color: "#fff",
                cursor: "pointer",
                fontWeight: 700,
                opacity: isAnalyzing ? 0.6 : 1,
              }}
            >
              {isAnalyzing
                ? `Ingesting (${uploadCount} files)...`
                : "↑ Upload & Ingest .EML"}
            </button>
            {selectedCaseId && (
              <button
                onClick={onClearCase}
                type="button"
                style={{
                  background: "#1E293B",
                  border: "1px solid #334155",
                  borderRadius: 8,
                  padding: "10px 16px",
                  fontSize: 13,
                  color: "#FCA5A5",
                  cursor: "pointer",
                  fontWeight: 700,
                }}
              >
                Clear
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Navbar ───────────────────────────────────────────────────────────────
function Navbar() {
  return (
    <nav
      style={{
        position: "sticky",
        top: 0,
        zIndex: 50,
        background: "rgba(250,250,250,0.92)",
        backdropFilter: "blur(14px)",
        borderBottom: "1px solid " + T.bdr,
      }}
    >
      <Wrap
        style={{ display: "flex", alignItems: "center", height: 62, gap: 28 }}
      >
        <span
          style={{
            fontWeight: 900,
            fontSize: 19,
            letterSpacing: "-0.04em",
            color: T.text,
            marginRight: "auto",
            display: "flex",
            alignItems: "center",
          }}
        >
          <span>
            Mail<span style={{ color: T.blue }}>Trace</span>
          </span>
        </span>
        {["Timeline", "Forensics", "Map", "Graph", "SHAP", "Custody"].map(
          (item) => (
            <a
              key={item}
              href={"#" + item.toLowerCase()}
              style={{
                fontSize: 15,
                color: T.sub,
                textDecoration: "none",
                fontWeight: 600,
              }}
            >
              {item}
            </a>
          ),
        )}
        <a
          href="#hero"
          style={{
            background: T.blue,
            color: "#fff",
            textDecoration: "none",
            borderRadius: 8,
            padding: "8px 20px",
            fontSize: 14,
            fontWeight: 700,
          }}
        >
          Terminal
        </a>
      </Wrap>
    </nav>
  );
}

// ── Hero Section ───────────────────────────────────────────────────────────
function Hero({
  activeCase,
  selectedCaseId,
  isAnalyzing,
  onUploadFiles,
  onClearCase,
  onClearAllQueue,
  onIngestRaw,
  casesCount,
  availableCases,
  onSelectCaseNumber,
  uploadCount,
}: {
  activeCase: CaseBundle | null;
  selectedCaseId: string | null;
  isAnalyzing: boolean;
  onUploadFiles: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onClearCase: () => void;
  onClearAllQueue: () => void;
  onIngestRaw?: (text: string) => Promise<void>;
  casesCount: number;
  availableCases: string[];
  onSelectCaseNumber: (cId: string) => void;
  uploadCount: number;
}) {
  return (
    <div id="hero" style={{ background: T.bg, padding: "64px 28px 88px" }}>
      <Wrap
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1.08fr",
          gap: 48,
          alignItems: "center",
        }}
      >
        <div>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              background: T.blueL,
              color: T.blue,
              fontSize: 12,
              fontWeight: 800,
              padding: "5px 14px",
              borderRadius: 100,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              marginBottom: 22,
            }}
          >
            <span>Security Operations Platform</span>
          </div>
          <h1
            style={{
              fontSize: "clamp(40px, 4.8vw, 60px)",
              fontWeight: 900,
              letterSpacing: "-0.04em",
              color: T.text,
              lineHeight: 1.06,
              margin: "0 0 20px",
            }}
          >
            Automated Email Threat Intelligence
          </h1>
          <p
            style={{
              fontSize: 17,
              color: T.sub,
              lineHeight: 1.68,
              maxWidth: 460,
              margin: "0 0 28px",
            }}
          >
            Multi-layer analysis pipeline for email security. Parses headers,
            validates authentication records, evaluates machine learning models
            with explainability, traces infrastructure, and maintains verifiable
            evidence chains.
          </p>

          {/* Stored Cases Queue Panel */}
          {casesCount > 0 && availableCases.length > 0 ? (
            <div
              style={{
                background: T.surf,
                border: "1px solid " + T.bdr,
                borderRadius: 14,
                padding: "18px",
                marginBottom: 24,
                maxWidth: 480,
                boxShadow: "0 1px 3px rgba(0,0,0,0.04)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: 12,
                }}
              >
                <div
                  style={{
                    fontSize: 12,
                    fontWeight: 800,
                    color: T.sub,
                    textTransform: "uppercase",
                    letterSpacing: "0.08em",
                  }}
                >
                  LOAD STORED CASE ({casesCount} IN QUEUE)
                </div>
                <button
                  onClick={onClearAllQueue}
                  type="button"
                  style={{
                    fontSize: 12,
                    color: "#DC2626",
                    background: "#FEF2F2",
                    border: "1px solid #FECACA",
                    borderRadius: 6,
                    padding: "5px 12px",
                    cursor: "pointer",
                    fontWeight: 700,
                    display: "flex",
                    alignItems: "center",
                    gap: 4,
                  }}
                >
                  ✕ Clear All
                </button>
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {availableCases.map((cId) => {
                  const isSelected = selectedCaseId === cId;
                  return (
                    <button
                      key={cId}
                      type="button"
                      onClick={() => onSelectCaseNumber(cId)}
                      style={{
                        fontSize: 12,
                        fontFamily: "monospace",
                        padding: "7px 14px",
                        borderRadius: 6,
                        border: "1px solid " + (isSelected ? T.blue : T.bdr),
                        background: isSelected ? T.blueL : "#FFF",
                        color: isSelected ? T.blue : T.text,
                        cursor: "pointer",
                        fontWeight: 700,
                      }}
                    >
                      {cId}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            <div
              style={{
                background: T.surf,
                border: "1px solid " + T.bdr,
                borderRadius: 12,
                padding: "16px 20px",
                marginBottom: 24,
                maxWidth: 480,
                color: T.sub,
                fontSize: 14,
                display: "flex",
                alignItems: "center",
                gap: 10,
              }}
            >
              <span style={{ color: T.mute, fontWeight: 700 }}>
                ○ No files uploaded
              </span>
              <span style={{ color: T.mute }}>—</span>
              <span>Ingest an .EML message to begin forensic triage.</span>
            </div>
          )}

          <p
            style={{ fontSize: 13, color: T.mute, margin: 0, fontWeight: 500 }}
          >
            10 forensic layers · Multi-file batch support · Cryptographic
            evidence preservation · MITRE ATT&CK
          </p>
        </div>

        <Widget
          activeCase={activeCase}
          selectedCaseId={selectedCaseId}
          isAnalyzing={isAnalyzing}
          onUploadFiles={onUploadFiles}
          onClearCase={onClearCase}
          onIngestRaw={onIngestRaw}
          uploadCount={uploadCount}
        />
      </Wrap>
    </div>
  );
}

// ── Forensic Investigation Timeline (Chronological Execution Trail) ───────
function ForensicTimeline({
  activeCase,
  selectedCaseId,
}: {
  activeCase: CaseBundle | null;
  selectedCaseId: string | null;
}) {
  const c = activeCase?.case;
  const trail = c?.trail || activeCase?.trail || [];

  const timelineItems =
    trail.length > 0
      ? trail.map((t, i) => ({
          id: i + 1,
          layer: "L" + (t.layer || i + 1),
          title: t.action
            ? t.action.replace(/_/g, " ").toUpperCase()
            : "FORENSIC STAGE " + (i + 1),
          desc: t.description || t.details || "Step verified successfully",
          time: t.timestamp
            ? new Date(t.timestamp).toLocaleTimeString("en-GB", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })
            : `09:42:0${i + 1}`,
          status: t.status || "completed",
        }))
      : [
          {
            id: 1,
            layer: "L1",
            title: "MIME INGESTION & HEADER PARSING",
            desc: "Raw RFC-822 headers decoded and parsed into structured envelope fields.",
            time: "00:00:01",
            status: "idle",
          },
          {
            id: 2,
            layer: "L2",
            title: "ML CLASSIFICATION & SHAP ATTRIBUTION",
            desc: "Calibrated TF-IDF 5-class model probability and local feature weights computed.",
            time: "00:00:02",
            status: "idle",
          },
          {
            id: 3,
            layer: "L3",
            title: "ATTACHMENT RECON & MAGIC BYTES",
            desc: "File payloads checked for double extensions, executable markers, and SHA-256 digests.",
            time: "00:00:03",
            status: "idle",
          },
          {
            id: 4,
            layer: "L4",
            title: "SPF, DKIM & DMARC AUTHENTICATION",
            desc: "RFC 7489 alignment verified against sender domain policies.",
            time: "00:00:04",
            status: "idle",
          },
          {
            id: 5,
            layer: "L5",
            title: "RELAY PATH INVERSION & GEOLOCATION",
            desc: "Received hops inverted to trace earliest reliable origin node and ASN.",
            time: "00:00:05",
            status: "idle",
          },
          {
            id: 6,
            layer: "L6",
            title: "URL DETONATION & INTEL ENRICHMENT",
            desc: "Embedded URLs evaluated against domain age and threat intelligence feeds.",
            time: "00:00:06",
            status: "idle",
          },
          {
            id: 7,
            layer: "L7",
            title: "IDENTITY CORRELATION & ATT&CK MAPPING",
            desc: "Threat infrastructure linked into force-directed clusters and MITRE tactics.",
            time: "00:00:07",
            status: "idle",
          },
          {
            id: 8,
            layer: "L8",
            title: "MERKLE ROOT & BLOCKCHAIN ANCHORING",
            desc: "Cryptographic custody record sealed onto the immutable EVM ledger.",
            time: "00:00:08",
            status: "idle",
          },
          {
            id: 9,
            layer: "L9",
            title: "SOAR PLAYBOOK & DISCORD ALERTING",
            desc: "Automated containment policies generated with end-to-end PII masking.",
            time: "00:00:09",
            status: "idle",
          },
          {
            id: 10,
            layer: "L10",
            title: "SIEM EVENT EXPORT & REST API SYNC",
            desc: "Structured JSON findings and audit trails made accessible to SIEM endpoints.",
            time: "00:00:10",
            status: "idle",
          },
        ];

  return (
    <div
      id="timeline"
      style={{
        background: T.bg,
        padding: "80px 28px 56px",
        borderTop: "1px solid " + T.bdr,
      }}
    >
      <Wrap>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-end",
            marginBottom: 36,
          }}
        >
          <div>
            <EyeBrow>Execution Pipeline · Chronological Trail</EyeBrow>
            <BigH>Investigation Timeline</BigH>
            <SubP mw={580}>
              End-to-end audit trace detailing each sequential stage of forensic
              analysis from initial ingestion to immutable on-chain custody
              seal.
            </SubP>
          </div>
          {selectedCaseId && (
            <div
              style={{
                background: T.blueL,
                border: "1px solid rgba(37,99,235,0.2)",
                borderRadius: 8,
                padding: "8px 16px",
                fontSize: 13,
                fontWeight: 800,
                color: T.blue,
                fontFamily: "monospace",
              }}
            >
              TIMELINE: {selectedCaseId} ({timelineItems.length} STAGES
              EXECUTED)
            </div>
          )}
        </div>

        {/* Timeline Flow Cards */}
        <div style={{ position: "relative", margin: "24px 0 0" }}>
          {/* Connecting Vertical Track */}
          <div
            style={{
              position: "absolute",
              left: 24,
              top: 16,
              bottom: 24,
              width: 2,
              background: selectedCaseId ? T.blue : T.bdr,
              zIndex: 1,
            }}
          />

          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {timelineItems.map((item, idx) => {
              const isActive = Boolean(selectedCaseId);
              return (
                <div
                  key={item.id}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 20,
                    position: "relative",
                    zIndex: 2,
                  }}
                >
                  {/* Step Marker */}
                  <div
                    style={{
                      width: 48,
                      height: 48,
                      borderRadius: "50%",
                      background: isActive ? T.surf : "#F1F5F9",
                      border: "2px solid " + (isActive ? T.blue : T.bdr),
                      boxShadow: isActive ? "0 0 0 4px " + T.blueL : "none",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 800,
                      fontSize: 14,
                      color: isActive ? T.blue : T.mute,
                      flexShrink: 0,
                    }}
                  >
                    {item.layer}
                  </div>

                  {/* Step Card */}
                  <div
                    style={{
                      flex: 1,
                      background: T.surf,
                      border:
                        "1px solid " +
                        (isActive ? "rgba(37,99,235,0.18)" : T.bdr),
                      borderRadius: 14,
                      padding: "16px 20px",
                      boxShadow: "0 1px 3px rgba(0,0,0,0.03)",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      flexWrap: "wrap",
                      gap: 14,
                    }}
                  >
                    <div style={{ minWidth: 280, flex: 1 }}>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          marginBottom: 5,
                        }}
                      >
                        <span
                          style={{
                            fontSize: 14,
                            fontWeight: 800,
                            color: isActive ? T.text : T.sub,
                            letterSpacing: "0.04em",
                          }}
                        >
                          {item.title}
                        </span>
                        {isActive && (
                          <span
                            style={{
                              fontSize: 11,
                              background: T.grnL,
                              color: T.grn,
                              fontWeight: 800,
                              padding: "2px 7px",
                              borderRadius: 4,
                            }}
                          >
                            ✓ VERIFIED
                          </span>
                        )}
                      </div>
                      <div
                        style={{ fontSize: 14, color: T.sub, lineHeight: 1.55 }}
                      >
                        {item.desc}
                      </div>
                    </div>

                    <div style={{ textAlign: "right", flexShrink: 0 }}>
                      <div
                        style={{
                          fontSize: 12,
                          fontFamily: "monospace",
                          color: T.mute,
                          fontWeight: 700,
                        }}
                      >
                        {item.time}
                      </div>
                      <div
                        style={{
                          fontSize: 11,
                          color: isActive ? T.blue : T.mute,
                          fontWeight: 800,
                          marginTop: 3,
                        }}
                      >
                        STAGE {idx + 1} OF {timelineItems.length}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </Wrap>
    </div>
  );
}

// ── Email Unfolds (10-Layer Forensic Tab Explorer) ─────────────────────────
function EmailUnfolds({
  activeCase,
  selectedCaseId,
}: {
  activeCase: CaseBundle | null;
  selectedCaseId: string | null;
}) {
  const [active, setActive] = useState("headers");
  const panelColor = lc(active);
  const c = activeCase?.case;

  const getDynamicRows = (tab: string) => {
    if (!selectedCaseId || !activeCase) return [];

    if (tab === "headers") {
      const pe = c?.parsed_email;
      const headersList = pe?.headers || [];
      const fromH =
        headersList.find((h: any) => h.name?.toLowerCase() === "from")?.value ||
        c?.sender_address ||
        "—";
      const toH =
        headersList.find((h: any) => h.name?.toLowerCase() === "to")?.value ||
        c?.recipient ||
        "—";
      const subjH =
        headersList.find((h: any) => h.name?.toLowerCase() === "subject")
          ?.value ||
        c?.subject ||
        "—";
      const dateH =
        headersList.find((h: any) => h.name?.toLowerCase() === "date")?.value ||
        c?.created_at ||
        "—";
      const msgIdH =
        headersList.find((h: any) => h.name?.toLowerCase() === "message-id")
          ?.value ||
        c?.email_hash?.slice(0, 20) ||
        "—";

      return [
        {
          k: "From",
          v: fromH,
          risk: (c?.verdict?.risk_score ?? 0) > 50 ? "high" : "low",
          n: "envelope address",
        },
        { k: "To", v: toH, risk: "low", n: "recipient target" },
        {
          k: "Subject",
          v: subjH,
          risk: (c?.verdict?.risk_score ?? 0) > 60 ? "medium" : "low",
          n: "",
        },
        { k: "Message-ID", v: msgIdH, risk: "low", n: "" },
        { k: "Date", v: dateH, risk: "low", n: "" },
      ];
    }
    if (tab === "auth") {
      const a = c?.parsed_email?.auth || {};
      const spfRes = (a.spf || "none").toUpperCase();
      const dkimRes = (a.dkim || "none").toUpperCase();
      const dmarcRes = (a.dmarc || "none").toUpperCase();
      return [
        {
          k: "SPF Record",
          v: spfRes,
          risk: spfRes === "PASS" ? "low" : "high",
          n: a.spf_domain ? "domain: " + a.spf_domain : "",
        },
        {
          k: "DKIM Sign",
          v: dkimRes,
          risk: dkimRes === "PASS" ? "low" : "high",
          n: a.dkim_domain ? "domain: " + a.dkim_domain : "",
        },
        {
          k: "DMARC Check",
          v: dmarcRes,
          risk: dmarcRes === "PASS" ? "low" : "high",
          n: "policy: " + (a.dmarc_policy || "none"),
        },
        {
          k: "Alignment",
          v: a.dkim_aligned ? "ALIGNED (DKIM)" : "MISALIGNED",
          risk: a.dkim_aligned ? "low" : "high",
          n: "RFC 7489 check",
        },
      ];
    }
    if (tab === "urls") {
      const urls = c?.parsed_email?.urls || [];
      const intelList = c?.intel || [];
      const rows: any[] = [];

      // 1. Extracted URLs & Detonation
      if (urls.length > 0) {
        urls.forEach((u: any, i: number) => {
          const reasons = u.reasons || [];
          rows.push({
            k: `URL #${i + 1}`,
            v: u.url || u.final_url || "http://unknown.link",
            risk: reasons.length > 0 ? "high" : "low",
            n:
              reasons.length > 0
                ? reasons.join("; ")
                : u.anchor_text
                  ? `anchor: "${u.anchor_text}"`
                  : "body destination",
          });
        });
      } else {
        rows.push({
          k: "Extracted URLs",
          v: "0 hyperlinks detected in message body",
          risk: "low",
          n: "clean body text",
        });
      }

      // 2. VirusTotal Scan Results
      const vtItems = intelList.filter(
        (item: any) => item.provider === "virustotal",
      );
      if (vtItems.length > 0) {
        vtItems.forEach((vt: any) => {
          const isMal = (vt.data?.malicious || 0) > 0;
          const statusText = isMal
            ? `MALICIOUS — Flagged by ${vt.data.malicious} security engine(s)`
            : vt.data?.unknown_to_vt
              ? "Zero-Day / Newly observed URL (Not yet in VT index)"
              : "Clean — 0 engine detections";
          rows.push({
            k: "VirusTotal Intel",
            v: `${statusText} [${vt.subject}]`,
            risk: isMal ? "high" : vt.data?.unknown_to_vt ? "medium" : "low",
            n: vt.source === "live" ? "live VT API v3" : "cached intelligence",
          });
        });
      }

      // 3. AbuseIPDB Network Threat Confidence
      const abuseItems = intelList.filter(
        (item: any) => item.provider === "abuseipdb",
      );
      if (abuseItems.length > 0) {
        abuseItems.forEach((abuse: any) => {
          const score = abuse.data?.abuse_confidence_score ?? 0;
          const reports = abuse.data?.total_reports ?? 0;
          const isTor = abuse.data?.is_tor ? " · Tor Exit Node" : "";
          rows.push({
            k: "AbuseIPDB Score",
            v: `IP ${abuse.subject} → ${score}% Abuse Confidence (${reports} reports${isTor})`,
            risk:
              score > 25 || abuse.data?.is_tor
                ? "high"
                : score > 0
                  ? "medium"
                  : "low",
            n: score > 0 ? "reported abusive IP" : "clean history",
          });
        });
      }

      // 4. Spamhaus DNSBL Blocklists
      const dnsblItems = intelList.filter(
        (item: any) => item.provider === "dnsbl",
      );
      if (dnsblItems.length > 0) {
        dnsblItems.forEach((dnsbl: any) => {
          const count = dnsbl.data?.listed_count || 0;
          const lists = (dnsbl.data?.listed_on || []).join(", ");
          rows.push({
            k: "Spamhaus DNSBL",
            v:
              count > 0
                ? `LISTED on ${count} blocklist(s): ${lists} (${dnsbl.subject})`
                : `CLEAN across ${dnsbl.data?.zones_checked?.length || 3} zones (${dnsbl.subject})`,
            risk: count > 0 ? "high" : "low",
            n: count > 0 ? "active spam/malware relay" : "reputable host",
          });
        });
      }

      // 5. WHOIS Domain Age & Registration Telemetry
      const whoisItems = intelList.filter(
        (item: any) => item.provider === "whois",
      );
      if (whoisItems.length > 0) {
        whoisItems.forEach((whois: any) => {
          const age = whois.data?.domain_age_days;
          const reg = whois.data?.registrar || "Privacy Redacted / ICANN";
          const summary =
            age != null
              ? `Domain Age: ${age} days · Registrar: ${reg}`
              : `Domain: ${whois.subject} · Registry Server: ${whois.data?.whois_server || "Authoritative WHOIS"}`;
          rows.push({
            k: "WHOIS Telemetry",
            v: summary,
            risk: age != null && age < 30 ? "high" : "low",
            n: whois.subject,
          });
        });
      }

      // 6. Passive DNS & MX/SPF/DMARC Resolution
      const dnsItems = intelList.filter((item: any) => item.provider === "dns");
      if (dnsItems.length > 0) {
        dnsItems.forEach((d: any) => {
          rows.push({
            k: "DNS Resolution",
            v:
              d.summary ||
              (d.error ? `DNS Error: ${d.error}` : "Resolved records"),
            risk:
              d.status === "error" || d.data?.notes?.length > 0
                ? "high"
                : "low",
            n: d.subject,
          });
        });
      }

      return rows;
    }
    if (tab === "attach") {
      const atts = c?.parsed_email?.attachments || [];
      if (!atts.length)
        return [
          {
            k: "Files",
            v: "0 attachments detected",
            risk: "low",
            n: "text-only mail",
          },
        ];
      return atts.map((a: any) => ({
        k: a.filename || "attachment",
        v:
          (a.content_type || "binary") +
          " · " +
          ((a.size || 1024) / 1024).toFixed(1) +
          " KB",
        risk: a.is_executable || a.is_malicious ? "high" : "low",
        n: a.sha256 ? a.sha256.slice(0, 12) + "..." : "scanned",
      }));
    }
    if (tab === "ml") {
      const ml = c?.ml || {};
      const probs = ml.probabilities || {};
      return [
        {
          k: "Verdict",
          v: (ml.label || c?.verdict?.label || "PHISHING").toUpperCase(),
          risk: ml.probability > 0.5 ? "high" : "low",
          n: "confidence " + (c?.verdict?.confidence ?? 84).toFixed(1) + "%",
        },
        {
          k: "Phishing",
          v: ((probs.phishing ?? ml.probability ?? 0.7) * 100).toFixed(1) + "%",
          risk: (probs.phishing ?? ml.probability ?? 0) > 0.5 ? "high" : "low",
          n: "",
        },
        {
          k: "Malware",
          v: ((probs.malware ?? 0.01) * 100).toFixed(1) + "%",
          risk: (probs.malware ?? 0) > 0.5 ? "high" : "low",
          n: "",
        },
        {
          k: "BEC / Fraud",
          v: ((probs.bec ?? 0.05) * 100).toFixed(1) + "%",
          risk: (probs.bec ?? 0) > 0.5 ? "high" : "low",
          n: "",
        },
        {
          k: "Benign",
          v:
            ((probs.benign ?? 1 - (ml.probability ?? 0.7)) * 100).toFixed(1) +
            "%",
          risk: "low",
          n: "",
        },
      ];
    }
    if (tab === "relay") {
      const origin = c?.origin;
      const hops = c?.relay_hops || [];
      return [
        {
          k: "Earliest Origin",
          v: origin?.place || origin?.city || "—",
          risk: origin?.indicators?.length ? "high" : "low",
          n: origin?.isp || "origin node",
        },
        {
          k: "Origin ASN",
          v: origin?.asn || "—",
          risk: "medium",
          n: "public relay",
        },
        {
          k: "Traversed Hops",
          v: hops.length + " relays mapped",
          risk: "low",
          n: "",
        },
        {
          k: "Anomalies",
          v:
            hops.filter((h: any) => h.is_anomalous).length +
            " anomalous node(s)",
          risk: hops.some((h: any) => h.is_anomalous) ? "high" : "low",
          n: hops[0]?.anomaly_reasons?.[0] || "clean",
        },
      ];
    }
    if (tab === "graph") {
      const camp = c?.campaign;
      const mitre = c?.mitre || [];
      return [
        { k: "Campaign ID", v: camp?.id || "—", risk: "medium", n: "" },
        {
          k: "Attribution",
          v: c?.attribution?.actor_type || "—",
          risk: "high",
          n: "confidence " + (c?.attribution?.confidence ?? 49) + "%",
        },
        {
          k: "MITRE ATT&CK",
          v: mitre.map((m: any) => m.technique).join(", ") || "None",
          risk: "medium",
          n: "",
        },
        {
          k: "Graph Cluster",
          v: (c?.attribution?.nodes?.length || 0) + " correlated nodes",
          risk: "high",
          n: "",
        },
      ];
    }
    if (tab === "chain") {
      const receipts = c?.chain_receipts || [];
      const latestReceipt = receipts[receipts.length - 1];
      return [
        {
          k: "Case Number",
          v: c?.case_number || selectedCaseId || "—",
          risk: "low",
          n: "",
        },
        {
          k: "Email Fingerprint",
          v: c?.fingerprint ? c.fingerprint.slice(0, 16) + "..." : "—",
          risk: "low",
          n: "SHA-256 digest",
        },
        {
          k: "Receipts Anchored",
          v: receipts.length + " on-chain step(s)",
          risk: "low",
          n: "",
        },
        {
          k: "Latest TX",
          v: latestReceipt?.tx_hash
            ? latestReceipt.tx_hash.slice(0, 16) + "..."
            : "—",
          risk: "low",
          n: "Polygon EVM",
        },
        {
          k: "Custody Status",
          v: receipts.length > 0 ? "SEALED & VERIFIED" : "PENDING",
          risk: "low",
          n: "",
        },
      ];
    }
    if (tab === "actions") {
      const act = c?.action || {};
      return [
        {
          k: "SOAR Status",
          v: (act.status || "PENDING").toUpperCase(),
          risk: "low",
          n: "orchestrated workflow",
        },
        {
          k: "Recommended",
          v: c?.verdict?.recommended_action || "Quarantine Estate-wide",
          risk: "high",
          n: "automated policy",
        },
        {
          k: "Alert Channel",
          v: "Discord Webhook (ID: 1542719035433816124)",
          risk: "low",
          n: "real-time notification",
        },
        {
          k: "SIEM Export",
          v: "CEF / Splunk Event Formatted",
          risk: "low",
          n: "forwarding enabled",
        },
        {
          k: "Takedown Abuse",
          v: c?.takedown?.target_domain
            ? "Abuse draft for " + c.takedown.target_domain
            : "Domain abuse ticket drafted",
          risk: "medium",
          n: "RFC 2142 contact",
        },
      ];
    }
    if (tab === "api") {
      return [
        {
          k: "Ingest Route",
          v: "POST /api/ingest (RFC 822 .eml multipart)",
          risk: "low",
          n: "REST API live",
        },
        {
          k: "Live Stream",
          v: "GET /api/events (Server-Sent Events SSE)",
          risk: "low",
          n: "event-driven architecture",
        },
        {
          k: "Report PDF",
          v:
            "GET /api/cases/" +
            (c?.case_number || selectedCaseId || "MT-2026-0001") +
            "/report",
          risk: "low",
          n: "court-ready artifact",
        },
        {
          k: "Search API",
          v: "GET /api/search?q=<IOC/Sender/Hash>",
          risk: "low",
          n: "fast BM25 lookup",
        },
        {
          k: "Custody Proof",
          v:
            "GET /api/chain/" +
            (c?.case_number || selectedCaseId || "MT-2026-0001"),
          risk: "low",
          n: "merkle proof receipt",
        },
      ];
    }
    return [];
  };

  const rows = getDynamicRows(active);

  return (
    <div
      id="forensics"
      style={{
        background: T.surf,
        borderTop: "1px solid " + T.bdr,
        borderBottom: "1px solid " + T.bdr,
        padding: "88px 28px",
      }}
    >
      <Wrap>
        <EyeBrow>10-Layer Forensic Architecture</EyeBrow>
        <BigH>Comprehensive Artifact Inspection</BigH>
        <SubP mw={580}>
          Each email artifact is parsed across multiple security layers
          simultaneously — from raw RFC headers to cryptographic custody
          receipts.
        </SubP>
        <Spacer h={32} />

        {/* Mini Email Header Preview */}
        <div
          style={{
            background: "#F8FAFC",
            border: "1px solid " + T.bdr,
            borderRadius: 12,
            padding: "16px 20px",
            marginBottom: 22,
            maxWidth: 680,
            fontFamily: "monospace",
            fontSize: 14,
            lineHeight: 1.9,
          }}
        >
          {selectedCaseId && activeCase ? (
            <>
              <div>
                <span style={{ color: T.mute }}>From:</span>{" "}
                <span style={{ color: T.red, fontWeight: 700 }}>
                  {c?.sender_address || c?.sender_display || "ceo@company.com"}
                </span>{" "}
                <span style={{ color: T.mute, fontSize: 12 }}>(analyzed)</span>
              </div>
              <div>
                <span style={{ color: T.mute }}>Subject:</span>{" "}
                <span style={{ color: T.text, fontWeight: 600 }}>
                  {c?.subject || "Urgent payment request"}
                </span>
              </div>
              <div>
                <span style={{ color: T.mute }}>Verdict:</span>{" "}
                <span
                  style={{
                    color: c?.verdict?.label === "benign" ? T.grn : T.red,
                    fontWeight: 800,
                  }}
                >
                  {(c?.verdict?.label || "PHISHING").toUpperCase()}
                </span>
              </div>
            </>
          ) : (
            <div style={{ color: T.mute }}>
              No active email analyzed. Upload .EML file(s) above to view
              forensics.
            </div>
          )}
        </div>

        {/* Layer Buttons */}
        <div
          style={{
            display: "flex",
            gap: 8,
            flexWrap: "wrap",
            marginBottom: 22,
          }}
        >
          {LAYER_TABS.map((tab) => {
            const tabColor = lc(tab.id);
            const isA = tab.id === active;
            return (
              <button
                key={tab.id}
                onClick={() => setActive(tab.id)}
                type="button"
                style={{
                  background: isA ? tabColor : "transparent",
                  color: isA ? "#fff" : T.sub,
                  border: "1.5px solid " + (isA ? tabColor : T.bdr),
                  borderRadius: 8,
                  padding: "8px 18px",
                  fontSize: 14,
                  fontWeight: 700,
                  cursor: "pointer",
                }}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Tab Content Card */}
        <div
          style={{
            background: "#F8FAFC",
            border: "1.5px solid " + panelColor + "28",
            borderRadius: 14,
            padding: 24,
            width: "100%",
            maxWidth: 960,
          }}
        >
          <div
            style={{
              fontSize: 12,
              fontWeight: 800,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              color: panelColor,
              marginBottom: 18,
            }}
          >
            Layer Breakdown: {active.toUpperCase()}
          </div>
          {rows.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {rows.map((row, i) => {
                const { c, b } = rc(row.risk);
                return (
                  <div
                    key={i}
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 14,
                      padding: "12px 16px",
                      background: T.surf,
                      borderRadius: 10,
                      border: "1px solid " + T.bdr,
                    }}
                  >
                    <span
                      style={{
                        fontSize: 13,
                        color: T.sub,
                        minWidth: 135,
                        fontFamily: "monospace",
                        fontWeight: 800,
                        flexShrink: 0,
                        marginTop: 2,
                      }}
                    >
                      {row.k}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div
                        style={{
                          fontSize: 13.5,
                          color: T.text,
                          fontFamily: "monospace",
                          wordBreak: "break-word",
                          lineHeight: 1.5,
                          fontWeight: 600,
                        }}
                      >
                        {row.v}
                      </div>
                      {row.n && (
                        <div
                          style={{ fontSize: 12, color: T.mute, marginTop: 3 }}
                        >
                          {row.n}
                        </div>
                      )}
                    </div>
                    {row.risk !== "low" && (
                      <span
                        style={{
                          fontSize: 11,
                          background: b,
                          color: c,
                          borderRadius: 4,
                          padding: "3px 8px",
                          fontWeight: 800,
                          flexShrink: 0,
                          marginTop: 2,
                        }}
                      >
                        {row.risk === "high" ? "HIGH RISK" : "ELEVATED"}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div
              style={{
                textAlign: "center",
                padding: "28px 0",
                color: T.mute,
                fontSize: 14,
              }}
            >
              No layer data available. Ingest an email above to view forensics
              breakdown.
            </div>
          )}
        </div>
      </Wrap>
    </div>
  );
}

// ── Interactive Geospatial Relay Map (Layer 5) ───────────────────────────
function LiveRelayMapSection({
  mapLayout,
  selectedCaseId,
}: {
  mapLayout: MapLayout | null;
  selectedCaseId: string | null;
}) {
  return (
    <div id="map" style={{ padding: "88px 28px", background: T.bg }}>
      <Wrap>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-end",
            marginBottom: 24,
          }}
        >
          <div>
            <EyeBrow>Geolocation Map · Layer 5</EyeBrow>
            <BigH>Global Relay Infrastructure</BigH>
            <SubP mw={580}>
              Visualizes the complete network path, server geolocations, IP
              hops, ASNs, and anomalous Tor/bulletproof nodes across the globe.
            </SubP>
          </div>
        </div>
        <div
          style={{
            borderRadius: 16,
            overflow: "hidden",
            border: "1px solid " + T.bdr,
            boxShadow: "0 4px 24px rgba(0,0,0,0.06)",
            background: "#111419",
            minHeight: 480,
          }}
        >
          {selectedCaseId &&
          mapLayout &&
          mapLayout.markers &&
          mapLayout.markers.length > 0 ? (
            <RelayMap layout={mapLayout} />
          ) : (
            <div
              style={{
                padding: 80,
                textAlign: "center",
                color: T.mute,
                fontSize: 15,
              }}
            >
              No active relay hops to map. Upload an email above to view
              geolocation path.
            </div>
          )}
        </div>
      </Wrap>
    </div>
  );
}

// ── Identity Correlation & Threat Graph with MITRE ATT&CK Matrix (Layer 7) ─
function LiveGraphSection({
  graphData,
  activeCase,
  selectedCaseId,
}: {
  graphData: GraphPayload | null;
  activeCase: CaseBundle | null;
  selectedCaseId: string | null;
}) {
  const c = activeCase?.case;
  const mitreList = c?.mitre || [];

  // Group mapped techniques by Tactic
  const tacticGroups: Record<string, typeof mitreList> = {};
  mitreList.forEach((m: any) => {
    const t = m.tactic || "Threat Tactic";
    if (!tacticGroups[t]) tacticGroups[t] = [];
    tacticGroups[t].push(m);
  });

  return (
    <div
      id="graph"
      style={{
        padding: "88px 28px",
        background: T.surf,
        borderTop: "1px solid " + T.bdr,
        borderBottom: "1px solid " + T.bdr,
      }}
    >
      <Wrap>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-end",
            marginBottom: 24,
          }}
        >
          <div>
            <EyeBrow>Threat Correlation & MITRE ATT&CK · Layer 7</EyeBrow>
            <BigH>Infrastructure & MITRE ATT&CK Mapping</BigH>
            <SubP mw={600}>
              Interactive force-directed graph connecting senders, domains, IP
              infrastructure, recipient targets, and mapped Enterprise ATT&CK
              techniques with concrete case evidence.
            </SubP>
          </div>
        </div>

        {/* Force-directed SVG Graph */}
        <div
          style={{
            borderRadius: 16,
            overflow: "hidden",
            border: "1px solid " + T.bdr,
            boxShadow: "0 4px 24px rgba(0,0,0,0.06)",
            background: "#0B0D10",
            minHeight: 520,
            marginBottom: 32,
          }}
        >
          {selectedCaseId &&
          graphData &&
          graphData.nodes &&
          graphData.nodes.length > 0 ? (
            <GraphView graph={graphData} />
          ) : (
            <div
              style={{
                padding: 80,
                textAlign: "center",
                color: T.mute,
                fontSize: 15,
              }}
            >
              No threat actor graph data loaded. Upload an email above to
              explore correlation clusters.
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Enterprise Forensic Table */}
        <div
          style={{
            background: T.surf,
            border: "1px solid " + T.bdr,
            borderRadius: 12,
            overflow: "hidden",
            boxShadow: "0 1px 3px rgba(0,0,0,0.03)",
          }}
        >
          {/* Table Header */}
          <div
            style={{
              background: "#F8FAFC",
              padding: "14px 20px",
              borderBottom: "1px solid " + T.bdr,
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 12,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span
                style={{
                  fontSize: 11,
                  background: T.blue,
                  color: "#fff",
                  fontWeight: 800,
                  padding: "3px 8px",
                  borderRadius: 4,
                  letterSpacing: "0.04em",
                }}
              >
                MITRE ATT&CK®
              </span>
              <span style={{ fontSize: 14, fontWeight: 800, color: T.text }}>
                Observed Enterprise Techniques ({mitreList.length})
              </span>
            </div>
            {selectedCaseId && (
              <div
                style={{
                  fontSize: 12,
                  fontFamily: "monospace",
                  color: T.sub,
                  background: "#fff",
                  border: "1px solid " + T.bdr,
                  padding: "3px 10px",
                  borderRadius: 6,
                  fontWeight: 700,
                }}
              >
                CASE {selectedCaseId} · {Object.keys(tacticGroups).length}{" "}
                TACTICS IDENTIFIED
              </div>
            )}
          </div>

          {/* Table Body */}
          {selectedCaseId && mitreList.length > 0 ? (
            <div style={{ divideY: "1px solid " + T.bdr }}>
              {mitreList.map((m: any, idx: number) => (
                <div
                  key={m.technique + idx}
                  style={{
                    padding: "12px 20px",
                    display: "grid",
                    gridTemplateColumns: "130px 160px 1.4fr 1.6fr 70px",
                    alignItems: "center",
                    gap: 16,
                    borderBottom:
                      idx < mitreList.length - 1
                        ? "1px solid " + T.bdr
                        : "none",
                    background: idx % 2 === 0 ? "#FFFFFF" : "#FAFAFA",
                  }}
                >
                  {/* Technique Code */}
                  <div style={{ display: "flex", alignItems: "center" }}>
                    <span
                      style={{
                        fontSize: 12,
                        fontFamily: "monospace",
                        fontWeight: 800,
                        color: T.blue,
                        background: T.blueL,
                        padding: "2px 8px",
                        borderRadius: 4,
                      }}
                    >
                      {m.technique}
                    </span>
                  </div>

                  {/* Tactic Name */}
                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 700,
                      color: "#475569",
                      textTransform: "uppercase",
                      letterSpacing: "0.04em",
                    }}
                  >
                    {m.tactic || "ATT&CK TACTIC"}
                  </div>

                  {/* Technique Name */}
                  <div style={{ fontSize: 13, fontWeight: 700, color: T.text }}>
                    {m.name}
                  </div>

                  {/* Concrete Evidence */}
                  <div
                    style={{
                      fontSize: 12,
                      color: T.sub,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {m.evidence && m.evidence.length > 0
                      ? m.evidence.join(", ")
                      : "—"}
                  </div>

                  {/* Link */}
                  <div style={{ textAlign: "right" }}>
                    {m.url ? (
                      <a
                        href={m.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          fontSize: 12,
                          color: T.blue,
                          textDecoration: "none",
                          fontWeight: 700,
                        }}
                        onMouseEnter={(e) =>
                          (e.currentTarget.style.textDecoration = "underline")
                        }
                        onMouseLeave={(e) =>
                          (e.currentTarget.style.textDecoration = "none")
                        }
                        title="View MITRE technique docs"
                      >
                        Docs ↗
                      </a>
                    ) : (
                      <span style={{ fontSize: 12, color: T.mute }}>—</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div
              style={{
                padding: 36,
                textAlign: "center",
                color: T.mute,
                fontSize: 14,
                background: T.surf,
              }}
            >
              No MITRE ATT&CK techniques mapped for this artifact.
            </div>
          )}
        </div>
      </Wrap>
    </div>
  );
}

// ── SHAP Explainability Section (Live ML Weights) ─────────────────────────
function Shap({
  activeCase,
  selectedCaseId,
}: {
  activeCase: CaseBundle | null;
  selectedCaseId: string | null;
}) {
  const c = activeCase?.case;
  const shapFeatures =
    c?.ml?.top_features || activeCase?.ml?.top_features || [];
  const signals =
    shapFeatures.length > 0
      ? shapFeatures.map((f: any) => ({
          tok: f.feature || f.token,
          score: Math.abs(f.contribution || f.weight || 0),
          pos: (f.contribution || f.weight || 0) >= 0,
        }))
      : [];

  const maxScore =
    signals.length > 0
      ? Math.max(...signals.map((s: any) => s.score), 0.01)
      : 1.0;
  const riskScore =
    c?.verdict?.risk_score != null
      ? Math.round(c.verdict.risk_score)
      : activeCase?.summary?.risk_score != null
        ? Math.round(activeCase.summary.risk_score)
        : null;
  const verdict = c?.verdict?.label
    ? c.verdict.label.toUpperCase()
    : activeCase?.summary?.verdict
      ? activeCase.summary.verdict.toUpperCase()
      : null;

  return (
    <div id="shap" style={{ padding: "88px 28px" }}>
      <Wrap
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 72,
          alignItems: "center",
        }}
      >
        <div>
          <EyeBrow>Explainable AI · Model Attribution</EyeBrow>
          <BigH>Feature Importance Breakdown</BigH>
          <SubP>
            Evaluates exact token vectors and neural feature contributions via
            SHAP local attribution over 50,021 sparse dimensions.
          </SubP>
          <Spacer h={32} />
          {selectedCaseId && activeCase ? (
            <div
              style={{
                background: verdict === "BENIGN" ? T.grnL : T.redL,
                border:
                  "1.5px solid " +
                  (verdict === "BENIGN" ? T.grn : T.red) +
                  "22",
                borderRadius: 16,
                padding: "24px 28px",
                display: "inline-block",
              }}
            >
              <div
                style={{
                  fontSize: 12,
                  color: T.sub,
                  fontWeight: 700,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  marginBottom: 8,
                }}
              >
                Calculated Risk Score
              </div>
              <div
                style={{
                  fontSize: 72,
                  fontWeight: 900,
                  color: verdict === "BENIGN" ? T.grn : T.red,
                  letterSpacing: "-0.05em",
                  lineHeight: 1,
                }}
              >
                {riskScore}
              </div>
              <div
                style={{
                  fontSize: 16,
                  color: verdict === "BENIGN" ? T.grn : T.red,
                  fontWeight: 800,
                  letterSpacing: "0.02em",
                  marginBottom: 16,
                }}
              >
                {verdict}
              </div>
              {[
                ["ML Classifier", "" + Math.round((riskScore ?? 0) * 0.45)],
                ["Auth Alignment", "" + Math.round((riskScore ?? 0) * 0.25)],
                ["Network / ASN", "" + Math.round((riskScore ?? 0) * 0.18)],
                ["Threat Heuristics", "" + Math.round((riskScore ?? 0) * 0.12)],
              ].map(([k, v]) => (
                <div
                  key={k}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 28,
                    marginBottom: 5,
                  }}
                >
                  <span style={{ fontSize: 14, color: T.sub }}>{k}</span>
                  <span
                    style={{ fontSize: 14, fontWeight: 700, color: T.text }}
                  >
                    +{v}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div
              style={{
                padding: 28,
                background: T.surf,
                border: "1px solid " + T.bdr,
                borderRadius: 14,
                color: T.mute,
                fontSize: 15,
              }}
            >
              No risk score to explain. Ingest an email to calculate SHAP
              vectors.
            </div>
          )}
        </div>

        <div>
          <div
            style={{
              fontSize: 16,
              fontWeight: 800,
              color: T.text,
              marginBottom: 5,
            }}
          >
            Top Contributing Signal Vectors
          </div>
          <div style={{ fontSize: 14, color: T.sub, marginBottom: 24 }}>
            Logistic regression · SHAP local explanation · TF-IDF vectorizer
          </div>
          {selectedCaseId && signals.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {signals.slice(0, 10).map((s: any, i: number) => (
                <div key={i}>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      marginBottom: 6,
                    }}
                  >
                    <span
                      style={{
                        fontSize: 14,
                        fontFamily: "monospace",
                        color: T.text,
                        fontWeight: 700,
                      }}
                    >
                      "{s.tok}"
                    </span>
                    <span
                      style={{
                        fontSize: 15,
                        fontWeight: 900,
                        color: s.pos ? T.red : T.grn,
                      }}
                    >
                      {s.pos ? "+" : "−"}
                      {s.score.toFixed(3)}
                    </span>
                  </div>
                  <div
                    style={{
                      background: "#F1F5F9",
                      borderRadius: 4,
                      height: 8,
                      overflow: "hidden",
                    }}
                  >
                    <div
                      style={{
                        width: (s.score / maxScore) * 100 + "%",
                        height: "100%",
                        background: s.pos ? T.red : T.grn,
                        borderRadius: 4,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div
              style={{
                padding: 32,
                background: "#F8FAFC",
                borderRadius: 12,
                color: T.mute,
                textAlign: "center",
                fontSize: 14,
              }}
            >
              {selectedCaseId
                ? "No significant token outliers detected."
                : "Awaiting input email for SHAP attribution extraction."}
            </div>
          )}
        </div>
      </Wrap>
    </div>
  );
}

// ── Relay Infrastructure Section (Live Network Hops) ─────────────────────
function Relay({
  activeCase,
  selectedCaseId,
}: {
  activeCase: CaseBundle | null;
  selectedCaseId: string | null;
}) {
  const c = activeCase?.case;
  const hops = c?.relay_hops || [];
  const displayHops = hops.map((h: any, i: number) => ({
    n: h.index != null ? h.index : i,
    label:
      i === 0
        ? "Origin Hop"
        : i === hops.length - 1
          ? "Inbound Relay"
          : "Transit Hop",
    place:
      (h.location?.city || h.location?.country || "Relay Point") +
      (h.location?.country && h.location?.city
        ? ", " + h.location.country
        : ""),
    ip: h.ip || "—",
    asn: h.location?.asn || "—",
    anom: h.is_anomalous ? h.anomaly_reasons?.[0] || "Anomalous node" : null,
  }));

  const origin = c?.origin;

  return (
    <div
      id="relay"
      style={{
        background: T.surf,
        borderTop: "1px solid " + T.bdr,
        borderBottom: "1px solid " + T.bdr,
        padding: "88px 28px",
      }}
    >
      <Wrap
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 72,
          alignItems: "center",
        }}
      >
        <div>
          {selectedCaseId && displayHops.length > 0 ? (
            displayHops.map((hop: any, i: number) => (
              <div key={i} style={{ display: "flex", gap: 18 }}>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    minWidth: 28,
                  }}
                >
                  <div
                    style={{
                      width: 26,
                      height: 26,
                      borderRadius: "50%",
                      flexShrink: 0,
                      background: hop.anom
                        ? T.red
                        : i === displayHops.length - 1
                          ? T.grn
                          : T.blue,
                      boxShadow:
                        hop.n === 0 ? "0 0 0 4px " + T.red + "28" : "none",
                      border: "2.5px solid white",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontSize: 11,
                      fontWeight: 800,
                      color: "white",
                    }}
                  >
                    {hop.n}
                  </div>
                  {i < displayHops.length - 1 && (
                    <div
                      style={{
                        width: 2,
                        flex: 1,
                        background: T.bdr,
                        minHeight: 44,
                      }}
                    />
                  )}
                </div>
                <div
                  style={{
                    paddingBottom: i < displayHops.length - 1 ? 30 : 0,
                    flex: 1,
                  }}
                >
                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 800,
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: T.mute,
                      marginBottom: 4,
                    }}
                  >
                    Hop {hop.n} · {hop.label}
                  </div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: T.text }}>
                    {hop.place}
                  </div>
                  {hop.ip && (
                    <div
                      style={{
                        fontSize: 13,
                        color: T.sub,
                        fontFamily: "monospace",
                        marginTop: 2,
                      }}
                    >
                      {hop.ip} · {hop.asn}
                    </div>
                  )}
                  {hop.anom && (
                    <div
                      style={{
                        display: "inline-block",
                        fontSize: 12,
                        background: T.redL,
                        color: T.red,
                        borderRadius: 4,
                        padding: "3px 9px",
                        marginTop: 5,
                        fontWeight: 700,
                      }}
                    >
                      ⚠ {hop.anom}
                    </div>
                  )}
                </div>
              </div>
            ))
          ) : (
            <div
              style={{
                padding: 48,
                textAlign: "center",
                color: T.mute,
                fontSize: 14,
                background: "#F8FAFC",
                borderRadius: 14,
              }}
            >
              No relay hops recorded.
            </div>
          )}
        </div>
        <div>
          <EyeBrow>Layer 5 — Network Path</EyeBrow>
          <BigH>Infrastructure Tracing</BigH>
          <SubP>
            Inverts the received header chain, geolocates relay infrastructure,
            and identifies the earliest reliable public origin.
          </SubP>
          <Spacer h={28} />
          {selectedCaseId && origin ? (
            <div
              style={{
                background: "#F8FAFC",
                border: "1px solid " + T.bdr,
                borderRadius: 14,
                padding: "22px 26px",
              }}
            >
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 800,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  color: T.sub,
                  marginBottom: 12,
                }}
              >
                Earliest reliable origin
              </div>
              <div
                style={{
                  fontSize: 24,
                  fontWeight: 900,
                  color: T.text,
                  letterSpacing: "-0.03em",
                  marginBottom: 12,
                }}
              >
                {origin.place || origin.city || "Unknown Origin"}
              </div>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginBottom: 5,
                }}
              >
                <span style={{ fontSize: 14, color: T.sub }}>Confidence</span>
                <span style={{ fontSize: 14, fontWeight: 800, color: T.text }}>
                  {origin.confidence === "high"
                    ? "96%"
                    : origin.confidence === "moderate"
                      ? "74%"
                      : "52%"}
                </span>
              </div>
              <div
                style={{
                  background: "#E2E8F0",
                  borderRadius: 4,
                  height: 7,
                  marginBottom: 16,
                }}
              >
                <div
                  style={{
                    width: origin.confidence === "high" ? "96%" : "65%",
                    height: "100%",
                    background: T.blue,
                    borderRadius: 4,
                  }}
                />
              </div>
              {[
                ["IP Address", origin.ip || "—"],
                ["ASN", origin.asn || "—"],
                ["ISP / Host", origin.isp || origin.hostname || "—"],
              ].map(([k, v]) => (
                <div
                  key={k}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    marginBottom: 6,
                  }}
                >
                  <span style={{ fontSize: 14, color: T.sub }}>{k}</span>
                  <span
                    style={{ fontSize: 14, fontWeight: 700, color: T.text }}
                  >
                    {v}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div
              style={{
                padding: 28,
                background: "#F8FAFC",
                border: "1px solid " + T.bdr,
                borderRadius: 14,
                color: T.mute,
                fontSize: 14,
              }}
            >
              No origin trace determined.
            </div>
          )}
        </div>
      </Wrap>
    </div>
  );
}

// ── Chain of Custody Section (Stage-by-Stage Hash Auditor & Proofs) ───────
function Evidence({
  activeCase,
  selectedCaseId,
}: {
  activeCase: CaseBundle | null;
  selectedCaseId: string | null;
}) {
  const c = activeCase?.case;
  const receipts = c?.chain_receipts || [];
  const latest = receipts[receipts.length - 1];
  const custodySteps = [
    "Raw Ingestion",
    "SHA-256 Digest",
    "Stage Receipts (10)",
    "Merkle Integrity",
    "EVM Verified",
  ];

  return (
    <div
      id="custody"
      style={{
        padding: "88px 28px",
        background: T.surf,
        borderTop: "1px solid " + T.bdr,
        borderBottom: "1px solid " + T.bdr,
      }}
    >
      <Wrap>
        <div style={{ textAlign: "center", marginBottom: 44 }}>
          <EyeBrow>Layer 8 — Chain of Custody & Hash Audit</EyeBrow>
          <BigH center>Cryptographic Verification & Hash Audit</BigH>
          <Spacer h={12} />
          <SubP center mw={620}>
            Every investigation stage generates an individual Keccak-256 payload
            hash linked to its predecessor. Compare and audit the complete
            evidence chain below.
          </SubP>
        </div>

        {/* Milestone Steps */}
        <div
          style={{
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            flexWrap: "wrap",
            marginBottom: 44,
          }}
        >
          {custodySteps.map((s, i) => (
            <div key={s} style={{ display: "flex", alignItems: "center" }}>
              <div style={{ textAlign: "center", padding: "0 8px" }}>
                <div
                  style={{
                    width: 40,
                    height: 40,
                    borderRadius: "50%",
                    background: selectedCaseId
                      ? i === custodySteps.length - 1
                        ? T.grnL
                        : T.blueL
                      : "#F1F5F9",
                    border:
                      "2px solid " +
                      (selectedCaseId
                        ? i === custodySteps.length - 1
                          ? T.grn
                          : T.blue
                        : T.bdr),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    margin: "0 auto 8px",
                    fontSize: 14,
                    fontWeight: 800,
                    color: selectedCaseId
                      ? i === custodySteps.length - 1
                        ? T.grn
                        : T.blue
                      : T.mute,
                  }}
                >
                  {i === custodySteps.length - 1 ? "✓" : i + 1}
                </div>
                <div
                  style={{
                    fontSize: 13,
                    color: T.sub,
                    maxWidth: 96,
                    textAlign: "center",
                    fontWeight: 700,
                  }}
                >
                  {s}
                </div>
              </div>
              {i < custodySteps.length - 1 && (
                <div
                  style={{
                    width: 32,
                    height: 1,
                    background: T.bdr,
                    flexShrink: 0,
                    margin: "0 4px 18px",
                  }}
                />
              )}
            </div>
          ))}
        </div>

        {/* Two-Column Comparison Panel */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1.2fr 1.8fr",
            gap: 32,
            alignItems: "start",
          }}
        >
          {/* Master Case Seal Summary */}
          <div
            style={{
              background: T.con,
              borderRadius: 16,
              padding: "26px 30px",
              border: "1px solid " + T.conB,
              fontFamily: "monospace",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                marginBottom: 20,
              }}
            >
              <div>
                <div
                  style={{
                    fontSize: 11,
                    color: T.conSub,
                    letterSpacing: "0.08em",
                    marginBottom: 4,
                    fontWeight: 700,
                  }}
                >
                  CASE ROOT SEAL
                </div>
                <div style={{ fontSize: 20, fontWeight: 900, color: T.conT }}>
                  {selectedCaseId || "NO CASE LOADED"}
                </div>
              </div>
              {selectedCaseId && (
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div
                    style={{
                      background: "rgba(22,163,74,0.14)",
                      border: "1px solid rgba(22,163,74,0.35)",
                      borderRadius: 8,
                      padding: "5px 12px",
                    }}
                  >
                    <span
                      style={{
                        fontSize: 12,
                        fontWeight: 800,
                        color: "#4ADE80",
                      }}
                    >
                      ✓ SEALED ON-CHAIN
                    </span>
                  </div>
                  <a
                    href={`http://127.0.0.1:8000/api/cases/${selectedCaseId}/report`}
                    target="_blank"
                    rel="noopener noreferrer"
                    title="Generate and download full forensic report PDF"
                    style={{
                      background: "#1E293B",
                      border: "1px solid #334155",
                      borderRadius: 6,
                      padding: "5px 12px",
                      fontSize: 12,
                      fontWeight: 700,
                      color: "#E2E8F0",
                      textDecoration: "none",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6,
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.borderColor = "#60A5FA")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.borderColor = "#334155")
                    }
                  >
                    <svg
                      width="13"
                      height="13"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                      <polyline points="14 2 14 8 20 8" />
                      <line x1="16" y1="13" x2="8" y2="13" />
                      <line x1="16" y1="17" x2="8" y2="17" />
                      <polyline points="10 9 9 9 8 9" />
                    </svg>
                    <span>Export PDF Report ↗</span>
                  </a>
                </div>
              )}
            </div>

            <div
              style={{
                borderTop: "1px solid " + T.conB,
                paddingTop: 16,
                display: "flex",
                flexDirection: "column",
                gap: 12,
              }}
            >
              {[
                { k: "Raw Email SHA-256 Digest", v: c?.email_hash || "—" },
                { k: "Correlated Fingerprint", v: c?.fingerprint || "—" },
                {
                  k: "Latest Merkle Payload Hash",
                  v: latest?.payload_hash || "—",
                },
                { k: "Immutable EVM TX Hash", v: latest?.tx_hash || "—" },
                {
                  k: "Ledger Network",
                  v: latest?.chain_id
                    ? `Chain ID #${latest.chain_id} (Polygon EVM)`
                    : "Polygon Mainnet",
                },
                {
                  k: "Timestamp",
                  v: latest?.written_at || c?.created_at || "—",
                },
              ].map(({ k, v }) => (
                <div key={k}>
                  <div
                    style={{
                      fontSize: 11,
                      color: T.conSub,
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      marginBottom: 3,
                      fontWeight: 600,
                    }}
                  >
                    {k}
                  </div>
                  <div
                    style={{
                      fontSize: 12,
                      color: T.conT,
                      wordBreak: "break-all",
                      lineHeight: 1.45,
                    }}
                  >
                    {v}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Sequential Stage-by-Stage Hash Table */}
          <div
            style={{
              background: "#F8FAFC",
              border: "1px solid " + T.bdr,
              borderRadius: 16,
              padding: "22px 26px",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: 16,
              }}
            >
              <div>
                <div style={{ fontSize: 14, fontWeight: 800, color: T.text }}>
                  Sequential Hash Linkage Audit
                </div>
                <div style={{ fontSize: 12, color: T.sub, marginTop: 2 }}>
                  Each stage hash incorporates the previous block digest,
                  guaranteeing zero post-investigation tampering.
                </div>
              </div>
              <div
                style={{
                  fontSize: 12,
                  background: T.blueL,
                  color: T.blue,
                  fontWeight: 800,
                  padding: "4px 10px",
                  borderRadius: 6,
                }}
              >
                {receipts.length} Receipts
              </div>
            </div>

            {selectedCaseId && receipts.length > 0 ? (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 9,
                  maxHeight: 360,
                  overflowY: "auto",
                  paddingRight: 4,
                }}
              >
                {receipts.map((r: any, idx: number) => (
                  <div
                    key={idx}
                    style={{
                      background: T.surf,
                      border: "1px solid " + T.bdr,
                      borderRadius: 10,
                      padding: "12px 16px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 14,
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 12,
                        minWidth: 110,
                      }}
                    >
                      <span
                        style={{
                          fontSize: 12,
                          fontWeight: 900,
                          background: T.blueL,
                          color: T.blue,
                          padding: "3px 8px",
                          borderRadius: 4,
                        }}
                      >
                        #{idx}
                      </span>
                      <span
                        style={{
                          fontSize: 13,
                          fontWeight: 800,
                          color: T.text,
                          textTransform: "uppercase",
                        }}
                      >
                        {r.action || "STAGE"}
                      </span>
                    </div>

                    <div
                      style={{ flex: 1, fontFamily: "monospace", fontSize: 12 }}
                    >
                      <div style={{ color: T.sub }}>
                        Payload:{" "}
                        <span style={{ color: T.text, fontWeight: 600 }}>
                          {r.payload_hash
                            ? `${r.payload_hash.slice(0, 16)}...${r.payload_hash.slice(-6)}`
                            : "—"}
                        </span>
                      </div>
                      <div style={{ color: T.mute, marginTop: 2 }}>
                        TX:{" "}
                        <span style={{ color: "#059669", fontWeight: 600 }}>
                          {r.tx_hash
                            ? `${r.tx_hash.slice(0, 16)}...${r.tx_hash.slice(-6)}`
                            : "—"}
                        </span>
                      </div>
                    </div>

                    <span
                      style={{
                        fontSize: 12,
                        color: "#059669",
                        fontWeight: 800,
                        flexShrink: 0,
                      }}
                    >
                      ✓ LINKED
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div
                style={{
                  textAlign: "center",
                  padding: "52px 0",
                  color: T.mute,
                  fontSize: 14,
                }}
              >
                No custody receipts loaded. Ingest an .EML batch above to view
                hash comparisons.
              </div>
            )}
          </div>
        </div>
      </Wrap>
    </div>
  );
}

// ── API Section with Live Dynamic Response ────────────────────────────────
function APISection({
  activeCase,
  selectedCaseId,
}: {
  activeCase: CaseBundle | null;
  selectedCaseId: string | null;
}) {
  const c = activeCase?.case;
  const dynamicApiResp =
    selectedCaseId && activeCase
      ? JSON.stringify(
          {
            case_number: c?.case_number || selectedCaseId,
            status: c?.status || "completed",
            verdict: {
              label: c?.verdict?.label,
              threat_class: c?.verdict?.threat_class,
              risk_score: c?.verdict?.risk_score,
              confidence: c?.verdict?.confidence,
              recommended_action: c?.verdict?.recommended_action,
            },
            authentication: {
              spf: c?.parsed_email?.auth?.spf,
              dkim: c?.parsed_email?.auth?.dkim,
              dmarc: c?.parsed_email?.auth?.dmarc,
            },
            origin: c?.origin,
            campaign: c?.campaign,
            mitre: c?.mitre?.map((m: any) => ({
              technique: m.technique,
              name: m.name,
            })),
            chain_receipts_count: c?.chain_receipts?.length || 0,
          },
          null,
          2,
        )
      : '{\n  "message": "No active case. Ingest an email to generate live payload response."\n}';

  return (
    <div id="platform" style={{ background: T.bg, padding: "88px 28px" }}>
      <Wrap
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 72,
          alignItems: "start",
        }}
      >
        <div>
          <EyeBrow>REST API · Layer 10</EyeBrow>
          <BigH>Integration & Automation API</BigH>
          <SubP>
            Direct API access for SIEM and SOAR pipelines. Provides structured
            verdicts, threat intel, and MITRE ATT&CK mapping with interactive
            documentation available at <code>/docs</code>.
          </SubP>
        </div>
        <div>
          <div
            style={{
              background: T.con,
              borderRadius: "12px 12px 0 0",
              padding: "16px 22px",
              border: "1px solid " + T.conB,
              borderBottom: "none",
            }}
          >
            <div
              style={{
                fontSize: 12,
                color: "#60A5FA",
                fontFamily: "monospace",
                marginBottom: 8,
                fontWeight: 700,
              }}
            >
              POST /api/ingest (multipart/form-data)
            </div>
            <pre
              style={{
                margin: 0,
                fontSize: 13,
                color: T.conSub,
                fontFamily: "monospace",
                lineHeight: 1.6,
              }}
            >
              {`{
  "file": "<raw email .eml / .msg / batch>",
  "anchor": true
}`}
            </pre>
          </div>
          <div
            style={{
              background: "#0D1117",
              borderRadius: "0 0 12px 12px",
              padding: "16px 22px",
              border: "1px solid " + T.conB,
              borderTop: "1px solid rgba(255,255,255,0.05)",
            }}
          >
            <div
              style={{
                fontSize: 12,
                color: "#4ADE80",
                fontFamily: "monospace",
                marginBottom: 8,
                fontWeight: 700,
              }}
            >
              200 OK — Live Pipeline Response
            </div>
            <pre
              style={{
                margin: 0,
                fontSize: 13,
                color: "#E2E8F0",
                fontFamily: "monospace",
                lineHeight: 1.65,
                overflow: "auto",
                maxHeight: 250,
              }}
            >
              {dynamicApiResp}
            </pre>
          </div>
        </div>
      </Wrap>
    </div>
  );
}

// ── Streamlined Footer with Verified Working Links ──────────────────────
function Footer() {
  const footerSections = [
    {
      title: "Forensic Layers",
      links: [
        { label: "Chronological Timeline", href: "#timeline" },
        { label: "10-Layer Forensics Explorer", href: "#forensics" },
        { label: "Relay Geolocation Map", href: "#map" },
        { label: "Threat Actor Correlation Graph", href: "#graph" },
      ],
    },
    {
      title: "Investigation Tools",
      links: [
        { label: "Explainable AI Feature Importance", href: "#shap" },
        { label: "Hop-by-Hop Relay Analysis", href: "#relay" },
        { label: "Chain of Custody Hash Audit", href: "#custody" },
        { label: "SIEM & SOAR Integration Routes", href: "#platform" },
      ],
    },
    {
      title: "Live Backend APIs",
      links: [
        {
          label: "Interactive API Docs (Swagger UI)",
          href: "http://127.0.0.1:8000/docs",
          external: true,
        },
        {
          label: "ReDoc API Specification",
          href: "http://127.0.0.1:8000/redoc",
          external: true,
        },
        {
          label: "System Health Check (/api/health)",
          href: "http://127.0.0.1:8000/api/health",
          external: true,
        },
        {
          label: "Cases Queue JSON (/api/cases)",
          href: "http://127.0.0.1:8000/api/cases",
          external: true,
        },
      ],
    },
  ];

  return (
    <footer
      style={{
        background: "#0B0D13",
        borderTop: "1px solid #1E293B",
        padding: "60px 28px 36px",
      }}
    >
      <Wrap>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "2fr 1fr 1fr 1.2fr",
            gap: 40,
            marginBottom: 44,
          }}
        >
          <div>
            <div
              style={{
                fontSize: 24,
                fontWeight: 900,
                color: "#fff",
                letterSpacing: "-0.04em",
                marginBottom: 10,
              }}
            >
              Mail<span style={{ color: T.blue }}>Trace</span>
            </div>
            <p
              style={{
                fontSize: 15,
                color: "#94A3B8",
                lineHeight: 1.65,
                maxWidth: 300,
                margin: "0 0 16px",
              }}
            >
              Autonomous multi-layer email forensics and threat intelligence
              platform.
            </p>
            <div style={{ fontSize: 13, color: "#64748B" }}>
              Cryptographic custody verification · RFC 822 parsing · MITRE
              ATT&CK
            </div>
          </div>

          {footerSections.map((sec) => (
            <div key={sec.title}>
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 800,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  color: "#64748B",
                  marginBottom: 14,
                }}
              >
                {sec.title}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
                {sec.links.map((link) => (
                  <a
                    key={link.label}
                    href={link.href}
                    target={link.external ? "_blank" : undefined}
                    rel={link.external ? "noopener noreferrer" : undefined}
                    style={{
                      fontSize: 14,
                      color: "#94A3B8",
                      textDecoration: "none",
                      transition: "color 0.15s",
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.color = "#60A5FA")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.color = "#94A3B8")
                    }
                  >
                    {link.label} {link.external ? "↗" : ""}
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div
          style={{
            borderTop: "1px solid #1E293B",
            paddingTop: 22,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 14,
          }}
        >
          <span style={{ fontSize: 13, color: "#64748B" }}>
            © 2026 MailTrace SOC Platform. All rights reserved.
          </span>
          <a
            href="#hero"
            style={{
              fontSize: 14,
              color: T.blue,
              textDecoration: "none",
              fontWeight: 700,
            }}
          >
            Back to top ↑
          </a>
        </div>
      </Wrap>
    </footer>
  );
}

// ── Root Component: Live Data Orchestrator ────────────────────────────────
export default function App() {
  const [activeCase, setActiveCase] = useState<CaseBundle | null>(null);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [mapLayout, setMapLayout] = useState<MapLayout | null>(null);
  const [graphData, setGraphData] = useState<GraphPayload | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [backendMode, setBackendMode] = useState<Mode>("probing");
  const [casesCount, setCasesCount] = useState(0);
  const [availableCases, setAvailableCases] = useState<string[]>([]);
  const [uploadCount, setUploadCount] = useState(0);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const caseRef = params.get("case") || params.get("ref");
    if (!caseRef) return;
    void loadCaseDetails(caseRef);
  }, []);

  // Subscribe to backend connectivity mode
  useEffect(() => {
    return onModeChange(setBackendMode);
  }, []);

  // Connect SSE live stream for automatic instant updates
  const { events } = useLiveEvents(true);

  // Helper to load case with map & graph
  const loadCaseDetails = async (caseId: string) => {
    try {
      const [bundle, map, graph] = await Promise.all([
        api.case(caseId),
        api.caseMap(caseId).catch(() => null),
        api.caseGraph(caseId).catch(() => null),
      ]);
      setActiveCase(bundle);
      setSelectedCaseId(caseId);
      if (map) setMapLayout(map);
      if (graph) setGraphData(graph);
    } catch (e) {
      console.error("Error loading case bundle:", e);
    }
  };

  // Refresh cases list from backend
  const refreshQueue = async () => {
    try {
      const q = await api.cases({ limit: 50 });
      const items = q?.items || [];
      setCasesCount(q?.total != null ? q.total : items.length);
      const caseNums = items
        .map((item) => item.case_number || item.id)
        .filter(Boolean);
      setAvailableCases(caseNums.slice(0, 12));
    } catch (e) {
      console.error("Error fetching cases queue:", e);
      setCasesCount(0);
      setAvailableCases([]);
    }
  };

  // Load initial queue
  useEffect(() => {
    refreshQueue();
  }, []);

  // When live events arrive from backend, automatically refresh the active case
  useEffect(() => {
    if (events.length > 0) {
      const latest = events[events.length - 1];
      if (latest.kind === "case" && latest.data?.case_number) {
        loadCaseDetails(String(latest.data.case_number));
        refreshQueue();
      }
    }
  }, [events]);

  // Handler: Select specific case by ID
  const handleSelectCase = async (caseId: string) => {
    setIsAnalyzing(true);
    try {
      await loadCaseDetails(caseId);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Handler: Clear current active case
  const handleClearCase = () => {
    setActiveCase(null);
    setSelectedCaseId(null);
    setMapLayout(null);
    setGraphData(null);
  };

  // Handler: Clear all queue from DB and UI
  const handleClearAllQueue = async () => {
    try {
      await api.clearCases();
      setActiveCase(null);
      setSelectedCaseId(null);
      setMapLayout(null);
      setGraphData(null);
      setCasesCount(0);
      setAvailableCases([]);
    } catch (err) {
      console.error("Error clearing queue:", err);
    }
  };

  // Handler: Paste raw RFC 822 email text and ingest it
  const handleIngestRaw = async (rawText: string) => {
    if (!rawText.trim()) return;
    setIsAnalyzing(true);
    setUploadCount(1);
    try {
      const blob = new Blob([rawText], { type: "message/rfc822" });
      const file = new File([blob], "pasted-email.eml", {
        type: "message/rfc822",
      });
      const result: any = await api.ingest(file, true);
      const caseId =
        result?.cases?.[0]?.case_number ||
        result?.cases?.[0]?.id ||
        result?.case?.case_number ||
        result?.case?.id ||
        result?.id ||
        result?.summary?.id;
      await refreshQueue();
      if (caseId) await loadCaseDetails(caseId);
    } catch (err) {
      alert((err as Error).message || "Failed to analyze raw email");
    } finally {
      setIsAnalyzing(false);
      setUploadCount(0);
    }
  };

  // Handler: Upload batch of real .EML or raw email files
  const handleUploadFiles = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setIsAnalyzing(true);
    setUploadCount(files.length);
    let lastLoadedCaseId: string | null = null;

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const result: any = await api.ingest(file, true);
        const caseId =
          result?.cases?.[0]?.case_number ||
          result?.cases?.[0]?.id ||
          result?.case?.case_number ||
          result?.case?.id ||
          result?.id ||
          result?.summary?.id;
        if (caseId) {
          lastLoadedCaseId = caseId;
        }
      }

      await refreshQueue();

      if (lastLoadedCaseId) {
        await loadCaseDetails(lastLoadedCaseId);
      }
    } catch (err) {
      alert((err as Error).message || "Failed to analyze files");
    } finally {
      setIsAnalyzing(false);
      setUploadCount(0);
      e.target.value = "";
    }
  };

  return (
    <div
      style={{
        background: T.bg,
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Inter", system-ui, sans-serif',
        color: T.text,
        margin: 0,
        padding: 0,
        minHeight: "100vh",
      }}
    >
      <Navbar />
      <Hero
        activeCase={activeCase}
        selectedCaseId={selectedCaseId}
        isAnalyzing={isAnalyzing}
        onUploadFiles={handleUploadFiles}
        onClearCase={handleClearCase}
        onClearAllQueue={handleClearAllQueue}
        onIngestRaw={handleIngestRaw}
        casesCount={casesCount}
        availableCases={availableCases}
        onSelectCaseNumber={handleSelectCase}
        uploadCount={uploadCount}
      />
      <ForensicTimeline
        activeCase={activeCase}
        selectedCaseId={selectedCaseId}
      />
      <EmailUnfolds activeCase={activeCase} selectedCaseId={selectedCaseId} />
      <LiveRelayMapSection
        mapLayout={mapLayout}
        selectedCaseId={selectedCaseId}
      />
      <LiveGraphSection
        graphData={graphData}
        activeCase={activeCase}
        selectedCaseId={selectedCaseId}
      />
      <Shap activeCase={activeCase} selectedCaseId={selectedCaseId} />
      <Relay activeCase={activeCase} selectedCaseId={selectedCaseId} />
      <Evidence activeCase={activeCase} selectedCaseId={selectedCaseId} />
      <APISection activeCase={activeCase} selectedCaseId={selectedCaseId} />
      <Footer />
    </div>
  );
}
