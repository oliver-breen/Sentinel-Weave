import React, { useEffect, useMemo, useState } from "react";
import {
  fetchEvents,
  fetchSummary,
  ingestLog,
  ingestEmail,
  ingestImap,
  redteamPortscan,
  redteamVulnscan,
  redteamCredaudit,
  redteamRecon,
  redteamShellcode,
  redteamYara,
  redteamAnomaly,
  quantaweaveKeygen,
  quantaweaveEncrypt,
  quantaweaveDecrypt,
  mlkemKeygen,
  mlkemEncaps,
  mlkemDecaps,
  mldsaKeygen,
  mldsaSign,
  mldsaVerify,
} from "./lib/api";
import { SummaryMetrics, ThreatEvent } from "./lib/types";
import Panel from "./components/Panel";
import StatCard from "./components/StatCard";
import TopList from "./components/TopList";
import EventsTable from "./components/EventsTable";

const emptySummary: SummaryMetrics = {
  total_events: 0,
  levels: { BENIGN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  emails_scanned: 0,
  email_threats: 0,
  avg_anomaly_score: 0,
  events_per_minute: 0,
  top_sources: [],
  recent_sigs: [],
};

export default function App() {
  const [summary, setSummary] = useState<SummaryMetrics>(emptySummary);
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [status, setStatus] = useState("connecting");
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [backendStatus, setBackendStatus] = useState("checking");
  const [backendMeta, setBackendMeta] = useState<string | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [filterLevel, setFilterLevel] = useState("ALL");
  const [filterTerm, setFilterTerm] = useState("");
  const [overrideEnabled, setOverrideEnabled] = useState(false);
  const [overrideFields, setOverrideFields] = useState({
    total_events: "",
    events_per_minute: "",
    avg_anomaly_score: "",
    emails_scanned: "",
    email_threats: "",
    benign: "",
    low: "",
    medium: "",
    high: "",
    critical: "",
  });
  const [logInput, setLogInput] = useState("");
  const [logResult, setLogResult] = useState<string | null>(null);
  const [emailInput, setEmailInput] = useState("");
  const [emailResult, setEmailResult] = useState<string | null>(null);
  const [imapConfig, setImapConfig] = useState({
    host: "",
    port: "993",
    username: "",
    password: "",
    folder: "INBOX",
    limit: "20",
  });
  const [imapResult, setImapResult] = useState<string | null>(null);
  const [imapRows, setImapRows] = useState<any[]>([]);
  const [imapFilter, setImapFilter] = useState("");
  const [imapLevel, setImapLevel] = useState("ALL");
  const [rememberImap, setRememberImap] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [portscan, setPortscan] = useState({ host: "", ports: "", range: "" });
  const [portscanResult, setPortscanResult] = useState<string | null>(null);
  const [vulnBanner, setVulnBanner] = useState("");
  const [vulnResult, setVulnResult] = useState<string | null>(null);
  const [credsInput, setCredsInput] = useState("");
  const [credsResult, setCredsResult] = useState<string | null>(null);
  const [reconTarget, setReconTarget] = useState("");
  const [reconPorts, setReconPorts] = useState("");
  const [reconResult, setReconResult] = useState<string | null>(null);
  const [shellcodeHex, setShellcodeHex] = useState("");
  const [shellcodeArch, setShellcodeArch] = useState("x86_64");
  const [shellcodeResult, setShellcodeResult] = useState<string | null>(null);
  const [shellcodeData, setShellcodeData] = useState<any | null>(null);
  const [yaraText, setYaraText] = useState("");
  const [yaraHex, setYaraHex] = useState("");
  const [yaraRuleSets, setYaraRuleSets] = useState("");
  const [yaraCustom, setYaraCustom] = useState("");
  const [yaraResult, setYaraResult] = useState<string | null>(null);
  const [yaraData, setYaraData] = useState<any | null>(null);
  const [anomalyJson, setAnomalyJson] = useState("[]");
  const [anomalyResult, setAnomalyResult] = useState<string | null>(null);
  const [anomalyData, setAnomalyData] = useState<any | null>(null);
  const [qwLevel, setQwLevel] = useState("LEVEL1");
  const [qwPublicKey, setQwPublicKey] = useState("");
  const [qwPrivateKey, setQwPrivateKey] = useState("");
  const [qwMessage, setQwMessage] = useState("");
  const [qwCiphertext, setQwCiphertext] = useState("");
  const [qwPlaintext, setQwPlaintext] = useState<string | null>(null);
  const [qwStatus, setQwStatus] = useState<string | null>(null);
  const [mlkemAlg, setMlkemAlg] = useState("ML-KEM-512");
  const [mlkemPk, setMlkemPk] = useState("");
  const [mlkemSk, setMlkemSk] = useState("");
  const [mlkemCt, setMlkemCt] = useState("");
  const [mlkemSs, setMlkemSs] = useState("");
  const [mldsaAlg, setMldsaAlg] = useState("ML-DSA-44");
  const [mldsaPk, setMldsaPk] = useState("");
  const [mldsaSk, setMldsaSk] = useState("");
  const [mldsaMessage, setMldsaMessage] = useState("");
  const [mldsaSig, setMldsaSig] = useState("");
  const [mldsaValid, setMldsaValid] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    const loadInitial = async () => {
      try {
        const [summaryData, eventsData] = await Promise.all([
          fetchSummary(),
          fetchEvents(50),
        ]);
        if (!mounted) return;
        setSummary(summaryData);
        setEvents(eventsData);
        setLastUpdate(new Date());
      } catch (err) {
        if (!mounted) return;
        setStatus("offline");
      }
    };

    loadInitial();

    const poll = setInterval(loadInitial, 15000);
    return () => {
      mounted = false;
      clearInterval(poll);
    };
  }, []);

  useEffect(() => {
    const source = new EventSource("/api/stream");
    source.onopen = () => setStatus("live");
    source.onerror = () => setStatus("offline");
    source.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload?.type === "metrics") {
          setSummary(payload.data);
          setLastUpdate(new Date());
        }
      } catch {
        // Ignore malformed updates
      }
    };
    return () => source.close();
  }, []);

  useEffect(() => {
    let mounted = true;
    const pollHealth = async () => {
      try {
        const res = await fetch("/health");
        if (!res.ok) {
          throw new Error(`Backend status ${res.status}`);
        }
        const data = await res.json();
        if (!mounted) return;
        setBackendStatus("online");
        setBackendMeta(data?.version ? `v${data.version}` : null);
      } catch {
        if (!mounted) return;
        setBackendStatus("offline");
        setBackendMeta(null);
      }
    };

    pollHealth();
    const interval = setInterval(pollHealth, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    const saved = localStorage.getItem("sw_imap_config");
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        setImapConfig({
          host: parsed.host ?? "",
          port: String(parsed.port ?? "993"),
          username: parsed.username ?? "",
          password: "",
          folder: parsed.folder ?? "INBOX",
          limit: String(parsed.limit ?? "20"),
        });
        setRememberImap(true);
      } catch {
        // Ignore invalid saved config
      }
    }
  }, []);

  useEffect(() => {
    if (!rememberImap) {
      localStorage.removeItem("sw_imap_config");
      return;
    }
    const payload = {
      host: imapConfig.host,
      port: imapConfig.port,
      username: imapConfig.username,
      folder: imapConfig.folder,
      limit: imapConfig.limit,
    };
    localStorage.setItem("sw_imap_config", JSON.stringify(payload));
  }, [rememberImap, imapConfig.host, imapConfig.port, imapConfig.username, imapConfig.folder, imapConfig.limit]);

  const displaySummary = useMemo(() => {
    if (!overrideEnabled) {
      return summary;
    }
    const toNumber = (value: string, fallback: number) => {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : fallback;
    };
    return {
      ...summary,
      total_events: toNumber(overrideFields.total_events, summary.total_events),
      events_per_minute: toNumber(overrideFields.events_per_minute, summary.events_per_minute),
      avg_anomaly_score: toNumber(overrideFields.avg_anomaly_score, summary.avg_anomaly_score),
      emails_scanned: toNumber(overrideFields.emails_scanned, summary.emails_scanned),
      email_threats: toNumber(overrideFields.email_threats, summary.email_threats),
      levels: {
        BENIGN: toNumber(overrideFields.benign, summary.levels.BENIGN),
        LOW: toNumber(overrideFields.low, summary.levels.LOW),
        MEDIUM: toNumber(overrideFields.medium, summary.levels.MEDIUM),
        HIGH: toNumber(overrideFields.high, summary.levels.HIGH),
        CRITICAL: toNumber(overrideFields.critical, summary.levels.CRITICAL),
      },
    };
  }, [overrideEnabled, overrideFields, summary]);

  const topSources = useMemo(
    () => displaySummary.top_sources.map(([label, value]) => ({ label, value })),
    [displaySummary.top_sources]
  );

  const topSigs = useMemo(
    () => displaySummary.recent_sigs.map((s) => ({ label: s.sig, value: s.count })),
    [displaySummary.recent_sigs]
  );

  const filteredEvents = useMemo(() => {
    const term = filterTerm.trim().toLowerCase();
    return events.filter((event) => {
      if (filterLevel !== "ALL" && event.threat_level !== filterLevel) {
        return false;
      }
      if (!term) {
        return true;
      }
      const haystack = [
        event.source_ip ?? "",
        event.event_type ?? "",
        event.summary ?? "",
        ...(event.sigs ?? []),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(term);
    });
  }, [events, filterLevel, filterTerm]);

  const filteredImapRows = useMemo(() => {
    const term = imapFilter.trim().toLowerCase();
    return imapRows.filter((row) => {
      if (imapLevel !== "ALL" && row.threat_level !== imapLevel) {
        return false;
      }
      if (!term) return true;
      const haystack = [row.sender, row.subject]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(term);
    });
  }, [imapRows, imapFilter, imapLevel]);

  const onOverrideChange = (key: string, value: string) => {
    setOverrideFields((prev) => ({ ...prev, [key]: value }));
  };

  const parsePortList = (value: string) =>
    value
      .split(",")
      .map((part) => Number(part.trim()))
      .filter((num) => Number.isFinite(num) && num >= 1 && num <= 65535);

  const parsePortRange = (value: string): [number, number] | undefined => {
    const parts = value.split("-").map((part) => Number(part.trim()));
    if (parts.length !== 2) return undefined;
    if (!Number.isFinite(parts[0]) || !Number.isFinite(parts[1])) return undefined;
    if (parts[0] < 1 || parts[1] > 65535 || parts[0] > parts[1]) return undefined;
    return [parts[0], parts[1]];
  };

  const parseRuleSets = (value: string) =>
    value
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);

  const parseJsonField = (value: string, label: string) => {
    try {
      return JSON.parse(value);
    } catch {
      setQwStatus(`${label} is not valid JSON`);
      return null;
    }
  };

  const logValid = logInput.trim().length > 0 && logInput.length <= 4096;
  const emailValid = emailInput.trim().length > 0 && emailInput.length <= 200000;
  const imapValid = Boolean(imapConfig.host && imapConfig.username && imapConfig.password);
  const portscanValid = Boolean(portscan.host.trim());
  const vulnValid = Boolean(vulnBanner.trim());
  const credsValid = Boolean(credsInput.trim());
  const reconValid = Boolean(reconTarget.trim());
  const shellcodeValid = Boolean(shellcodeHex.trim());
  const yaraValid = Boolean(yaraHex.trim() || yaraText.trim());
  const anomalyValid = Boolean(anomalyJson.trim());
  const qwMessageValid = qwMessage.length > 0 && new TextEncoder().encode(qwMessage).length <= 1024;
  const qwKeyValid = Boolean(qwPublicKey.trim());
  const qwCipherValid = Boolean(qwCiphertext.trim());
  const qwPrivValid = Boolean(qwPrivateKey.trim());
  const mlkemPkValid = Boolean(mlkemPk.trim());
  const mlkemSkValid = Boolean(mlkemSk.trim());
  const mlkemCtValid = Boolean(mlkemCt.trim());
  const mldsaPkValid = Boolean(mldsaPk.trim());
  const mldsaSkValid = Boolean(mldsaSk.trim());
  const mldsaSigValid = Boolean(mldsaSig.trim());
  const mldsaMsgValid = Boolean(mldsaMessage.trim());

  const toHex = (b64: string) => {
    try {
      const bin = atob(b64.trim());
      return Array.from(bin)
        .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("");
    } catch {
      return "";
    }
  };

  const copyText = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      setLastError("Clipboard write failed. Copy manually.");
    }
  };

  const runRequest = async <T,>(fn: () => Promise<T>): Promise<T | null> => {
    setLastError(null);
    try {
      return await fn();
    } catch (err) {
      setLastError(err instanceof Error ? err.message : String(err));
      return null;
    }
  };

  return (
    <div className="app">
      <header className="app__header">
        <div>
          <p className="eyebrow">SentinelWeave Security Console</p>
          <h1>Threat Situation Room</h1>
          <p className="subtle">
            QuantaWeave-secured telemetry across LWE, ML-KEM/ML-DSA, and Falcon.
          </p>
        </div>
        <div className="status">
          <span className={`status__dot status__dot--${status}`} />
          <div>
            <p className="status__label">{status === "live" ? "Live feed" : "Offline"}</p>
            <p className="status__meta">
              {lastUpdate ? `Updated ${lastUpdate.toLocaleTimeString()}` : "Awaiting data"}
            </p>
            <p className="status__meta">
              Backend {backendStatus}{backendMeta ? ` • ${backendMeta}` : ""}
            </p>
          </div>
        </div>
      </header>

      {lastError ? <div className="banner banner--error">{lastError}</div> : null}

      <nav className="tabs">
        {[
          { id: "overview", label: "Overview" },
          { id: "scanners", label: "Scanners" },
          { id: "redteam", label: "Red Team" },
          { id: "quantaweave", label: "QuantaWeave" },
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`tab ${activeTab === tab.id ? "tab--active" : ""}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {activeTab === "overview" ? (
        <>
          <section className="stats">
            <StatCard label="Total events" value={displaySummary.total_events} />
            <StatCard label="Critical" value={displaySummary.levels.CRITICAL} tone="bad" />
            <StatCard label="High" value={displaySummary.levels.HIGH} tone="warn" />
            <StatCard label="Avg anomaly" value={displaySummary.avg_anomaly_score.toFixed(2)} />
            <StatCard label="Events/min" value={displaySummary.events_per_minute.toFixed(1)} />
            <StatCard label="Emails scanned" value={displaySummary.emails_scanned} />
          </section>

          <section className="grid">
            <Panel title="Threat levels" subtitle="Real-time classification counts">
              <div className="level-grid">
                {Object.entries(displaySummary.levels).map(([key, value]) => (
                  <div className="level-pill" key={key}>
                    <span>{key}</span>
                    <strong>{value}</strong>
                  </div>
                ))}
              </div>
            </Panel>
            <Panel title="Top sources" subtitle="Most active IPs">
              <TopList title="Sources" items={topSources} />
            </Panel>
            <Panel title="Recent signatures" subtitle="Latest matched indicators">
              <TopList title="Signatures" items={topSigs} />
            </Panel>
          </section>

          <section className="grid grid--wide">
            <Panel title="Recent events" subtitle="Last 50 detections">
              <div className="table-filters">
                <input
                  type="text"
                  placeholder="Search IPs, signatures, summaries..."
                  value={filterTerm}
                  onChange={(event) => setFilterTerm(event.target.value)}
                />
                <select
                  value={filterLevel}
                  onChange={(event) => setFilterLevel(event.target.value)}
                >
                  {[
                    "ALL",
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                    "BENIGN",
                  ].map((level) => (
                    <option key={level} value={level}>
                      {level}
                    </option>
                  ))}
                </select>
                <span className="table-count">{filteredEvents.length} events</span>
              </div>
              <EventsTable events={filteredEvents} />
            </Panel>
            <Panel title="Operations" subtitle="Security posture">
              <div className="ops">
                <div>
                  <p>Email threats</p>
                  <strong>{displaySummary.email_threats}</strong>
                </div>
                <div>
                  <p>Secure reports</p>
                  <strong>{displaySummary.total_events}</strong>
                </div>
                <div>
                  <p>QuantaWeave mode</p>
                  <strong>Hybrid PQ + AES</strong>
                </div>
                <div>
                  <p>Data policy</p>
                  <strong>Zero trust ingest</strong>
                </div>
              </div>
            </Panel>
          </section>

          <section className="grid">
            <Panel title="Local overrides" subtitle="Client-only metrics tuning">
              <div className="form-grid">
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={overrideEnabled}
                    onChange={(event) => setOverrideEnabled(event.target.checked)}
                  />
                  <span>Enable overrides</span>
                </label>
                <div className="form-row">
                  <label>Total events</label>
                  <input
                    type="number"
                    value={overrideFields.total_events}
                    onChange={(event) => onOverrideChange("total_events", event.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>Events / min</label>
                  <input
                    type="number"
                    value={overrideFields.events_per_minute}
                    onChange={(event) => onOverrideChange("events_per_minute", event.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>Avg anomaly</label>
                  <input
                    type="number"
                    value={overrideFields.avg_anomaly_score}
                    onChange={(event) => onOverrideChange("avg_anomaly_score", event.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>Emails scanned</label>
                  <input
                    type="number"
                    value={overrideFields.emails_scanned}
                    onChange={(event) => onOverrideChange("emails_scanned", event.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>Email threats</label>
                  <input
                    type="number"
                    value={overrideFields.email_threats}
                    onChange={(event) => onOverrideChange("email_threats", event.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>Critical</label>
                  <input
                    type="number"
                    value={overrideFields.critical}
                    onChange={(event) => onOverrideChange("critical", event.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>High</label>
                  <input
                    type="number"
                    value={overrideFields.high}
                    onChange={(event) => onOverrideChange("high", event.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>Medium</label>
                  <input
                    type="number"
                    value={overrideFields.medium}
                    onChange={(event) => onOverrideChange("medium", event.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>Low</label>
                  <input
                    type="number"
                    value={overrideFields.low}
                    onChange={(event) => onOverrideChange("low", event.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>Benign</label>
                  <input
                    type="number"
                    value={overrideFields.benign}
                    onChange={(event) => onOverrideChange("benign", event.target.value)}
                  />
                </div>
              </div>
            </Panel>
          </section>
        </>
      ) : null}

      {activeTab === "scanners" ? (
        <section className="grid grid--wide">
          <Panel title="Log ingestion" subtitle="Send a raw log line to /api/ingest">
            <div className="form-grid">
              <label>Raw log line</label>
              <textarea
                rows={4}
                value={logInput}
                onChange={(event) => setLogInput(event.target.value)}
                placeholder="Failed password for root from 10.0.0.5 port 22 ssh2"
              />
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => ingestLog(logInput));
                  if (!result) return;
                  setLogResult(JSON.stringify(result, null, 2));
                }}
                disabled={!logValid}
              >
                Ingest log
              </button>
              <p className="hint">Max 4,096 characters. Required.</p>
              {logResult ? <pre className="result">{logResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="Email scanner" subtitle="Ingest raw email into /api/ingest/email">
            <div className="ops">
              <div>
                <p>Emails scanned</p>
                <strong>{displaySummary.emails_scanned}</strong>
              </div>
              <div>
                <p>Email threats</p>
                <strong>{displaySummary.email_threats}</strong>
              </div>
              <div>
                <p>Active indicators</p>
                <strong>{Math.max(displaySummary.email_threats, 0)}</strong>
              </div>
            </div>
            <div className="form-grid">
              <label>Raw RFC 5322 email</label>
              <textarea
                rows={5}
                value={emailInput}
                onChange={(event) => setEmailInput(event.target.value)}
                placeholder="From: sender@example.com\nTo: you@example.com\nSubject: Verify your account\n\nBody..."
              />
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => ingestEmail(emailInput));
                  if (!result) return;
                  setEmailResult(JSON.stringify(result, null, 2));
                }}
                disabled={!emailValid}
              >
                Scan email
              </button>
              <p className="hint">Max 200k characters. Required.</p>
              {emailResult ? <pre className="result">{emailResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="IMAP inbox scan" subtitle="Connect to mailbox and scan recent messages">
            <div className="form-grid">
              <label>Host</label>
              <input
                value={imapConfig.host}
                onChange={(event) => setImapConfig({ ...imapConfig, host: event.target.value })}
                placeholder="imap.gmail.com"
              />
              <label>Port</label>
              <input
                value={imapConfig.port}
                onChange={(event) => setImapConfig({ ...imapConfig, port: event.target.value })}
              />
              <label>Username</label>
              <input
                value={imapConfig.username}
                onChange={(event) => setImapConfig({ ...imapConfig, username: event.target.value })}
              />
              <label>Password (app password recommended)</label>
              <input
                type="password"
                value={imapConfig.password}
                onChange={(event) => setImapConfig({ ...imapConfig, password: event.target.value })}
              />
              <label className="switch">
                <input
                  type="checkbox"
                  checked={rememberImap}
                  onChange={(event) => setRememberImap(event.target.checked)}
                />
                <span>Remember IMAP config (no password)</span>
              </label>
              <label>Folder</label>
              <input
                value={imapConfig.folder}
                onChange={(event) => setImapConfig({ ...imapConfig, folder: event.target.value })}
              />
              <label>Limit</label>
              <input
                value={imapConfig.limit}
                onChange={(event) => setImapConfig({ ...imapConfig, limit: event.target.value })}
              />
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => ingestImap(
                    {
                      host: imapConfig.host,
                      port: Number(imapConfig.port),
                      username: imapConfig.username,
                      password: imapConfig.password,
                      folder: imapConfig.folder,
                      limit: Number(imapConfig.limit),
                    },
                    { apiKey }
                  ));
                  if (!result) return;
                  setImapResult(JSON.stringify(result, null, 2));
                  setImapRows(Array.isArray(result?.results) ? result.results : []);
                }}
                disabled={!imapValid}
              >
                Scan inbox
              </button>
              <p className="hint">Host, username, and password are required.</p>
              {imapResult ? <pre className="result">{imapResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="Inbox results" subtitle="Most recent IMAP scan results">
            <div className="table-filters">
              <input
                type="text"
                placeholder="Search sender/subject"
                value={imapFilter}
                onChange={(event) => setImapFilter(event.target.value)}
              />
              <select value={imapLevel} onChange={(event) => setImapLevel(event.target.value)}>
                {[
                  "ALL",
                  "CRITICAL",
                  "HIGH",
                  "MEDIUM",
                  "LOW",
                  "BENIGN",
                ].map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
              <span className="table-count">{filteredImapRows.length} messages</span>
            </div>
            <div className="inbox-table">
              <div className="inbox-table__header">
                <span>Sender</span>
                <span>Subject</span>
                <span>Threat</span>
                <span>Score</span>
                <span>Indicators</span>
              </div>
              {filteredImapRows.length === 0 ? (
                <div className="inbox-table__empty">No inbox results yet.</div>
              ) : (
                filteredImapRows.map((row, index) => (
                  <div className="inbox-table__row" key={`${row.subject}-${index}`}>
                    <span>{row.sender || "—"}</span>
                    <span>{row.subject || "—"}</span>
                    <span className="badge badge--medium">{row.threat_level}</span>
                    <span>{Number(row.risk_score ?? 0).toFixed(2)}</span>
                    <span>{row.indicator_count ?? 0}</span>
                  </div>
                ))
              )}
            </div>
          </Panel>
        </section>
      ) : null}

      {activeTab === "redteam" ? (
        <section className="grid">
          <Panel title="API key" subtitle="Required when SENTINELWEAVE_API_KEY is set">
            <div className="form-grid">
              <label>API key</label>
              <input
                type="password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                placeholder="Optional"
              />
            </div>
          </Panel>
          <Panel title="Port scan" subtitle="/api/redteam/portscan">
            <div className="form-grid">
              <label>Host</label>
              <input
                value={portscan.host}
                onChange={(event) => setPortscan({ ...portscan, host: event.target.value })}
                placeholder="192.168.1.10"
              />
              <label>Ports (comma-separated)</label>
              <input
                value={portscan.ports}
                onChange={(event) => setPortscan({ ...portscan, ports: event.target.value })}
                placeholder="22,80,443"
              />
              <label>Port range (start-end)</label>
              <input
                value={portscan.range}
                onChange={(event) => setPortscan({ ...portscan, range: event.target.value })}
                placeholder="1-100"
              />
              <button
                type="button"
                onClick={async () => {
                  const payload: any = { host: portscan.host };
                  const ports = parsePortList(portscan.ports);
                  const range = parsePortRange(portscan.range);
                  if (ports.length) payload.ports = ports;
                  if (range) payload.port_range = range;
                  const result = await runRequest(() => redteamPortscan(payload, { apiKey }));
                  if (!result) return;
                  setPortscanResult(JSON.stringify(result, null, 2));
                }}
                disabled={!portscanValid}
              >
                Run scan
              </button>
              <p className="hint">Ports must be 1-65535.</p>
              {portscanResult ? <pre className="result">{portscanResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="Vulnerability scan" subtitle="/api/redteam/vulnscan">
            <div className="form-grid">
              <label>Service banner</label>
              <textarea
                rows={3}
                value={vulnBanner}
                onChange={(event) => setVulnBanner(event.target.value)}
                placeholder="OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"
              />
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => redteamVulnscan(vulnBanner, { apiKey }));
                  if (!result) return;
                  setVulnResult(JSON.stringify(result, null, 2));
                }}
                disabled={!vulnValid}
              >
                Assess banner
              </button>
              {vulnResult ? <pre className="result">{vulnResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="Credential audit" subtitle="/api/redteam/credaudit">
            <div className="form-grid">
              <label>Passwords (one per line)</label>
              <textarea
                rows={4}
                value={credsInput}
                onChange={(event) => setCredsInput(event.target.value)}
              />
              <button
                type="button"
                onClick={async () => {
                  const passwords = credsInput.split("\n").map((p) => p.trim()).filter(Boolean);
                  const result = await runRequest(() => redteamCredaudit(passwords, { apiKey }));
                  if (!result) return;
                  setCredsResult(JSON.stringify(result, null, 2));
                }}
                disabled={!credsValid}
              >
                Audit credentials
              </button>
              {credsResult ? <pre className="result">{credsResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="Recon" subtitle="/api/redteam/recon">
            <div className="form-grid">
              <label>Target</label>
              <input
                value={reconTarget}
                onChange={(event) => setReconTarget(event.target.value)}
                placeholder="example.com"
              />
              <label>Quick ports (comma-separated)</label>
              <input
                value={reconPorts}
                onChange={(event) => setReconPorts(event.target.value)}
                placeholder="80,443,22"
              />
              <button
                type="button"
                onClick={async () => {
                  const quick_ports = parsePortList(reconPorts);
                  const result = await runRequest(() => redteamRecon(
                    { target: reconTarget, quick_ports: quick_ports.length ? quick_ports : undefined },
                    { apiKey }
                  ));
                  if (!result) return;
                  setReconResult(JSON.stringify(result, null, 2));
                }}
                disabled={!reconValid}
              >
                Run recon
              </button>
              {reconResult ? <pre className="result">{reconResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="Shellcode analysis" subtitle="/api/redteam/shellcode">
            <div className="form-grid">
              <label>Hex-encoded shellcode</label>
              <textarea
                rows={3}
                value={shellcodeHex}
                onChange={(event) => setShellcodeHex(event.target.value)}
                placeholder="4831c04889c7b03b0f05"
              />
              <label>Architecture</label>
              <select value={shellcodeArch} onChange={(event) => setShellcodeArch(event.target.value)}>
                {[
                  "x86_64",
                  "x86",
                  "arm",
                  "arm64",
                ].map((arch) => (
                  <option key={arch} value={arch}>
                    {arch}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => redteamShellcode(
                    { hex: shellcodeHex, arch: shellcodeArch },
                    { apiKey }
                  ));
                  if (!result) return;
                  setShellcodeResult(JSON.stringify(result, null, 2));
                  setShellcodeData(result);
                }}
                disabled={!shellcodeValid}
              >
                Analyze shellcode
              </button>
              {shellcodeData ? (
                <div className="mini-table">
                  <div className="mini-table__row">
                    <span>Threat</span>
                    <strong>{shellcodeData.threat_level}</strong>
                  </div>
                  <div className="mini-table__row">
                    <span>Instructions</span>
                    <strong>{shellcodeData.instruction_count}</strong>
                  </div>
                  <div className="mini-table__row">
                    <span>Entropy</span>
                    <strong>{Number(shellcodeData.entropy ?? 0).toFixed(2)}</strong>
                  </div>
                  <div className="mini-table__row">
                    <span>Patterns</span>
                    <strong>{(shellcodeData.matched_patterns ?? []).join(", ") || "None"}</strong>
                  </div>
                </div>
              ) : null}
              {shellcodeResult ? <pre className="result">{shellcodeResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="YARA scan" subtitle="/api/redteam/yara">
            <div className="form-grid">
              <label>Text content</label>
              <textarea
                rows={3}
                value={yaraText}
                onChange={(event) => setYaraText(event.target.value)}
                placeholder="Suspicious string..."
              />
              <label>Hex content (optional)</label>
              <textarea
                rows={2}
                value={yaraHex}
                onChange={(event) => setYaraHex(event.target.value)}
                placeholder="48656c6c6f"
              />
              <label>Rule sets (comma-separated)</label>
              <input
                value={yaraRuleSets}
                onChange={(event) => setYaraRuleSets(event.target.value)}
                placeholder="malware, phishing"
              />
              <label>Custom rules (optional)</label>
              <textarea
                rows={3}
                value={yaraCustom}
                onChange={(event) => setYaraCustom(event.target.value)}
              />
              <button
                type="button"
                onClick={async () => {
                  const payload: any = {};
                  if (yaraHex.trim()) {
                    payload.hex = yaraHex.trim();
                  } else {
                    payload.text = yaraText.trim();
                  }
                  const ruleSets = parseRuleSets(yaraRuleSets);
                  if (ruleSets.length) payload.rule_sets = ruleSets;
                  if (yaraCustom.trim()) payload.custom_rules = yaraCustom;
                  const result = await runRequest(() => redteamYara(payload, { apiKey }));
                  if (!result) return;
                  setYaraResult(JSON.stringify(result, null, 2));
                  setYaraData(result);
                }}
                disabled={!yaraValid}
              >
                Run YARA scan
              </button>
              {yaraData ? (
                <div className="mini-table">
                  <div className="mini-table__row">
                    <span>Severity</span>
                    <strong>{yaraData.severity}</strong>
                  </div>
                  <div className="mini-table__row">
                    <span>Matches</span>
                    <strong>{yaraData.match_count}</strong>
                  </div>
                  {(yaraData.matches ?? []).slice(0, 5).map((match: any, index: number) => (
                    <div className="mini-table__row" key={`${match.rule_name}-${index}`}>
                      <span>{match.rule_name}</span>
                      <strong>{match.severity}</strong>
                    </div>
                  ))}
                </div>
              ) : null}
              {yaraResult ? <pre className="result">{yaraResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="Anomaly detection" subtitle="/api/redteam/anomaly">
            <div className="form-grid">
              <label>Observations (JSON array)</label>
              <textarea
                rows={6}
                value={anomalyJson}
                onChange={(event) => setAnomalyJson(event.target.value)}
                placeholder='[{"latency": 120, "errors": 3}]'
              />
              <button
                type="button"
                onClick={async () => {
                  try {
                    const observations = JSON.parse(anomalyJson);
                    const result = await runRequest(() => redteamAnomaly({ observations }, { apiKey }));
                    if (!result) return;
                    setAnomalyResult(JSON.stringify(result, null, 2));
                    setAnomalyData(result);
                  } catch (err) {
                    setAnomalyResult(JSON.stringify({ error: "Invalid JSON payload" }, null, 2));
                    setAnomalyData(null);
                  }
                }}
                disabled={!anomalyValid}
              >
                Run anomaly detection
              </button>
              {anomalyData ? (
                <div className="mini-table">
                  <div className="mini-table__row">
                    <span>Total</span>
                    <strong>{anomalyData.total_observations}</strong>
                  </div>
                  <div className="mini-table__row">
                    <span>Anomalies</span>
                    <strong>{anomalyData.anomaly_count}</strong>
                  </div>
                  {(anomalyData.records ?? []).slice(0, 5).map((record: any) => (
                    <div className="mini-table__row" key={record.index}>
                      <span>#{record.index}</span>
                      <strong>{record.risk_label}</strong>
                    </div>
                  ))}
                </div>
              ) : null}
              {anomalyResult ? <pre className="result">{anomalyResult}</pre> : null}
            </div>
          </Panel>
          <Panel title="Available endpoints" subtitle="REST operations">
            <div className="list">
              <div>POST /api/redteam/portscan</div>
              <div>POST /api/redteam/vulnscan</div>
              <div>POST /api/redteam/credaudit</div>
              <div>POST /api/redteam/recon</div>
              <div>POST /api/redteam/shellcode</div>
              <div>POST /api/redteam/yara</div>
              <div>POST /api/redteam/anomaly</div>
            </div>
          </Panel>
        </section>
      ) : null}

      {activeTab === "quantaweave" ? (
        <section className="grid">
          <Panel title="API key" subtitle="Required if backend API key is enabled">
            <div className="form-grid">
              <label>API key</label>
              <input
                type="password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                placeholder="Optional"
              />
            </div>
          </Panel>
          <Panel title="QuantaWeave cryptography" subtitle="Hybrid PQ + AES-GCM">
            <div className="list">
              <div>LWE PKE for classical lattice security</div>
              <div>ML-KEM + ML-DSA via liboqs bridge</div>
              <div>Falcon signatures for compact auth</div>
              <div>AES-GCM data envelope with hybrid secret combiner</div>
            </div>
          </Panel>
          <Panel title="Proof sketches" subtitle="Formal reduction outlines">
            <div className="list">
              <div>IND-CPA LWE reduction</div>
              <div>Hybrid KEM combiner in RO/KDF model</div>
              <div>EUF-CMA for ML-DSA + Falcon</div>
              <div>Hybrid signature threshold composition</div>
            </div>
          </Panel>
          <Panel title="Key generation" subtitle="Generate QuantaWeave LWE keys">
            <div className="form-grid">
              <label>Security level</label>
              <select value={qwLevel} onChange={(event) => setQwLevel(event.target.value)}>
                {[
                  "LEVEL1",
                  "LEVEL3",
                  "LEVEL5",
                ].map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => quantaweaveKeygen(qwLevel, { apiKey }));
                  if (!result) return;
                  if (result?.error) {
                    setQwStatus(result.error);
                    return;
                  }
                  setQwPublicKey(JSON.stringify(result.public_key, null, 2));
                  setQwPrivateKey(JSON.stringify(result.private_key, null, 2));
                  setQwStatus("Generated new keypair.");
                }}
              >
                Generate keys
              </button>
              {qwStatus ? <p className="hint">{qwStatus}</p> : null}
            </div>
          </Panel>
          <Panel title="Encrypt" subtitle="Encrypt a message with a public key">
            <div className="form-grid">
              <label>Public key (JSON)</label>
              <textarea
                rows={6}
                value={qwPublicKey}
                onChange={(event) => setQwPublicKey(event.target.value)}
              />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(qwPublicKey)}>Copy</button>
              </div>
              <label>Message (UTF-8)</label>
              <textarea
                rows={3}
                value={qwMessage}
                onChange={(event) => setQwMessage(event.target.value)}
              />
              <button
                type="button"
                onClick={async () => {
                  const pk = parseJsonField(qwPublicKey, "Public key");
                  if (!pk) return;
                  const result = await runRequest(() => quantaweaveEncrypt({
                    message: qwMessage,
                    public_key: pk,
                  }, { apiKey }));
                  if (!result) return;
                  if (result?.error) {
                    setQwStatus(result.error);
                    return;
                  }
                  setQwCiphertext(JSON.stringify(result.ciphertext, null, 2));
                  setQwStatus("Encrypted message.");
                }}
                disabled={!qwKeyValid || !qwMessageValid}
              >
                Encrypt
              </button>
              <p className="hint">Message max 1,024 bytes. Public key JSON required.</p>
            </div>
          </Panel>
          <Panel title="Decrypt" subtitle="Decrypt ciphertext with a private key">
            <div className="form-grid">
              <label>Private key (JSON)</label>
              <textarea
                rows={6}
                value={qwPrivateKey}
                onChange={(event) => setQwPrivateKey(event.target.value)}
              />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(qwPrivateKey)}>Copy</button>
              </div>
              <label>Ciphertext (JSON)</label>
              <textarea
                rows={6}
                value={qwCiphertext}
                onChange={(event) => setQwCiphertext(event.target.value)}
              />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(qwCiphertext)}>Copy</button>
              </div>
              <button
                type="button"
                onClick={async () => {
                  const sk = parseJsonField(qwPrivateKey, "Private key");
                  const ct = parseJsonField(qwCiphertext, "Ciphertext");
                  if (!sk || !ct) return;
                  const result = await runRequest(() => quantaweaveDecrypt({
                    private_key: sk,
                    ciphertext: ct,
                  }, { apiKey }));
                  if (!result) return;
                  if (result?.error) {
                    setQwStatus(result.error);
                    return;
                  }
                  setQwPlaintext(result.plaintext ?? "");
                  setQwStatus("Decrypted message.");
                }}
                disabled={!qwPrivValid || !qwCipherValid}
              >
                Decrypt
              </button>
              {qwPlaintext ? <pre className="result">{qwPlaintext}</pre> : null}
            </div>
          </Panel>
          <Panel title="ML-KEM keygen" subtitle="Generate ML-KEM keypair (base64)">
            <div className="form-grid">
              <label>Algorithm</label>
              <select value={mlkemAlg} onChange={(event) => setMlkemAlg(event.target.value)}>
                {["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"].map((alg) => (
                  <option key={alg} value={alg}>
                    {alg}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => mlkemKeygen(mlkemAlg, { apiKey }));
                  if (!result) return;
                  if (result?.error) {
                    setQwStatus(result.error);
                    return;
                  }
                  setMlkemPk(result.public_key_b64 ?? "");
                  setMlkemSk(result.secret_key_b64 ?? "");
                }}
              >
                Generate ML-KEM keys
              </button>
              <label>Public key (base64)</label>
              <textarea rows={4} value={mlkemPk} onChange={(event) => setMlkemPk(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mlkemPk)}>Copy</button>
                <span className="hint">Hex: {toHex(mlkemPk).slice(0, 64)}…</span>
              </div>
              <label>Secret key (base64)</label>
              <textarea rows={4} value={mlkemSk} onChange={(event) => setMlkemSk(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mlkemSk)}>Copy</button>
                <span className="hint">Hex: {toHex(mlkemSk).slice(0, 64)}…</span>
              </div>
            </div>
          </Panel>
          <Panel title="ML-KEM encapsulate" subtitle="Encapsulate with a public key">
            <div className="form-grid">
              <label>Public key (base64)</label>
              <textarea rows={4} value={mlkemPk} onChange={(event) => setMlkemPk(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mlkemPk)}>Copy</button>
                <span className="hint">Hex: {toHex(mlkemPk).slice(0, 64)}…</span>
              </div>
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => mlkemEncaps({ alg: mlkemAlg, public_key_b64: mlkemPk }, { apiKey }));
                  if (!result) return;
                  if (result?.error) {
                    setQwStatus(result.error);
                    return;
                  }
                  setMlkemCt(result.ciphertext_b64 ?? "");
                  setMlkemSs(result.shared_secret_b64 ?? "");
                }}
                disabled={!mlkemPkValid}
              >
                Encapsulate
              </button>
              <label>Ciphertext (base64)</label>
              <textarea rows={4} value={mlkemCt} onChange={(event) => setMlkemCt(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mlkemCt)}>Copy</button>
                <span className="hint">Hex: {toHex(mlkemCt).slice(0, 64)}…</span>
              </div>
              <label>Shared secret (base64)</label>
              <textarea rows={3} value={mlkemSs} onChange={(event) => setMlkemSs(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mlkemSs)}>Copy</button>
                <span className="hint">Hex: {toHex(mlkemSs).slice(0, 64)}…</span>
              </div>
            </div>
          </Panel>
          <Panel title="ML-KEM decapsulate" subtitle="Recover shared secret">
            <div className="form-grid">
              <label>Ciphertext (base64)</label>
              <textarea rows={4} value={mlkemCt} onChange={(event) => setMlkemCt(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mlkemCt)}>Copy</button>
                <span className="hint">Hex: {toHex(mlkemCt).slice(0, 64)}…</span>
              </div>
              <label>Secret key (base64)</label>
              <textarea rows={4} value={mlkemSk} onChange={(event) => setMlkemSk(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mlkemSk)}>Copy</button>
                <span className="hint">Hex: {toHex(mlkemSk).slice(0, 64)}…</span>
              </div>
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => mlkemDecaps({
                    alg: mlkemAlg,
                    ciphertext_b64: mlkemCt,
                    secret_key_b64: mlkemSk,
                  }, { apiKey }));
                  if (!result) return;
                  if (result?.error) {
                    setQwStatus(result.error);
                    return;
                  }
                  setMlkemSs(result.shared_secret_b64 ?? "");
                }}
                disabled={!mlkemCtValid || !mlkemSkValid}
              >
                Decapsulate
              </button>
              <label>Shared secret (base64)</label>
              <textarea rows={3} value={mlkemSs} onChange={(event) => setMlkemSs(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mlkemSs)}>Copy</button>
                <span className="hint">Hex: {toHex(mlkemSs).slice(0, 64)}…</span>
              </div>
            </div>
          </Panel>
          <Panel title="ML-DSA keygen" subtitle="Generate signature keys (base64)">
            <div className="form-grid">
              <label>Algorithm</label>
              <select value={mldsaAlg} onChange={(event) => setMldsaAlg(event.target.value)}>
                {["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"].map((alg) => (
                  <option key={alg} value={alg}>
                    {alg}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => mldsaKeygen(mldsaAlg, { apiKey }));
                  if (!result) return;
                  if (result?.error) {
                    setQwStatus(result.error);
                    return;
                  }
                  setMldsaPk(result.public_key_b64 ?? "");
                  setMldsaSk(result.secret_key_b64 ?? "");
                }}
              >
                Generate ML-DSA keys
              </button>
              <label>Public key (base64)</label>
              <textarea rows={4} value={mldsaPk} onChange={(event) => setMldsaPk(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mldsaPk)}>Copy</button>
                <span className="hint">Hex: {toHex(mldsaPk).slice(0, 64)}…</span>
              </div>
              <label>Secret key (base64)</label>
              <textarea rows={4} value={mldsaSk} onChange={(event) => setMldsaSk(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mldsaSk)}>Copy</button>
                <span className="hint">Hex: {toHex(mldsaSk).slice(0, 64)}…</span>
              </div>
            </div>
          </Panel>
          <Panel title="ML-DSA sign" subtitle="Sign a message">
            <div className="form-grid">
              <label>Message</label>
              <textarea rows={3} value={mldsaMessage} onChange={(event) => setMldsaMessage(event.target.value)} />
              <label>Secret key (base64)</label>
              <textarea rows={4} value={mldsaSk} onChange={(event) => setMldsaSk(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mldsaSk)}>Copy</button>
                <span className="hint">Hex: {toHex(mldsaSk).slice(0, 64)}…</span>
              </div>
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => mldsaSign({
                    alg: mldsaAlg,
                    secret_key_b64: mldsaSk,
                    message: mldsaMessage,
                  }, { apiKey }));
                  if (!result) return;
                  if (result?.error) {
                    setQwStatus(result.error);
                    return;
                  }
                  setMldsaSig(result.signature_b64 ?? "");
                }}
                disabled={!mldsaSkValid || !mldsaMsgValid}
              >
                Sign message
              </button>
              <label>Signature (base64)</label>
              <textarea rows={4} value={mldsaSig} onChange={(event) => setMldsaSig(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mldsaSig)}>Copy</button>
                <span className="hint">Hex: {toHex(mldsaSig).slice(0, 64)}…</span>
              </div>
            </div>
          </Panel>
          <Panel title="ML-DSA verify" subtitle="Verify a signature">
            <div className="form-grid">
              <label>Message</label>
              <textarea rows={3} value={mldsaMessage} onChange={(event) => setMldsaMessage(event.target.value)} />
              <label>Public key (base64)</label>
              <textarea rows={4} value={mldsaPk} onChange={(event) => setMldsaPk(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mldsaPk)}>Copy</button>
                <span className="hint">Hex: {toHex(mldsaPk).slice(0, 64)}…</span>
              </div>
              <label>Signature (base64)</label>
              <textarea rows={4} value={mldsaSig} onChange={(event) => setMldsaSig(event.target.value)} />
              <div className="field-actions">
                <button type="button" onClick={() => copyText(mldsaSig)}>Copy</button>
                <span className="hint">Hex: {toHex(mldsaSig).slice(0, 64)}…</span>
              </div>
              <button
                type="button"
                onClick={async () => {
                  const result = await runRequest(() => mldsaVerify({
                    alg: mldsaAlg,
                    public_key_b64: mldsaPk,
                    signature_b64: mldsaSig,
                    message: mldsaMessage,
                  }, { apiKey }));
                  if (!result) return;
                  if (result?.error) {
                    setQwStatus(result.error);
                    return;
                  }
                  setMldsaValid(result.valid ? "valid" : "invalid");
                }}
                disabled={!mldsaPkValid || !mldsaSigValid || !mldsaMsgValid}
              >
                Verify signature
              </button>
              {mldsaValid ? <p className="hint">Signature is {mldsaValid}.</p> : null}
            </div>
          </Panel>
        </section>
      ) : null}
    </div>
  );
}
