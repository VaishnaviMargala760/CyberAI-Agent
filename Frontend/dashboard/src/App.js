// Frontend/dashboard/src/App.js
import React, { useEffect, useMemo, useRef, useState } from "react";
import { io } from "socket.io-client";
import "./App.css";

const API_BASE = "http://127.0.0.1:5000";
const WS_URL = "http://127.0.0.1:5000";

const fmt = (n) => {
  if (n === null || n === undefined) return "";
  if (typeof n === "number") return Number.isInteger(n) ? String(n) : n.toFixed(4);
  return String(n);
};

function MiniLineChart({ values }) {
  // Simple SVG sparkline
  const w = 520;
  const h = 140;
  const pad = 10;

  const safe = values && values.length ? values : [0, 0, 0, 0, 0];
  const minV = Math.min(...safe);
  const maxV = Math.max(...safe);
  const range = maxV - minV || 1;

  const points = safe
    .map((v, i) => {
      const x = pad + (i * (w - pad * 2)) / (safe.length - 1 || 1);
      const y = pad + (h - pad * 2) * (1 - (v - minV) / range);
      return [x, y];
    })
    .map((p) => p.join(","))
    .join(" ");

  return (
    <div className="chartBox">
      <svg width="100%" viewBox={`0 0 ${w} ${h}`}>
        <polyline fill="none" stroke="rgba(120,245,255,0.95)" strokeWidth="3" points={points} />
      </svg>
      <div className="chartMeta">
        <span>min: {fmt(minV)}</span>
        <span>max: {fmt(maxV)}</span>
        <span>latest: {fmt(safe[safe.length - 1])}</span>
      </div>
    </div>
  );
}

export default function App() {
  const [connected, setConnected] = useState(false);

  const [tab, setTab] = useState("Brute");
  const [event, setEvent] = useState({
    ip: "192.168.1.45",
    host: "local",
    failed_logins: 10,
    requests_per_min: 30,
    bytes_out_kb: 120,
    unique_ports: 2,
    new_processes: 0,
  });

  const [detectedEvent, setDetectedEvent] = useState(null);
  const [detection, setDetection] = useState(null);
  const [plan, setPlan] = useState(null);
  const [response, setResponse] = useState(null);
  const [actionsLog, setActionsLog] = useState([]);

  const [trend, setTrend] = useState([]); // anomaly scores
  const [severityCounts, setSeverityCounts] = useState({ LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 });

  const [banner, setBanner] = useState([]); // last few alerts
  const [ipRisk, setIpRisk] = useState(null);

  const socketRef = useRef(null);

  const payloadPreview = useMemo(() => JSON.stringify(event, null, 2), [event]);
  const detectedPreview = useMemo(() => (detectedEvent ? JSON.stringify(detectedEvent, null, 2) : ""), [detectedEvent]);

  const setPreset = (kind) => {
    if (kind === "Brute") {
      setTab("Brute");
      setEvent((e) => ({ ...e, failed_logins: 12, requests_per_min: 40, bytes_out_kb: 120, unique_ports: 2, new_processes: 0 }));
    } else if (kind === "Scan") {
      setTab("Scan");
      setEvent((e) => ({ ...e, failed_logins: 1, requests_per_min: 260, bytes_out_kb: 80, unique_ports: 18, new_processes: 1 }));
    } else if (kind === "Exfil") {
      setTab("Exfil");
      setEvent((e) => ({ ...e, failed_logins: 0, requests_per_min: 40, bytes_out_kb: 850, unique_ports: 3, new_processes: 2 }));
    } else {
      setTab("Normal");
      setEvent((e) => ({ ...e, failed_logins: 0, requests_per_min: 25, bytes_out_kb: 60, unique_ports: 2, new_processes: 0 }));
    }
  };

  const fetchActions = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/actions?limit=20`);
      const data = await res.json();
      setActionsLog(data.logs || []);
      // recompute severity counts from logs
      const counts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
      (data.logs || []).forEach((l) => {
        const s = l.severity || "LOW";
        if (counts[s] !== undefined) counts[s] += 1;
      });
      setSeverityCounts(counts);
    } catch {
      // ignore
    }
  };

  const fetchRisk = async (ip) => {
    try {
      const res = await fetch(`${API_BASE}/api/ip-risk?ip=${encodeURIComponent(ip)}`);
      const data = await res.json();
      setIpRisk(data);
    } catch {
      setIpRisk(null);
    }
  };

  const analyze = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event),
      });
      const data = await res.json();

      setDetectedEvent(data.event);
      setDetection(data.detection);
      setPlan(data.plan);
      setResponse(data.response);
      setIpRisk(data.ip_risk || null);

      // trend update
      setTrend((t) => {
        const next = [...t, Number(data.detection?.score || 0)];
        return next.slice(-12);
      });

      // banner (last 5)
      const sev = data.plan?.severity || "LOW";
      const act0 = data.plan?.actions?.[0]?.type || "ALERT";
      setBanner((b) => {
        const msg = `${sev} threat — ${act0}`;
        const next = [msg, ...b];
        return next.slice(0, 5);
      });

      // also refresh logs list
      fetchActions();
    } catch (e) {
      alert(`Backend not reachable. Is Flask running on 127.0.0.1:5000 ?`);
    }
  };

  // WebSocket live feed
  useEffect(() => {
    const socket = io(WS_URL, { transports: ["websocket"] });
    socketRef.current = socket;

    socket.on("connect", () => setConnected(true));
    socket.on("disconnect", () => setConnected(false));

    socket.on("threat_event", (data) => {
      // When backend pushes new event, update UI live
      if (!data) return;

      setDetectedEvent(data.event || null);
      setDetection(data.detection || null);
      setPlan(data.plan || null);
      setResponse(data.response || null);
      if (data.ip_risk) setIpRisk(data.ip_risk);

      const score = Number(data.detection?.score || 0);
      setTrend((t) => {
        const next = [...t, score];
        return next.slice(-12);
      });

      const sev = data.plan?.severity || "LOW";
      const act0 = data.plan?.actions?.[0]?.type || "ALERT";
      setBanner((b) => {
        const msg = `${sev} threat — ${act0}`;
        const next = [msg, ...b];
        return next.slice(0, 5);
      });

      fetchActions();
    });

    return () => socket.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Initial load
  useEffect(() => {
    fetchActions();
    fetchRisk(event.ip);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Risk refresh when IP changes
  useEffect(() => {
    if (event.ip) fetchRisk(event.ip);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [event.ip]);

  const riskPillClass = (level) => {
    if (!level) return "pill";
    const l = level.toUpperCase();
    if (l === "CRITICAL") return "pill pillCritical";
    if (l === "HIGH") return "pill pillHigh";
    if (l === "MEDIUM") return "pill pillMedium";
    return "pill pillLow";
  };

  return (
    <div className="page">
      <div className="bgGlow" />

      <div className="container">
        {/* Top Bar */}
        <div className="topBar glass">
          <div className="brand">
            <div className="logoBadge">CA</div>
            <div className="brandText">
              <div className="title">CyberAI Agent Dashboard</div>
              <div className="subtitle">
                Threat Detection + Agentic Response •{" "}
                <span className={connected ? "ok" : "bad"}>{connected ? "connected" : "disconnected"}</span>
              </div>
            </div>
          </div>

          <div className="navBtns">
            <button className={`navBtn ${tab === "Brute" ? "active" : ""}`} onClick={() => setPreset("Brute")}>
              Brute Force
            </button>
            <button className={`navBtn ${tab === "Scan" ? "active" : ""}`} onClick={() => setPreset("Scan")}>
              Scan / DDoS
            </button>
            <button className={`navBtn ${tab === "Exfil" ? "active" : ""}`} onClick={() => setPreset("Exfil")}>
              Data Exfil
            </button>
          </div>
        </div>

        {/* Alert Banner */}
        {banner.length > 0 && (
          <div className="alertTicker glass">
            <div className="tickerInner">
              {banner.map((b, i) => (
                <span key={i} className="tickerItem">
                  ⚠ {b}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Main grid */}
        <div className="grid2">
          {/* Left: Form */}
          <div className="card glass">
            <div className="cardHead">
              <div>
                <div className="cardTitle">Custom Event Analyzer</div>
                <div className="cardHint">Tip: change values and click Analyze.</div>
              </div>
              <button className="primaryBtn" onClick={analyze}>
                Analyze
              </button>
            </div>

            <div className="formGrid">
              <div className="field">
                <label>IP</label>
                <input value={event.ip} onChange={(e) => setEvent({ ...event, ip: e.target.value })} />
              </div>

              <div className="field">
                <label>Host</label>
                <input value={event.host} onChange={(e) => setEvent({ ...event, host: e.target.value })} />
              </div>

              <div className="field">
                <label>Failed Logins</label>
                <input
                  type="number"
                  value={event.failed_logins}
                  onChange={(e) => setEvent({ ...event, failed_logins: Number(e.target.value) })}
                />
              </div>

              <div className="field">
                <label>Requests / min</label>
                <input
                  type="number"
                  value={event.requests_per_min}
                  onChange={(e) => setEvent({ ...event, requests_per_min: Number(e.target.value) })}
                />
              </div>

              <div className="field">
                <label>Bytes Out (KB)</label>
                <input
                  type="number"
                  value={event.bytes_out_kb}
                  onChange={(e) => setEvent({ ...event, bytes_out_kb: Number(e.target.value) })}
                />
              </div>

              <div className="field">
                <label>Unique Ports</label>
                <input
                  type="number"
                  value={event.unique_ports}
                  onChange={(e) => setEvent({ ...event, unique_ports: Number(e.target.value) })}
                />
              </div>

              <div className="field">
                <label>New Processes</label>
                <input
                  type="number"
                  value={event.new_processes}
                  onChange={(e) => setEvent({ ...event, new_processes: Number(e.target.value) })}
                />
              </div>

              <div className="quick">
                <div className="quickLabel">Quick presets</div>
                <div className="quickBtns">
                  <button className="chip" onClick={() => setPreset("Brute")}>
                    Brute
                  </button>
                  <button className="chip" onClick={() => setPreset("Scan")}>
                    Scan
                  </button>
                  <button className="chip" onClick={() => setPreset("Exfil")}>
                    Exfil
                  </button>
                  <button className="chip" onClick={() => setPreset("Normal")}>
                    Normal
                  </button>
                </div>
              </div>
            </div>

            <div className="subCard">
              <div className="subTitle">Payload Preview</div>
              <pre className="code">{payloadPreview}</pre>
            </div>
          </div>

          {/* Right: Analytics */}
          <div className="card glass">
            <div className="cardHead">
              <div>
                <div className="cardTitle">Threat Analytics (Live)</div>
                <div className="cardHint">Charts update instantly via WebSocket.</div>
              </div>
            </div>

            <div className="subCard">
              <div className="subTitle">Anomaly Score Trend</div>
              {trend.length ? <MiniLineChart values={trend} /> : <div className="empty">No chart data yet</div>}
            </div>

            <div className="subCard">
              <div className="subTitle">Severity Distribution (Live Feed)</div>

              {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((k) => {
                const v = severityCounts[k] || 0;
                const max = Math.max(...Object.values(severityCounts), 1);
                const pct = (v / max) * 100;
                return (
                  <div key={k} className="sevRow">
                    <span className={`sevTag sev_${k}`}>{k}</span>
                    <div className="sevBar">
                      <div className="sevFill" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="sevNum">{v}</span>
                  </div>
                );
              })}
            </div>

            <div className="subCard">
              <div className="subTitle">IP Risk Scoring</div>
              {!ipRisk ? (
                <div className="empty">No risk data yet</div>
              ) : (
                <div className="riskBox">
                  <div className="riskTop">
                    <div className="riskIP">{ipRisk.ip}</div>
                    <div className={riskPillClass(ipRisk.level)}>
                      {ipRisk.level} • {ipRisk.score}/100
                    </div>
                  </div>
                  <ul className="riskReasons">
                    {(ipRisk.reasons || []).map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Lower grid */}
        <div className="grid2">
          <div className="card glass">
            <div className="cardHead">
              <div className="cardTitle">Detected Event</div>
            </div>
            <pre className="code">{detectedPreview || "Run Analyze to generate an event."}</pre>
          </div>

          <div className="card glass">
            <div className="cardHead">
              <div className="cardTitle">Detection Output</div>
            </div>
            <div className="kv">
              <div className="kvRow">
                <span className="k">Anomaly:</span> <span className="v">{String(detection?.anomaly ?? "-")}</span>
              </div>
              <div className="kvRow">
                <span className="k">Score:</span> <span className="v">{fmt(detection?.score ?? "-")}</span>
              </div>
              <div className="kvRow">
                <span className="k">Reasons:</span>
              </div>
              <ul className="list">
                {(detection?.reasons || []).map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        <div className="grid2">
          <div className="card glass">
            <div className="cardHead">
              <div className="cardTitle">Agent Plan</div>
            </div>
            <div className="kv">
              <div className="kvRow">
                <span className="k">Severity:</span> <span className="v">{plan?.severity || "-"}</span>
              </div>
              <div className="kvRow">
                <span className="k">Score:</span> <span className="v">{plan?.score ?? "-"}</span>
              </div>

              <div className="kvRow">
                <span className="k">Actions:</span>
              </div>
              <ul className="list">
                {(plan?.actions || []).map((a, i) => (
                  <li key={i}>
                    <b>{a.type}</b> — {JSON.stringify(a)}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="card glass">
            <div className="cardHead">
              <div className="cardTitle">Automated Response (Safe Mode)</div>
            </div>
            <div className="kv">
              <div className="kvRow">
                <span className="k">Safe Mode:</span> <span className="v">{String(response?.safe_mode ?? "-")}</span>
              </div>
              <div className="kvRow">
                <span className="k">Executed:</span>
              </div>
              <ul className="list">
                {(response?.executed || []).map((x, i) => (
                  <li key={i}>
                    <b>{x.type}</b> — {x.status} — {JSON.stringify(x.details)}
                  </li>
                ))}
              </ul>
              <div className="kvRow">
                <span className="k">Log File:</span> <span className="v">{response?.log_file || "-"}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="card glass">
          <div className="cardHead">
            <div className="cardTitle">Recent Actions Log (Last 20)</div>
            <button className="ghostBtn" onClick={fetchActions}>
              Refresh
            </button>
          </div>

          {!actionsLog.length ? (
            <div className="empty">No logs yet.</div>
          ) : (
            <div className="logList">
              {actionsLog.map((l, idx) => (
                <div key={idx} className="logItem">
                  <div className="logMeta">
                    <span className="logTime">{l.time}</span>
                    <span className={`pill pillSmall ${riskPillClass(l.severity).replace("pill ", "")}`}>
                      {l.severity}
                    </span>
                  </div>
                  <div className="logAction">
                    <b>{l.action?.type}</b> — {l.action?.status}
                  </div>
                  <pre className="logCode">{JSON.stringify(l.action?.details || {}, null, 2)}</pre>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="footerSpace" />
      </div>
    </div>
  );
}