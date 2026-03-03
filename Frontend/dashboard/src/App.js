import React, { useEffect, useMemo, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:5000";

function Card({ title, right, children }) {
  return (
    <div className="card">
      <div className="cardHead">
        <div className="cardTitle">{title}</div>
        <div className="cardRight">{right}</div>
      </div>
      <div className="cardBody">{children}</div>
    </div>
  );
}

function Badge({ text }) {
  const cls =
    text === "CRITICAL"
      ? "badge critical"
      : text === "HIGH"
      ? "badge high"
      : text === "MEDIUM"
      ? "badge medium"
      : "badge low";
  return <span className={cls}>{text}</span>;
}

function nowISO() {
  return new Date().toISOString();
}

// -------- Charts (no extra libraries) --------
function MiniLineChart({ points = [] }) {
  if (!points.length) return <div className="hint">No chart data yet</div>;

  const w = 520;
  const h = 120;
  const pad = 12;

  const ys = points.map((p) => Number(p));
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const range = maxY - minY || 1;

  const xScale = (i) =>
    pad + (i / Math.max(points.length - 1, 1)) * (w - pad * 2);
  const yScale = (y) => h - pad - ((y - minY) / range) * (h - pad * 2);

  const d = points
    .map((y, i) => `${i === 0 ? "M" : "L"} ${xScale(i)} ${yScale(Number(y))}`)
    .join(" ");

  return (
    <div className="chartWrap">
      <svg width="100%" viewBox={`0 0 ${w} ${h}`}>
        <path d={d} fill="none" stroke="currentColor" strokeWidth="2" />
      </svg>
      <div className="chartMeta">
        <span>min: {minY.toFixed(4)}</span>
        <span>max: {maxY.toFixed(4)}</span>
        <span>latest: {ys[ys.length - 1].toFixed(4)}</span>
      </div>
    </div>
  );
}

function SeverityBars({ counts }) {
  const items = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((k) => ({
    key: k,
    val: counts[k] || 0,
  }));
  const maxV = Math.max(...items.map((x) => x.val), 1);

  return (
    <div className="barList">
      {items.map((it) => (
        <div className="barRow" key={it.key}>
          <div className="barLabel">
            <Badge text={it.key} />
          </div>
          <div className="barTrack">
            <div
              className="barFill"
              style={{ width: `${(it.val / maxV) * 100}%` }}
            />
          </div>
          <div className="barNum">{it.val}</div>
        </div>
      ))}
    </div>
  );
}

export default function App() {
  const [result, setResult] = useState(null);
  const [logs, setLogs] = useState([]);
  const [scoreSeries, setScoreSeries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [logLoading, setLogLoading] = useState(false);

  // ✅ Custom event form
  const [form, setForm] = useState({
    ip: "192.168.1.45",
    host: "local",
    failed_logins: 10,
    requests_per_min: 30,
    bytes_out_kb: 120,
    unique_ports: 2,
    new_processes: 0,
  });

  // ✅ Training panel
  const [trainParams, setTrainParams] = useState({
    n_baseline: 800,
    contamination: 0.06,
    n_estimators: 250,
  });
  const [trainMsg, setTrainMsg] = useState("");
  const [trainInfo, setTrainInfo] = useState(null);
  const [training, setTraining] = useState(false);

  const formJson = useMemo(() => JSON.stringify(form, null, 2), [form]);

  const loadLogs = async () => {
    setLogLoading(true);
    try {
      const res = await fetch(`${API}/api/logs`);
      if (!res.ok) return;
      const data = await res.json();
      setLogs(Array.isArray(data.logs) ? data.logs : []);
    } catch {
      // ignore
    } finally {
      setLogLoading(false);
    }
  };

  const pushScore = (data) => {
    const s = Number(data?.detection?.anomaly_score || 0);
    setScoreSeries((p) => [...p.slice(-29), s]); // keep last 30
  };

  const callDemo = async (type) => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/demo/${type}`);
      if (!res.ok) throw new Error("Bad response");
      const data = await res.json();
      setResult(data);
      pushScore(data);
      await loadLogs();
    } catch {
      alert("Backend not reachable. Is Flask running on 127.0.0.1:5000 ?");
    } finally {
      setLoading(false);
    }
  };

  const analyzeCustom = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error("Bad response");
      const data = await res.json();
      setResult(data);
      pushScore(data);
      await loadLogs();
    } catch {
      alert("Analyze failed. Check backend + CORS.");
    } finally {
      setLoading(false);
    }
  };

  const retrain = async () => {
    setTraining(true);
    setTrainMsg("");
    setTrainInfo(null);
    try {
      const res = await fetch(`${API}/api/train`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(trainParams),
      });
      if (!res.ok) throw new Error("train failed");
      const data = await res.json();
      setTrainMsg(data.message || "Model retrained ✅");
      setTrainInfo(data.info || null);
    } catch (e) {
      setTrainMsg("Training failed ❌ (check backend)");
    } finally {
      setTraining(false);
    }
  };

  useEffect(() => {
    callDemo("bruteforce");
    const t = setInterval(loadLogs, 5000);
    return () => clearInterval(t);
    // eslint-disable-next-line
  }, []);

  const setNum = (key, value) => {
    const v = value === "" ? "" : Number(value);
    setForm((p) => ({ ...p, [key]: v }));
  };

  const setText = (key, value) => setForm((p) => ({ ...p, [key]: value }));

  const severityCounts = useMemo(() => {
    return logs.reduce((acc, l) => {
      const s = (l.severity || "LOW").toUpperCase();
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {});
  }, [logs]);

  return (
    <div className="page">
      <div className="topbar">
        <div className="brand">
          <div className="logo">CA</div>
          <div>
            <div className="brandTitle">CyberAI Agent Dashboard</div>
            <div className="brandSub">Threat Detection + Agentic Response</div>
          </div>
        </div>

        <div className="btnRow">
          <button onClick={() => callDemo("bruteforce")} disabled={loading}>
            Brute Force
          </button>
          <button onClick={() => callDemo("scan")} disabled={loading}>
            Scan / DDoS
          </button>
          <button onClick={() => callDemo("exfil")} disabled={loading}>
            Data Exfil
          </button>
        </div>
      </div>

      <div className="grid">
        {/* ✅ Custom event form */}
        <Card
          title="Custom Event Analyzer"
          right={
            <button onClick={analyzeCustom} disabled={loading}>
              Analyze
            </button>
          }
        >
          <div className="formGrid">
            <div className="field">
              <div className="fieldLabel">IP</div>
              <input
                value={form.ip}
                onChange={(e) => setText("ip", e.target.value)}
                placeholder="e.g. 192.168.1.10"
              />
            </div>

            <div className="field">
              <div className="fieldLabel">Host</div>
              <input
                value={form.host}
                onChange={(e) => setText("host", e.target.value)}
                placeholder="local"
              />
            </div>

            <div className="field">
              <div className="fieldLabel">Failed Logins</div>
              <input
                type="number"
                value={form.failed_logins}
                onChange={(e) => setNum("failed_logins", e.target.value)}
              />
            </div>

            <div className="field">
              <div className="fieldLabel">Requests / min</div>
              <input
                type="number"
                value={form.requests_per_min}
                onChange={(e) => setNum("requests_per_min", e.target.value)}
              />
            </div>

            <div className="field">
              <div className="fieldLabel">Bytes Out (KB)</div>
              <input
                type="number"
                value={form.bytes_out_kb}
                onChange={(e) => setNum("bytes_out_kb", e.target.value)}
              />
            </div>

            <div className="field">
              <div className="fieldLabel">Unique Ports</div>
              <input
                type="number"
                value={form.unique_ports}
                onChange={(e) => setNum("unique_ports", e.target.value)}
              />
            </div>

            <div className="field">
              <div className="fieldLabel">New Processes</div>
              <input
                type="number"
                value={form.new_processes}
                onChange={(e) => setNum("new_processes", e.target.value)}
              />
            </div>

            <div className="field">
              <div className="fieldLabel">Quick presets</div>
              <div className="presetRow">
                <button
                  className="ghost"
                  onClick={() =>
                    setForm({
                      ip: "192.168.1.45",
                      host: "local",
                      failed_logins: 10,
                      requests_per_min: 30,
                      bytes_out_kb: 120,
                      unique_ports: 2,
                      new_processes: 0,
                    })
                  }
                  disabled={loading}
                >
                  Brute
                </button>
                <button
                  className="ghost"
                  onClick={() =>
                    setForm({
                      ip: "10.0.0.77",
                      host: "local",
                      failed_logins: 0,
                      requests_per_min: 160,
                      bytes_out_kb: 500,
                      unique_ports: 60,
                      new_processes: 0,
                    })
                  }
                  disabled={loading}
                >
                  Scan
                </button>
                <button
                  className="ghost"
                  onClick={() =>
                    setForm({
                      ip: "172.16.0.9",
                      host: "local",
                      failed_logins: 1,
                      requests_per_min: 40,
                      bytes_out_kb: 8000,
                      unique_ports: 4,
                      new_processes: 1,
                    })
                  }
                  disabled={loading}
                >
                  Exfil
                </button>
                <button
                  className="ghost"
                  onClick={() =>
                    setForm({
                      ip: "1.2.3.4",
                      host: "local",
                      failed_logins: 0,
                      requests_per_min: 10,
                      bytes_out_kb: 50,
                      unique_ports: 1,
                      new_processes: 0,
                    })
                  }
                  disabled={loading}
                >
                  Normal
                </button>
              </div>
            </div>
          </div>

          <div className="miniTitle">Payload Preview</div>
          <pre>{formJson}</pre>
          <div className="hint">Tip: change values and click Analyze.</div>
        </Card>

        {/* ✅ Charts */}
        <Card title="Threat Analytics (Live)">
          <div className="miniTitle">Anomaly Score Trend</div>
          <MiniLineChart points={scoreSeries} />

          <div className="miniTitle" style={{ marginTop: 14 }}>
            Severity Distribution (from logs)
          </div>
          <SeverityBars counts={severityCounts} />
          <div className="hint">
            Charts update when you Analyze or click demo buttons.
          </div>
        </Card>

        {/* ✅ Training panel */}
        <Card
          title="Model Training (Agentic)"
          right={
            <button onClick={retrain} disabled={training}>
              {training ? "Training..." : "Retrain Model"}
            </button>
          }
        >
          <div className="formGrid">
            <div className="field">
              <div className="fieldLabel">Baseline Samples</div>
              <input
                type="number"
                value={trainParams.n_baseline}
                onChange={(e) =>
                  setTrainParams((p) => ({
                    ...p,
                    n_baseline: Number(e.target.value),
                  }))
                }
              />
            </div>

            <div className="field">
              <div className="fieldLabel">Contamination</div>
              <input
                type="number"
                step="0.01"
                value={trainParams.contamination}
                onChange={(e) =>
                  setTrainParams((p) => ({
                    ...p,
                    contamination: Number(e.target.value),
                  }))
                }
              />
            </div>

            <div className="field">
              <div className="fieldLabel">Estimators</div>
              <input
                type="number"
                value={trainParams.n_estimators}
                onChange={(e) =>
                  setTrainParams((p) => ({
                    ...p,
                    n_estimators: Number(e.target.value),
                  }))
                }
              />
            </div>
          </div>

          {trainMsg && <div className="hint">{trainMsg}</div>}

          {trainInfo && (
            <>
              <div className="miniTitle">Training Metrics</div>
              <pre>{JSON.stringify(trainInfo, null, 2)}</pre>
              <div className="hint">
                Good sign: validation.anomaly_rate_on_attack high, and
                anomaly_rate_on_normal low.
              </div>
            </>
          )}
        </Card>

        {/* ✅ Result cards */}
        <Card title="Detected Event">
          {!result ? (
            <div className="center">No data yet</div>
          ) : (
            <pre>{JSON.stringify(result.event, null, 2)}</pre>
          )}
        </Card>

        <Card title="Detection Output">
          {!result ? (
            <div className="center">No data yet</div>
          ) : (
            <>
              <div className="row">
                <div className="label">Anomaly:</div>
                <div>{String(result.detection.is_anomaly)}</div>
              </div>
              <div className="row">
                <div className="label">Score:</div>
                <div>{result.detection.anomaly_score}</div>
              </div>

              <div className="label" style={{ marginTop: 10 }}>
                Reasons:
              </div>
              <ul>
                {result.detection.reasons.length === 0 ? (
                  <li>No heuristic reasons</li>
                ) : (
                  result.detection.reasons.map((r, i) => <li key={i}>{r}</li>)
                )}
              </ul>
            </>
          )}
        </Card>

        <Card title="Agent Plan">
          {!result ? (
            <div className="center">No data yet</div>
          ) : (
            <>
              <div className="row">
                <div className="label">Severity:</div>
                <div>
                  <Badge text={result.agent_plan.severity} />
                </div>
              </div>

              <div className="row">
                <div className="label">Score:</div>
                <div>{result.agent_plan.severity_score}</div>
              </div>

              <div className="label" style={{ marginTop: 10 }}>
                Actions:
              </div>
              <ul>
                {result.agent_plan.actions.map((a, i) => (
                  <li key={i}>
                    <b>{a.type}</b> — {JSON.stringify(a)}
                  </li>
                ))}
              </ul>
            </>
          )}
        </Card>

        {/* ✅ Clean logs table */}
        <Card
          title="Recent Actions Log"
          right={
            <button className="ghost" onClick={loadLogs} disabled={logLoading}>
              {logLoading ? "Refreshing..." : "Refresh"}
            </button>
          }
        >
          {logs.length === 0 ? (
            <div>No logs yet</div>
          ) : (
            <div className="logTableWrap">
              <table className="logTable">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {logs
                    .slice()
                    .reverse()
                    .map((l, idx) => {
                      const details = l.action?.details || {};
                      const target =
                        details.ip || details.host || details.note || "-";
                      const time = l.time
                        ? l.time.replace("T", " ").replace("Z", "")
                        : nowISO();
                      return (
                        <tr key={idx}>
                          <td className="mono">{time}</td>
                          <td>
                            <Badge
                              text={(l.severity || "LOW").toUpperCase()}
                            />
                          </td>
                          <td className="mono">{l.action?.type || "-"}</td>
                          <td className="mono">{String(target)}</td>
                          <td className="mono">{l.action?.status || "-"}</td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          )}
          <div className="hint">Auto refreshes every 5 seconds.</div>
        </Card>
      </div>
    </div>
  );
}