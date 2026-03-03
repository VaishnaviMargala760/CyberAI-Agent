# Backend/app.py
from __future__ import annotations

import json
import os
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from flask import Flask, jsonify, request
from flask_cors import CORS

# WebSocket (Socket.IO)
from flask_socketio import SocketIO

# -----------------------------
# Config
# -----------------------------
PORT = int(os.environ.get("PORT", "5000"))
SAFE_MODE = os.environ.get("SAFE_MODE", "true").lower() != "false"
LOG_FILE = os.path.join(os.path.dirname(__file__), "actions_log.jsonl")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# If you face WebSocket issues, install eventlet and keep async_mode="eventlet"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# In-memory counters for quick "intel"
IP_SEEN: Dict[str, int] = {}

# -----------------------------
# Helpers
# -----------------------------
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clamp(n: float, a: float, b: float) -> float:
    return max(a, min(b, n))


def write_log_entry(entry: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_last_logs(limit: int = 20) -> List[Dict[str, Any]]:
    if not os.path.exists(LOG_FILE):
        return []
    # read last N lines safely
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    tail = lines[-limit:]
    out = []
    for ln in reversed(tail):  # newest first
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return out


def basic_detection(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Very simple anomaly scoring (0..1). You can replace with your ML later.
    """
    failed = float(event.get("failed_logins", 0))
    rpm = float(event.get("requests_per_min", 0))
    bytes_out = float(event.get("bytes_out_kb", 0))
    new_proc = float(event.get("new_processes", 0))
    ports = float(event.get("unique_ports", 0))

    score = 0.0
    reasons = []

    if failed >= 8:
        score += 0.25
        reasons.append("High failed_logins (possible brute force).")
    if rpm >= 200:
        score += 0.25
        reasons.append("High requests_per_min (possible scan/DDoS).")
    if bytes_out >= 500:
        score += 0.30
        reasons.append("High bytes_out_kb (possible exfiltration).")
    if new_proc >= 3:
        score += 0.10
        reasons.append("New processes spike (possible compromise).")
    if ports >= 10:
        score += 0.10
        reasons.append("Many unique ports (port scan behavior).")

    score = float(clamp(score, 0.0, 1.0))
    anomaly = score >= 0.55

    if not reasons:
        reasons = ["Within normal thresholds."]

    return {"anomaly": anomaly, "score": score, "reasons": reasons}


def severity_from_detection(det: Dict[str, Any]) -> Tuple[str, int]:
    s = float(det.get("score", 0.0))
    # plan score is 1..10-ish
    if s >= 0.85:
        return "CRITICAL", 9
    if s >= 0.65:
        return "HIGH", 7
    if s >= 0.45:
        return "MEDIUM", 4
    return "LOW", 2


def build_agent_plan(event: Dict[str, Any], det: Dict[str, Any]) -> Dict[str, Any]:
    ip = str(event.get("ip", "unknown"))
    host = str(event.get("host", "local"))

    severity, plan_score = severity_from_detection(det)
    actions = []

    # choose actions based on top signals
    reasons = det.get("reasons", [])
    text = " ".join(reasons).lower()

    if "exfil" in text or float(event.get("bytes_out_kb", 0)) >= 500:
        actions.append({"type": "ISOLATE_HOST", "host": host})
        actions.append({"type": "ALERT", "message": "Possible data exfiltration detected"})
    elif "ddos" in text or float(event.get("requests_per_min", 0)) >= 200:
        actions.append({"type": "BLOCK_IP", "ip": ip})
        actions.append({"type": "ALERT", "message": f"Traffic spike suspected from {ip}"})
    elif float(event.get("failed_logins", 0)) >= 8:
        actions.append({"type": "BLOCK_IP", "ip": ip})
        actions.append({"type": "ALERT", "message": f"Brute force suspected from {ip}"})
    else:
        actions.append({"type": "ALERT", "message": f"Suspicious activity observed from {ip}"})

    return {
        "severity": severity,
        "score": plan_score,
        "actions": actions,
    }


def execute_actions(plan: Dict[str, Any], safe_mode: bool = True) -> Dict[str, Any]:
    """
    Safe execution: simulate only.
    """
    executed = []
    for a in plan.get("actions", []):
        executed.append(
            {
                "type": a.get("type"),
                "status": "SIMULATED" if safe_mode else "EXECUTED",
                "details": a,
            }
        )
    return {"safe_mode": safe_mode, "executed": executed, "log_file": LOG_FILE}


# ---------- IP RISK ----------
def is_private_ip(ip: str) -> bool:
    return ip.startswith("10.") or ip.startswith("192.168.") or (
        ip.startswith("172.") and len(ip.split(".")) >= 2 and ip.split(".")[1].isdigit() and 16 <= int(ip.split(".")[1]) <= 31
    )


def score_ip(ip: str, event: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """
    0..100 risk score
    """
    score = 5
    reasons = []

    if is_private_ip(ip):
        score += 10
        reasons.append("Private IP range (internal host).")

    seen = IP_SEEN.get(ip, 0)
    if seen > 0:
        score += min(35, seen * 7)
        reasons.append(f"Seen in recent events {seen} time(s).")

    if event:
        if float(event.get("failed_logins", 0)) >= 8:
            score += 25
            reasons.append("High failed_logins signal.")
        if float(event.get("requests_per_min", 0)) >= 200:
            score += 25
            reasons.append("High requests_per_min signal.")
        if float(event.get("bytes_out_kb", 0)) >= 500:
            score += 30
            reasons.append("High outbound data signal.")
        if float(event.get("unique_ports", 0)) >= 10:
            score += 10
            reasons.append("Multiple unique ports signal.")

    score = int(clamp(score, 0, 100))

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons = ["No strong risk signals yet."]

    return {"ip": ip, "score": score, "level": level, "reasons": reasons}


# -----------------------------
# Routes
# -----------------------------
@app.get("/api/health")
def health():
    return jsonify({"ok": True, "safe_mode": SAFE_MODE})


@app.get("/api/actions")
def actions():
    limit = int(request.args.get("limit", "20"))
    return jsonify({"logs": read_last_logs(limit=limit)})


@app.get("/api/ip-risk")
def ip_risk():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    return jsonify(score_ip(ip))


@app.post("/api/analyze")
def analyze():
    event = request.get_json(force=True) or {}

    # normalize event fields
    event = {
        "ip": str(event.get("ip", "0.0.0.0")),
        "host": str(event.get("host", "local")),
        "failed_logins": int(event.get("failed_logins", 0)),
        "requests_per_min": int(event.get("requests_per_min", 0)),
        "bytes_out_kb": int(event.get("bytes_out_kb", 0)),
        "unique_ports": int(event.get("unique_ports", 0)),
        "new_processes": int(event.get("new_processes", 0)),
    }

    # update intel
    IP_SEEN[event["ip"]] = IP_SEEN.get(event["ip"], 0) + 1

    detection = basic_detection(event)
    plan = build_agent_plan(event, detection)
    response = execute_actions(plan, safe_mode=SAFE_MODE)

    # log each action as separate line (for dashboard actions log)
    for ex in response["executed"]:
        entry = {
            "time": utc_now(),
            "severity": plan["severity"],
            "action": ex,
        }
        write_log_entry(entry)

    # compute ip risk (with current event signal)
    risk = score_ip(event["ip"], event=event)

    payload = {
        "event": event,
        "detection": detection,
        "plan": plan,
        "response": response,
        "ip_risk": risk,
    }

    # emit realtime feed to UI
    socketio.emit("threat_event", payload)

    return jsonify(payload)


# -----------------------------
# WebSocket events
# -----------------------------
@socketio.on("connect")
def on_connect():
    # you can print if you want, but keep clean
    pass


@socketio.on("disconnect")
def on_disconnect():
    pass


if __name__ == "__main__":
    # IMPORTANT: use socketio.run (not app.run) for websockets
    socketio.run(app, host="127.0.0.1", port=PORT, debug=True)