import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

from threat_detector import detect_threat, retrain_model
from agent import decide_action
from response_engine import execute_actions

app = Flask(__name__)
CORS(app)

SAFE_MODE = True
LOG_FILE = "actions_log.jsonl"


@app.get("/")
def home():
    return jsonify({
        "message": "CyberAI Agent Backend Running ✅",
        "endpoints": [
            "/api/analyze",
            "/api/train",
            "/api/logs",
            "/api/demo/bruteforce",
            "/api/demo/scan",
            "/api/demo/exfil"
        ]
    })


@app.post("/api/analyze")
def analyze():
    event = request.get_json(force=True)

    detection = detect_threat(event)
    plan = decide_action(event, detection)
    response = execute_actions(plan, safe_mode=SAFE_MODE)

    return jsonify({
        "event": event,
        "detection": detection,
        "agent_plan": plan,
        "response": response
    })


@app.post("/api/train")
def train():
    """
    Body (optional):
    {
      "n_baseline": 800,
      "contamination": 0.06,
      "n_estimators": 250
    }
    """
    body = request.get_json(silent=True) or {}
    n_baseline = int(body.get("n_baseline", 800))
    contamination = float(body.get("contamination", 0.06))
    n_estimators = int(body.get("n_estimators", 250))

    info = retrain_model(
        n_baseline=n_baseline,
        contamination=contamination,
        n_estimators=n_estimators
    )

    return jsonify({
        "message": "Model retrained ✅",
        "info": info
    })


@app.get("/api/logs")
def get_logs():
    if not os.path.exists(LOG_FILE):
        return jsonify({"logs": []})

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    last = lines[-20:]
    parsed = []
    for line in last:
        line = line.strip()
        if not line:
            continue
        try:
            parsed.append(json.loads(line))
        except Exception:
            parsed.append({"raw": line})

    return jsonify({"logs": parsed})


@app.get("/api/demo/bruteforce")
def demo_bruteforce():
    event = {
        "ip": "192.168.1.45",
        "host": "local",
        "failed_logins": 10,
        "requests_per_min": 30,
        "bytes_out_kb": 120,
        "unique_ports": 2,
        "new_processes": 0
    }
    detection = detect_threat(event)
    plan = decide_action(event, detection)
    response = execute_actions(plan, safe_mode=SAFE_MODE)
    return jsonify({"event": event, "detection": detection, "agent_plan": plan, "response": response})


@app.get("/api/demo/scan")
def demo_scan():
    event = {
        "ip": "10.0.0.77",
        "host": "local",
        "failed_logins": 0,
        "requests_per_min": 160,
        "bytes_out_kb": 500,
        "unique_ports": 60,
        "new_processes": 0
    }
    detection = detect_threat(event)
    plan = decide_action(event, detection)
    response = execute_actions(plan, safe_mode=SAFE_MODE)
    return jsonify({"event": event, "detection": detection, "agent_plan": plan, "response": response})


@app.get("/api/demo/exfil")
def demo_exfil():
    event = {
        "ip": "172.16.0.9",
        "host": "local",
        "failed_logins": 1,
        "requests_per_min": 40,
        "bytes_out_kb": 8000,
        "unique_ports": 4,
        "new_processes": 1
    }
    detection = detect_threat(event)
    plan = decide_action(event, detection)
    response = execute_actions(plan, safe_mode=SAFE_MODE)
    return jsonify({"event": event, "detection": detection, "agent_plan": plan, "response": response})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)