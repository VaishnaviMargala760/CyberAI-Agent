from ip_risk import is_blacklisted

def _severity_score(severity: str) -> int:
    s = (severity or "").upper()
    if s == "CRITICAL": return 4
    if s == "HIGH": return 3
    if s == "MEDIUM": return 2
    return 1


def build_agent_plan(event: dict, detection: dict):
    """
    Agentic plan based on:
    - detection reasons
    - anomaly flag
    - hard rules (bruteforce / scan / exfil)
    - blacklist override
    """
    ip = event.get("ip", "")
    failed = int(event.get("failed_logins", 0) or 0)
    rpm = int(event.get("requests_per_min", 0) or 0)
    ports = int(event.get("unique_ports", 0) or 0)
    bytes_out = int(event.get("bytes_out_kb", 0) or 0)

    reasons = detection.get("reasons", []) or []
    is_anomaly = bool(detection.get("is_anomaly", False))

    severity = "LOW"
    actions = []

    # ---- Rule-based severity ----
    if bytes_out >= 5000:
        severity = "CRITICAL"
        actions.append({"type": "ISOLATE_HOST", "host": event.get("host", "local")})
        actions.append({"type": "ALERT", "message": "Possible data exfiltration detected"})
    elif ports >= 40 or rpm >= 120:
        severity = "HIGH"
        actions.append({"type": "BLOCK_IP", "ip": ip})
        actions.append({"type": "ALERT", "message": f"Port scan / DDoS suspected from {ip}"})
    elif failed >= 8:
        severity = "MEDIUM"
        actions.append({"type": "BLOCK_IP", "ip": ip})
        actions.append({"type": "ALERT", "message": f"Brute force suspected from {ip}"})

    # ---- Anomaly bump ----
    if is_anomaly and severity == "LOW":
        severity = "MEDIUM"
        actions.append({"type": "ALERT", "message": f"Anomaly detected from {ip}"})

    # ---- Include detector reasons as alerts (optional) ----
    for r in reasons[:2]:
        actions.append({"type": "NOTE", "message": r})

    # ---- Persistent Blacklist Override ----
    if ip and is_blacklisted(ip):
        # force highest priority
        severity = "CRITICAL"
        # ensure BLOCK_IP exists
        if not any(a.get("type") == "BLOCK_IP" for a in actions):
            actions.insert(0, {"type": "BLOCK_IP", "ip": ip})
        actions.insert(0, {"type": "ALERT", "message": f"BLACKLISTED IP detected: {ip} (auto-block enforced)"})

    plan = {
        "severity": severity,
        "severity_score": _severity_score(severity),
        "actions": actions
    }
    return plan