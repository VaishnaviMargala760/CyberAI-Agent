from typing import Dict, Any


def decide_action(event: Dict[str, Any], detection: Dict[str, Any]) -> Dict[str, Any]:
    """
    Agentic AI Decision Engine (rule-based now, upgradeable later).
    Produces: severity + action plan.
    """

    ip = event.get("ip", "unknown")

    # ---- severity scoring (explainable) ----
    severity = 0
    severity += 3 if int(event.get("failed_logins", 0)) >= 6 else 0
    severity += 3 if int(event.get("unique_ports", 0)) >= 20 else 0
    severity += 4 if int(event.get("requests_per_min", 0)) >= 120 else 0
    severity += 4 if int(event.get("bytes_out_kb", 0)) >= 5000 else 0
    severity += 2 if int(event.get("new_processes", 0)) >= 5 else 0

    # IMPORTANT: convert to real Python bool (avoid numpy.bool_ JSON issue)
    if bool(detection.get("is_anomaly", False)):
        severity += 2

    if severity >= 8:
        level = "CRITICAL"
    elif severity >= 5:
        level = "HIGH"
    elif severity >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    actions = []

    # ---- decision policies ----

    # Brute force policy
    if int(event.get("failed_logins", 0)) >= 6:
        actions.append({"type": "BLOCK_IP", "ip": ip})
        actions.append({"type": "ALERT", "message": f"Brute force suspected from {ip}"})

    # Scan/DDoS policy
    if int(event.get("unique_ports", 0)) >= 20 or int(event.get("requests_per_min", 0)) >= 120:
        actions.append({"type": "RATE_LIMIT", "ip": ip})
        actions.append({"type": "ALERT", "message": f"Scan/DDoS suspected from {ip}"})

    # Data exfil policy
    if int(event.get("bytes_out_kb", 0)) >= 5000:
        actions.append({"type": "ISOLATE_HOST", "host": event.get("host", "local")})
        actions.append({"type": "ALERT", "message": "Possible data exfiltration detected"})

    # Suspicious process burst policy
    if int(event.get("new_processes", 0)) >= 5:
        actions.append({"type": "QUARANTINE", "note": "Suspicious process burst; quarantine recommended"})
        actions.append({"type": "ALERT", "message": "Suspicious new processes detected"})

    # If anomaly but no rules matched, still alert
    if bool(detection.get("is_anomaly", False)) and not actions:
        actions.append({"type": "ALERT", "message": f"Anomalous behavior detected from {ip} (needs review)"})

    return {
        "severity": level,
        "severity_score": int(severity),
        "actions": actions
    }