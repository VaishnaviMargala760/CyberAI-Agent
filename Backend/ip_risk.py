import json
import os
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "risk_db.json")

# auto blacklist threshold
BLACKLIST_THRESHOLD = 10


def _now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load():
    if not os.path.exists(DB_FILE):
        return {"ips": {}, "blacklist": {}}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {"ips": {}, "blacklist": {}}


def _save(db):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


def _level(score: int):
    if score >= 15:
        return "CRITICAL"
    if score >= 10:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"


def _bump(severity: str, event: dict, action_types: list[str]):
    """
    Points system (simple + explainable)
    """
    pts = 0

    # from severity
    sev = (severity or "").upper()
    if sev == "CRITICAL":
        pts += 4
    elif sev == "HIGH":
        pts += 3
    elif sev == "MEDIUM":
        pts += 2
    else:
        pts += 1

    # from signals
    failed = int(event.get("failed_logins", 0) or 0)
    rpm = int(event.get("requests_per_min", 0) or 0)
    ports = int(event.get("unique_ports", 0) or 0)
    bytes_out = int(event.get("bytes_out_kb", 0) or 0)
    new_proc = int(event.get("new_processes", 0) or 0)

    if failed >= 8:
        pts += 3
    elif failed >= 4:
        pts += 2

    if rpm >= 120:
        pts += 3
    elif rpm >= 60:
        pts += 2

    if ports >= 40:
        pts += 3
    elif ports >= 10:
        pts += 2

    if bytes_out >= 5000:
        pts += 4
    elif bytes_out >= 1000:
        pts += 2

    if new_proc >= 3:
        pts += 2
    elif new_proc >= 1:
        pts += 1

    # from actions
    if "ISOLATE_HOST" in action_types:
        pts += 4
    if "BLOCK_IP" in action_types:
        pts += 2
    if "ALERT" in action_types:
        pts += 1

    return pts


def is_blacklisted(ip: str) -> bool:
    db = _load()
    return ip in db.get("blacklist", {})


def update_ip_risk(ip: str, severity: str, event: dict, action_types: list):
    """
    Updates risk score and persists.
    Auto-blacklists if score >= threshold.
    Returns risk object for this IP.
    """
    if not ip:
        return {"ip": None, "score": 0, "level": "LOW", "blacklisted": False}

    db = _load()
    ips = db.setdefault("ips", {})
    bl = db.setdefault("blacklist", {})

    rec = ips.get(ip, {"score": 0, "last_seen": None, "events": 0})
    rec["events"] = int(rec.get("events", 0)) + 1

    pts = _bump(severity, event, action_types or [])
    rec["score"] = int(rec.get("score", 0)) + int(pts)
    rec["last_seen"] = _now_iso()

    ips[ip] = rec

    # auto blacklist
    if rec["score"] >= BLACKLIST_THRESHOLD and ip not in bl:
        bl[ip] = {"since": _now_iso(), "reason": f"score>={BLACKLIST_THRESHOLD}"}

    db["ips"] = ips
    db["blacklist"] = bl
    _save(db)

    return {
        "ip": ip,
        "score": rec["score"],
        "level": _level(rec["score"]),
        "blacklisted": ip in bl,
        "points_added": pts,
        "threshold": BLACKLIST_THRESHOLD,
    }


def top_risky(limit=10):
    db = _load()
    ips = db.get("ips", {})
    bl = db.get("blacklist", {})

    items = []
    for ip, rec in ips.items():
        score = int(rec.get("score", 0))
        items.append({
            "ip": ip,
            "score": score,
            "level": _level(score),
            "blacklisted": ip in bl,
            "last_seen": rec.get("last_seen"),
            "events": rec.get("events", 0),
        })

    items.sort(key=lambda x: x["score"], reverse=True)
    return items[:limit]


def get_blacklist():
    db = _load()
    return db.get("blacklist", {})


def unblacklist(ip: str):
    db = _load()
    if ip in db.get("blacklist", {}):
        db["blacklist"].pop(ip, None)
        _save(db)
        return True
    return False


def reset_risk():
    _save({"ips": {}, "blacklist": {}})