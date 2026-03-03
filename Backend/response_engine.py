import json
import os
from datetime import datetime

ACTIONS_LOG = "actions_log.jsonl"

def _log_action(record: dict):
    with open(ACTIONS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def execute_actions(plan: dict, safe_mode: bool = True) -> dict:
    """
    safe_mode=True: simulate actions only (recommended for safety).
    """
    executed = []
    for a in plan.get("actions", []):
        action_type = a.get("type")

        result = {
            "type": action_type,
            "status": "SIMULATED" if safe_mode else "PENDING_REAL",
            "details": a
        }

        executed.append(result)

        _log_action({
            "time": datetime.utcnow().isoformat() + "Z",
            "severity": plan.get("severity"),
            "action": result
        })

    return {"executed": executed, "safe_mode": safe_mode, "log_file": os.path.abspath(ACTIONS_LOG)}