import os
import time
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

# --- Model path ---
MODEL_PATH = "model.joblib"
MODEL = None

# Features order must match training
FEATURES = ["failed_logins", "requests_per_min", "bytes_out_kb", "unique_ports", "new_processes"]


def _to_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return float(default)


def event_to_vec(event: dict) -> np.ndarray:
    """Convert event dict -> 1D numpy array features."""
    return np.array([
        _to_float(event.get("failed_logins", 0)),
        _to_float(event.get("requests_per_min", 0)),
        _to_float(event.get("bytes_out_kb", 0)),
        _to_float(event.get("unique_ports", 0)),
        _to_float(event.get("new_processes", 0)),
    ], dtype=np.float64)


def _make_baseline_data(n=800, seed=42) -> np.ndarray:
    """Normal traffic baseline (synthetic)."""
    rng = np.random.default_rng(seed)
    failed_logins = rng.poisson(lam=0.3, size=n)             # mostly 0-1
    req_per_min = rng.normal(loc=25, scale=10, size=n)       # around 25
    bytes_out = rng.normal(loc=150, scale=120, size=n)       # small exfil
    ports = rng.poisson(lam=2, size=n)                       # few ports
    new_proc = rng.poisson(lam=0.2, size=n)                  # mostly 0

    X = np.vstack([failed_logins, req_per_min, bytes_out, ports, new_proc]).T
    X = np.clip(X, 0, None)  # no negatives
    return X.astype(np.float64)


def _make_attack_data(n=200, seed=1337) -> np.ndarray:
    """Attack-like synthetic samples (for validation metric only)."""
    rng = np.random.default_rng(seed)
    # mix of brute force + scan + exfil patterns
    failed_logins = rng.integers(5, 25, size=n)
    req_per_min = rng.integers(80, 250, size=n)
    bytes_out = rng.integers(1500, 12000, size=n)
    ports = rng.integers(20, 200, size=n)
    new_proc = rng.integers(0, 4, size=n)

    X = np.vstack([failed_logins, req_per_min, bytes_out, ports, new_proc]).T
    return X.astype(np.float64)


def load_model():
    global MODEL
    if MODEL is not None:
        return MODEL
    if os.path.exists(MODEL_PATH):
        MODEL = joblib.load(MODEL_PATH)
        return MODEL
    # If no model exists, train a default one
    MODEL = IsolationForest(n_estimators=250, contamination=0.06, random_state=42)
    MODEL.fit(_make_baseline_data(n=800))
    joblib.dump(MODEL, MODEL_PATH)
    return MODEL


def detect_threat(event: dict) -> dict:
    """
    Returns JSON-serializable detection result.
    """
    model = load_model()
    x = event_to_vec(event).reshape(1, -1)

    # IsolationForest: -1 means anomaly, 1 means normal
    pred = int(model.predict(x)[0])
    is_anomaly = (pred == -1)

    # score_samples: higher is more normal; we convert to anomaly_score 0..1-ish
    raw = float(model.score_samples(x)[0])
    anomaly_score = float(1.0 / (1.0 + np.exp(raw)))  # sigmoid-ish transform

    reasons = []
    if _to_float(event.get("failed_logins", 0)) >= 6:
        reasons.append("High failed_logins (possible brute force).")
    if _to_float(event.get("unique_ports", 0)) >= 30:
        reasons.append("Many unique_ports (possible port scan).")
    if _to_float(event.get("bytes_out_kb", 0)) >= 3000:
        reasons.append("High bytes_out_kb (possible data exfiltration).")
    if _to_float(event.get("requests_per_min", 0)) >= 120:
        reasons.append("High requests_per_min (possible DDoS/scan).")
    if _to_float(event.get("new_processes", 0)) >= 2:
        reasons.append("Many new_processes (suspicious process activity).")

    return {
        "is_anomaly": bool(is_anomaly),
        "anomaly_score": float(anomaly_score),
        "reasons": reasons,
        "features": {k: float(v) for k, v in zip(FEATURES, event_to_vec(event))}
    }


def retrain_model(n_baseline=800, contamination=0.06, n_estimators=250) -> dict:
    """
    Retrain IsolationForest on synthetic baseline.
    Returns metrics (JSON-serializable).
    """
    global MODEL

    t0 = time.time()
    X_train = _make_baseline_data(n=int(n_baseline))

    model = IsolationForest(
        n_estimators=int(n_estimators),
        contamination=float(contamination),
        random_state=42
    )
    model.fit(X_train)

    # simple validation metrics (not accuracy, since unsupervised)
    X_val_normal = _make_baseline_data(n=300, seed=99)
    X_val_attack = _make_attack_data(n=200, seed=123)

    pred_normal = model.predict(X_val_normal)  # -1 anomaly
    pred_attack = model.predict(X_val_attack)

    anomaly_rate_normal = float((pred_normal == -1).mean())
    anomaly_rate_attack = float((pred_attack == -1).mean())

    MODEL = model
    joblib.dump(MODEL, MODEL_PATH)

    t1 = time.time()
    return {
        "trained_on": int(n_baseline),
        "contamination": float(contamination),
        "n_estimators": int(n_estimators),
        "model_path": os.path.abspath(MODEL_PATH),
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "train_seconds": float(round(t1 - t0, 4)),
        "validation": {
            "anomaly_rate_on_normal": anomaly_rate_normal,
            "anomaly_rate_on_attack": anomaly_rate_attack
        }
    }