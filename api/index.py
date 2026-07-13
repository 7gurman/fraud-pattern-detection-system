"""
Flask API wrapping the fraud detection engine, deployable as a single
Vercel Python serverless function.

Endpoints:
  GET  /              -> health check + usage info
  GET  /api/demo       -> runs the built-in synthetic transaction stream
                          (same one from demo.py) and returns every alert
  POST /api/detect     -> submit your own transactions, get alerts back

POST /api/detect body:
{
  "transactions": [
    {"txn_id": "T1", "sender": "a", "receiver": "b", "amount": 5000, "timestamp": 1000},
    ...
  ],
  "config": {                      // optional, all fields optional
    "velocity_window_seconds": 60,
    "max_txns_in_window": 5,
    "max_amount_in_window": 200000,
    "circular_window_seconds": 600,
    "mule_cluster_min_size": 4,
    "pass_through_ratio_threshold": 0.85,
    "pass_through_seconds": 120,
    "mule_min_amount": 5000
  }
}
"""

import itertools
import random

from flask import Flask, request, jsonify
from api.fraud_detector import Transaction, FraudDetectionEngine

app = Flask(__name__)


def _alert_to_dict(a):
    return {
        "kind": a.kind,
        "severity": a.severity,
        "accounts": a.accounts,
        "reason": a.reason,
        "txn_ids": a.txn_ids,
    }


def _run_engine(txns, config):
    engine = FraudDetectionEngine(**config)
    alerts = []
    for t in txns:
        alerts.extend(engine.process(t))
    return {
        "alerts": [_alert_to_dict(a) for a in alerts],
        "clusters": engine.suspicious_clusters(),
        "summary": engine.summary(),
        "transactions_processed": len(txns),
    }


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "ok",
        "service": "Real-time Fraud Pattern Detector",
        "endpoints": {
            "GET /api/demo": "runs a built-in synthetic transaction stream and returns alerts",
            "POST /api/detect": "submit your own transactions (see module docstring for schema)",
        },
    })


@app.route("/api/demo", methods=["GET"])
def demo():
    random.seed(42)
    txns = []
    t = 1_000_000.0
    counter = itertools.count(1)

    def add(sender, receiver, amount, dt):
        nonlocal t
        t += dt
        txns.append(Transaction(f"T{next(counter):04d}", sender, receiver, amount, t))

    users = [f"user{i}" for i in range(1, 12)]
    for _ in range(25):
        s, r = random.sample(users, 2)
        add(s, r, random.uniform(200, 3000), random.uniform(5, 30))

    for _ in range(8):
        add("fraud_acct1", random.choice(users), random.uniform(9000, 15000), 3.0)

    add("user9", "user2", 500, 20)
    add("user9", "user2", 400, 20)
    add("user9", "shady_acct", 80000, 15)

    add("ring_A", "ring_B", 50000, 10)
    add("ring_B", "ring_C", 49000, 10)
    add("ring_C", "ring_D", 48500, 10)
    add("ring_D", "ring_A", 48000, 10)

    victims = ["victim1", "victim2", "victim3", "victim4"]
    for v in victims:
        add(v, "mule_hub", random.uniform(20000, 40000), 5)
    add("mule_hub", "collector1", 60000, 8)
    add("mule_hub", "collector2", 55000, 8)

    for _ in range(10):
        s, r = random.sample(users, 2)
        add(s, r, random.uniform(200, 3000), random.uniform(5, 30))

    result = _run_engine(txns, {})
    return jsonify(result)


@app.route("/api/detect", methods=["POST"])
def detect():
    body = request.get_json(force=True, silent=True) or {}
    raw_txns = body.get("transactions", [])
    config = body.get("config", {}) or {}

    if not raw_txns:
        return jsonify({"error": "No transactions provided. See '/' for expected schema."}), 400

    try:
        txns = [
            Transaction(
                txn_id=str(t["txn_id"]),
                sender=str(t["sender"]),
                receiver=str(t["receiver"]),
                amount=float(t["amount"]),
                timestamp=float(t["timestamp"]),
            )
            for t in raw_txns
        ]
    except (KeyError, TypeError, ValueError) as e:
        return jsonify({"error": f"Malformed transaction: {e}"}), 400

    result = _run_engine(txns, config)
    return jsonify(result)


# Vercel's Python runtime looks for a WSGI-compatible `app` object in this file.
if __name__ == "__main__":
    app.run(debug=True)
