"""
Demo: simulates a stream of UPI-style transactions containing:
  - normal background traffic
  - a velocity burst attack (one account fires many rapid txns)
  - a circular money flow (A -> B -> C -> D -> A)
  - a mule network (fan-in from many "victim" accounts -> pass-through -> fan-out)

Run: python3 demo.py
"""

import itertools
import random
from fraud_detector import Transaction, FraudDetectionEngine

random.seed(42)


def make_stream():
    txns = []
    t = 1_000_000.0
    txn_id = itertools.count(1)

    def add(sender, receiver, amount, dt):
        nonlocal t
        t += dt
        txns.append(Transaction(f"T{next(txn_id):04d}", sender, receiver, amount, t))

    # --- 1. normal background traffic among regular users ---
    users = [f"user{i}" for i in range(1, 12)]
    for _ in range(25):
        s, r = random.sample(users, 2)
        add(s, r, random.uniform(200, 3000), random.uniform(5, 30))

    # --- 2. velocity burst: fraud_acct1 fires rapid-fire small transactions ---
    for _ in range(8):
        add("fraud_acct1", random.choice(users), random.uniform(9000, 15000), 3.0)

    # --- 3. sudden spike: normally-quiet user9 sends a huge one-off amount ---
    add("user9", "user2", 500, 20)   # establish a normal baseline first
    add("user9", "user2", 400, 20)
    add("user9", "shady_acct", 80000, 15)  # 100x+ spike vs its own average

    # --- 4. circular flow: A -> B -> C -> D -> A (layering) ---
    add("ring_A", "ring_B", 50000, 10)
    add("ring_B", "ring_C", 49000, 10)
    add("ring_C", "ring_D", 48500, 10)
    add("ring_D", "ring_A", 48000, 10)

    # --- 5. mule network: several "victim" accounts fan money into a mule hub,
    #        which almost immediately forwards it out to 2 "collector" accounts ---
    victims = ["victim1", "victim2", "victim3", "victim4"]
    for v in victims:
        add(v, "mule_hub", random.uniform(20000, 40000), 5)
    add("mule_hub", "collector1", 60000, 8)
    add("mule_hub", "collector2", 55000, 8)

    # a bit more normal traffic tail
    for _ in range(10):
        s, r = random.sample(users, 2)
        add(s, r, random.uniform(200, 3000), random.uniform(5, 30))

    return txns


def main():
    engine = FraudDetectionEngine(
        velocity_window_seconds=60.0,
        max_txns_in_window=5,
        max_amount_in_window=200_000.0,
        circular_window_seconds=600.0,
        mule_cluster_min_size=4,
        pass_through_ratio_threshold=0.85,
        pass_through_seconds=120.0,
    )

    stream = make_stream()
    print(f"Processing {len(stream)} transactions in real time...\n")

    for txn in stream:
        alerts = engine.process(txn)
        for a in alerts:
            print(f"{txn}  =>  {a}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(engine.summary())


if __name__ == "__main__":
    main()
