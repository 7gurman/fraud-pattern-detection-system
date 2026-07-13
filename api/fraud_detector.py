"""
Real-time Fraud Pattern Detector for UPI/Fintech Transaction Streams
======================================================================

Rule-based, fully explainable fraud detection — no ML black box.

Core DSA components:
  1. Sliding Window        -> per-account velocity checks (burst detection)
  2. Union-Find (DSU)      -> clusters accounts into suspicious networks (mule rings)
  3. Directed Graph + DFS  -> detects circular money flows (layering / round-tripping)

Every alert carries a human-readable "reason" so it can be handed straight
to a fraud analyst or a compliance report — nothing is a black box.
"""

from __future__ import annotations
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional
import itertools
import time


# ---------------------------------------------------------------------------
# 1. Transaction model
# ---------------------------------------------------------------------------

@dataclass
class Transaction:
    txn_id: str
    sender: str
    receiver: str
    amount: float
    timestamp: float          # epoch seconds (monotonically increasing in the stream)

    def __repr__(self):
        return f"<Txn {self.txn_id} {self.sender}->{self.receiver} ₹{self.amount:.0f} @{self.timestamp:.1f}>"


@dataclass
class Alert:
    kind: str                 # VELOCITY | CIRCULAR_FLOW | MULE_CLUSTER
    severity: str             # LOW | MEDIUM | HIGH
    accounts: list
    reason: str
    txn_ids: list = field(default_factory=list)

    def __repr__(self):
        return f"[{self.severity:6}] {self.kind:14} accounts={self.accounts} :: {self.reason}"


# ---------------------------------------------------------------------------
# 2. Sliding Window Velocity Tracker
# ---------------------------------------------------------------------------
# For every account we keep a deque of (timestamp, amount, txn_id) for
# transactions the account SENT. As new transactions arrive we evict entries
# that have fallen outside the window. This gives O(1) amortized per-event
# updates instead of re-scanning history.

class SlidingWindowVelocityTracker:
    def __init__(self, window_seconds: float = 60.0,
                 max_txns_in_window: int = 5,
                 max_amount_in_window: float = 200_000.0,
                 spike_multiplier: float = 5.0,
                 min_spike_amount: float = 5000.0):
        self.window_seconds = window_seconds
        self.max_txns_in_window = max_txns_in_window
        self.max_amount_in_window = max_amount_in_window
        self.spike_multiplier = spike_multiplier
        # a jump from ₹50 to ₹500 is meaningless; only flag spikes with real rupee value
        self.min_spike_amount = min_spike_amount

        # account -> deque[(timestamp, amount, txn_id)]
        self._windows: dict[str, deque] = defaultdict(deque)
        # account -> running average amount (simple exponential average), for spike detection
        self._avg_amount: dict[str, float] = {}

    def _evict_old(self, account: str, now: float):
        dq = self._windows[account]
        while dq and now - dq[0][0] > self.window_seconds:
            dq.popleft()

    def check(self, txn: Transaction) -> list[Alert]:
        alerts = []
        acct = txn.sender
        self._evict_old(acct, txn.timestamp)
        dq = self._windows[acct]

        # --- spike check against historical average (before adding current txn) ---
        prev_avg = self._avg_amount.get(acct)
        if (prev_avg is not None and prev_avg > 0
                and txn.amount > prev_avg * self.spike_multiplier
                and txn.amount >= self.min_spike_amount):
            alerts.append(Alert(
                kind="VELOCITY",
                severity="MEDIUM",
                accounts=[acct],
                reason=(f"Transaction amount ₹{txn.amount:.0f} is {txn.amount/prev_avg:.1f}x "
                        f"the account's rolling average (₹{prev_avg:.0f}) — abrupt spike"),
                txn_ids=[txn.txn_id],
            ))

        # update rolling average (simple EMA, alpha=0.3)
        self._avg_amount[acct] = (0.3 * txn.amount + 0.7 * prev_avg) if prev_avg is not None else txn.amount

        # add current txn to window
        dq.append((txn.timestamp, txn.amount, txn.txn_id))

        # --- burst / count check ---
        if len(dq) > self.max_txns_in_window:
            alerts.append(Alert(
                kind="VELOCITY",
                severity="HIGH",
                accounts=[acct],
                reason=(f"{len(dq)} transactions from {acct} within {self.window_seconds:.0f}s "
                        f"(threshold {self.max_txns_in_window}) — burst pattern"),
                txn_ids=[t[2] for t in dq],
            ))

        # --- total amount check ---
        total = sum(t[1] for t in dq)
        if total > self.max_amount_in_window:
            alerts.append(Alert(
                kind="VELOCITY",
                severity="HIGH",
                accounts=[acct],
                reason=(f"₹{total:.0f} moved out of {acct} within {self.window_seconds:.0f}s "
                        f"(threshold ₹{self.max_amount_in_window:.0f})"),
                txn_ids=[t[2] for t in dq],
            ))

        return alerts


# ---------------------------------------------------------------------------
# 3. Union-Find (Disjoint Set Union) for mule-network clustering
# ---------------------------------------------------------------------------
# Every time two accounts transact with each other and at least one side of
# the transaction looks "suspicious enough" (fast pass-through, flagged by
# velocity, or part of a flagged circular flow) we union them. After a batch
# of processing, connected components with size >= threshold are reported
# as candidate mule networks.

class UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}
        # bookkeeping for explainability
        self.edge_reasons: dict[str, list[str]] = defaultdict(list)

    def _make(self, x: str):
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0

    def find(self, x: str) -> str:
        self._make(x)
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])  # path compression
        return self.parent[x]

    def union(self, a: str, b: str, reason: str = ""):
        self._make(a)
        self._make(b)
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            if reason:
                self.edge_reasons[ra].append(reason)
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1
        if reason:
            self.edge_reasons[ra].append(reason)

    def clusters(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = defaultdict(list)
        for acct in self.parent:
            groups[self.find(acct)].append(acct)
        return groups


# ---------------------------------------------------------------------------
# 4. Circular Flow Detector (directed graph + cycle detection)
# ---------------------------------------------------------------------------
# Money laundering "layering" often routes funds through a loop of accounts
# so it eventually returns to the origin (A->B->C->A), obscuring the trail.
# We maintain a directed multigraph of recent transactions (within a wider
# window than velocity, e.g. 10 minutes) and run cycle detection whenever a
# new edge is added, restricted to a bounded search depth for real-time use.

class CircularFlowDetector:
    def __init__(self, window_seconds: float = 600.0, max_cycle_len: int = 6,
                 min_amount: float = 5000.0):
        self.window_seconds = window_seconds
        self.max_cycle_len = max_cycle_len
        # Ignore small routine payments (chai, splitting a bill, etc.) — layering
        # detection only matters above a materiality threshold, same as real AML systems.
        self.min_amount = min_amount
        # adjacency: sender -> list[(receiver, timestamp, txn_id, amount)]
        self.edges: dict[str, list[tuple]] = defaultdict(list)

    def _evict_old(self, now: float):
        for acct, lst in self.edges.items():
            while lst and now - lst[0][1] > self.window_seconds:
                lst.pop(0)

    def add_and_check(self, txn: Transaction) -> Optional[Alert]:
        if txn.amount < self.min_amount:
            return None
        self._evict_old(txn.timestamp)
        self.edges[txn.sender].append((txn.receiver, txn.timestamp, txn.txn_id, txn.amount))

        # DFS from receiver, looking for a path back to sender within max_cycle_len
        path = self._find_cycle(start=txn.receiver, target=txn.sender, depth=self.max_cycle_len - 1)
        if path:
            full_cycle = [txn.sender] + path
            return Alert(
                kind="CIRCULAR_FLOW",
                severity="HIGH",
                accounts=full_cycle,
                reason=(f"Circular money flow detected: {' -> '.join(full_cycle)} -> {full_cycle[0]} "
                        f"within {self.window_seconds:.0f}s — classic layering pattern"),
                txn_ids=[txn.txn_id],
            )
        return None

    def _find_cycle(self, start: str, target: str, depth: int) -> Optional[list[str]]:
        # bounded DFS; returns path (excluding target) if a route start -> ... -> target exists
        visited = set()

        def dfs(node: str, remaining: int, path: list[str]) -> Optional[list[str]]:
            if node == target:
                return path
            if remaining == 0 or node in visited:
                return None
            visited.add(node)
            for (nxt, _ts, _tid, _amt) in self.edges.get(node, []):
                result = dfs(nxt, remaining - 1, path + [nxt])
                if result:
                    return result
            return None

        return dfs(start, depth, [start])


# ---------------------------------------------------------------------------
# 5. Fraud Detection Engine — ties everything together
# ---------------------------------------------------------------------------

class FraudDetectionEngine:
    def __init__(self,
                 velocity_window_seconds: float = 60.0,
                 max_txns_in_window: int = 5,
                 max_amount_in_window: float = 200_000.0,
                 circular_window_seconds: float = 600.0,
                 mule_cluster_min_size: int = 4,
                 pass_through_ratio_threshold: float = 0.9,
                 pass_through_seconds: float = 120.0,
                 mule_min_amount: float = 5000.0):
        self.velocity = SlidingWindowVelocityTracker(
            window_seconds=velocity_window_seconds,
            max_txns_in_window=max_txns_in_window,
            max_amount_in_window=max_amount_in_window,
            min_spike_amount=mule_min_amount,
        )
        self.circular = CircularFlowDetector(window_seconds=circular_window_seconds,
                                              min_amount=mule_min_amount)
        self.uf = UnionFind()

        self.mule_cluster_min_size = mule_cluster_min_size
        self.pass_through_ratio_threshold = pass_through_ratio_threshold
        self.pass_through_seconds = pass_through_seconds
        self.mule_min_amount = mule_min_amount

        # for pass-through / fan-in-fan-out mule detection:
        # account -> deque[(timestamp, amount, direction)]  direction: 'in'/'out'
        self._flow: dict[str, deque] = defaultdict(deque)

        self.all_alerts: list[Alert] = []

    # -- pass-through mule heuristic: money arrives and leaves almost fully, fast --
    def _update_flow_and_check_mule(self, txn: Transaction) -> list[Alert]:
        alerts = []
        if txn.amount < self.mule_min_amount:
            return alerts
        now = txn.timestamp

        for acct, direction, amt in ((txn.sender, "out", txn.amount), (txn.receiver, "in", txn.amount)):
            dq = self._flow[acct]
            dq.append((now, amt, direction))
            while dq and now - dq[0][0] > self.pass_through_seconds:
                dq.popleft()

        # Check BOTH parties of this transaction: whichever one is behaving like a
        # pass-through mule (received a pile of money and is forwarding almost all
        # of it back out, fast) gets flagged — regardless of whether it's the
        # sender or receiver of the specific transaction that completes the pattern.
        for acct, counterparty in ((txn.receiver, txn.sender), (txn.sender, txn.receiver)):
            dq = self._flow[acct]
            total_in = sum(a for (_, a, d) in dq if d == "in")
            total_out = sum(a for (_, a, d) in dq if d == "out")
            if total_in > 0 and total_out > 0 and (total_out / total_in) >= self.pass_through_ratio_threshold:
                reason = (f"{acct} forwarded ₹{total_out:.0f} of ₹{total_in:.0f} received "
                          f"(ratio {total_out/total_in:.0%}) within {self.pass_through_seconds:.0f}s — pass-through / mule behavior")
                self.uf.union(txn.sender, txn.receiver, reason=reason)
                alerts.append(Alert(
                    kind="MULE_CLUSTER",
                    severity="MEDIUM",
                    accounts=[acct, counterparty],
                    reason=reason,
                    txn_ids=[txn.txn_id],
                ))
        return alerts

    def process(self, txn: Transaction) -> list[Alert]:
        alerts: list[Alert] = []

        # 1. velocity / burst checks (sliding window)
        v_alerts = self.velocity.check(txn)
        alerts.extend(v_alerts)

        # 2. circular flow detection (graph + DFS)
        c_alert = self.circular.add_and_check(txn)
        if c_alert:
            alerts.append(c_alert)
            # union all accounts in the cycle — they're clearly one network
            for a, b in zip(c_alert.accounts, c_alert.accounts[1:] + c_alert.accounts[:1]):
                self.uf.union(a, b, reason=f"co-members of circular flow {c_alert.accounts}")

        # 3. pass-through / mule clustering
        m_alerts = self._update_flow_and_check_mule(txn)
        alerts.extend(m_alerts)

        # 4. if this txn's sender/receiver already flagged by velocity, cluster them too
        #    (a flagged account transacting with a clean one still taints the edge)
        if v_alerts:
            self.uf.union(txn.sender, txn.receiver,
                           reason=f"{txn.sender} flagged by velocity check, transacted with {txn.receiver}")

        self.all_alerts.extend(alerts)
        return alerts

    def suspicious_clusters(self) -> list[dict]:
        """Return connected components at/above the mule cluster size threshold."""
        out = []
        for root, members in self.uf.clusters().items():
            if len(members) >= self.mule_cluster_min_size:
                out.append({
                    "cluster_id": root,
                    "accounts": sorted(members),
                    "size": len(members),
                    "reasons": self.uf.edge_reasons.get(root, []),
                })
        return out

    def summary(self) -> str:
        lines = [f"Total alerts raised: {len(self.all_alerts)}"]
        by_kind = defaultdict(int)
        for a in self.all_alerts:
            by_kind[a.kind] += 1
        for k, v in by_kind.items():
            lines.append(f"  {k}: {v}")
        clusters = self.suspicious_clusters()
        lines.append(f"Suspicious clusters (size >= {self.mule_cluster_min_size}): {len(clusters)}")
        for c in clusters:
            lines.append(f"  cluster[{c['cluster_id']}] size={c['size']} accounts={c['accounts']}")
        return "\n".join(lines)
