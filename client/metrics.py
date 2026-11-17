#!/usr/bin/env python3
"""
DNS Tunnel – Detectability Metric
===================================
Implements the DETECTABILITY metric from the covert-channel literature.

Detectors typically look at:
  1. Shannon entropy of subdomain labels        (normal ≈ 2.5, tunnel ≈ 4.7)
  2. Average label length                       (normal ≈ 5, tunnel ≈ 30)
  3. Subdomain-to-domain ratio per unique FQDN  (high for tunnels)
  4. Query rate per registered domain            (burst of repeated root domain)

Run standalone:
    python metrics.py

Or import:
    from metrics import analyze_labels, compare_traffic
"""

import base64
import math
import statistics
from collections import Counter
from dataclasses import dataclass
from typing import List


# ── Shannon entropy ───────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """
    H(X) = -Σ p(x) log₂ p(x)

    For random / high-entropy strings (Base32 output) this approaches
    log₂(32) ≈ 5.0 bits/char.
    For short English words the value is much lower.
    """
    if not text:
        return 0.0
    c = Counter(text.lower())
    n = len(text)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in c.values())


# ── Label datasets ────────────────────────────────────────────

def _make_tunnel_labels(messages: List[str]) -> List[str]:
    labels = []
    for msg in messages:
        encoded = base64.b32encode(msg.encode()).decode().rstrip("=").lower()
        # Split into 30-char chunks (as the client does)
        labels += [encoded[i:i+30] for i in range(0, len(encoded), 30)]
    return labels


NORMAL_LABELS = [
    "www", "mail", "api", "auth", "static", "cdn", "login",
    "app", "dev", "staging", "docs", "blog", "shop", "support",
    "smtp", "pop3", "imap", "ns1", "ns2", "vpn",
    "gateway", "intranet", "ldap", "sso", "admin",
]

TUNNEL_MESSAGES = [
    "username=admin&password=Pa$$w0rd123",
    "hostname=workstation-7&os=Windows11",
    "2024-01-15T14:32:01 – exfiltration started",
    "file=/etc/shadow size=2048",
]

TUNNEL_LABELS = _make_tunnel_labels(TUNNEL_MESSAGES)


# ── Analysis ──────────────────────────────────────────────────

@dataclass
class LabelStats:
    entropy_mean: float
    entropy_stdev: float
    length_mean: float
    length_stdev: float
    unique_chars_mean: float


def label_stats(labels: List[str]) -> LabelStats:
    entropies = [shannon_entropy(l) for l in labels]
    lengths   = [len(l) for l in labels]
    uniq      = [len(set(l)) for l in labels]
    return LabelStats(
        entropy_mean  = statistics.mean(entropies),
        entropy_stdev = statistics.stdev(entropies) if len(entropies) > 1 else 0.0,
        length_mean   = statistics.mean(lengths),
        length_stdev  = statistics.stdev(lengths) if len(lengths) > 1 else 0.0,
        unique_chars_mean = statistics.mean(uniq),
    )


def analyze_labels(labels: List[str], title: str = ""):
    s = label_stats(labels)
    print(f"\n  {title}")
    print(f"  {'Label':<35} {'Entropy':>8}  {'Len':>4}")
    print("  " + "─" * 52)
    for lbl in labels[:10]:  # show first 10
        e = shannon_entropy(lbl)
        print(f"  {lbl:<35} {e:8.3f}  {len(lbl):4d}")
    if len(labels) > 10:
        print(f"  … ({len(labels) - 10} more labels)")
    print(f"\n  → entropy:  {s.entropy_mean:.3f} ± {s.entropy_stdev:.3f} bits/char")
    print(f"  → length:   {s.length_mean:.1f} ± {s.length_stdev:.1f} chars")
    print(f"  → unique chars (avg): {s.unique_chars_mean:.1f}")
    return s


def compare_traffic():
    print("\n" + "=" * 55)
    print("METRIC 3 – DETECTABILITY")
    print("=" * 55)

    n_stats = analyze_labels(NORMAL_LABELS, "NORMAL DNS labels")
    t_stats = analyze_labels(TUNNEL_LABELS, "TUNNEL DNS labels  (Base32-encoded)")

    # Entropy ratio as a simple classifier score
    ratio = t_stats.entropy_mean / n_stats.entropy_mean if n_stats.entropy_mean else 0
    len_ratio = t_stats.length_mean / n_stats.length_mean if n_stats.length_mean else 0

    print("\n── Detection thresholds ───────────────────────────")
    print(f"  Entropy ratio (tunnel / normal): {ratio:.2f}×")
    print(f"  Length  ratio (tunnel / normal): {len_ratio:.2f}×")
    print(f"\n  A simple IDS rule:")
    threshold = (n_stats.entropy_mean + t_stats.entropy_mean) / 2
    print(f"    IF entropy(label) > {threshold:.2f}  →  SUSPICIOUS")
    print(f"    IF len(label)     > 20            →  SUSPICIOUS")
    print(f"\n  A query-rate rule:")
    print(f"    IF same registered domain > 50 q/s  →  ANOMALY")

    return {"normal": n_stats, "tunnel": t_stats, "entropy_threshold": threshold}


if __name__ == "__main__":
    compare_traffic()
