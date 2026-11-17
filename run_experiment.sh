#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Run the full DNS Tunnel experiment and collect measurements
#  for slides 9–11.
# ─────────────────────────────────────────────────────────────

set -e
echo "════════════════════════════════════════════════"
echo "  DNS TUNNEL LAB – Full Experiment"
echo "════════════════════════════════════════════════"

# 1. Build & start the lab
echo -e "\n[1/4] Starting containers…"
docker compose up -d --build
sleep 5   # let Unbound and the authoritative server settle

# Verify DNS is working
echo -e "\n[2/4] Sanity check – dig tunnel.lab from resolver…"
docker exec dns_client python - <<'EOF'
import dns.resolver, dns.message, dns.query
try:
    req = dns.message.make_query("test.0.s1.tunnel.lab", "A")
    resp = dns.query.udp(req, "10.10.0.2", timeout=3)
    print(f"  Resolver → authoritative: rcode={resp.rcode()} ({'OK' if resp.rcode()==0 else 'FAIL'})")
except Exception as e:
    print(f"  FAIL: {e}")
EOF

# 3. Run the demo + all metrics
echo -e "\n[3/4] Running tunnel demo and collecting metrics…"
docker exec dns_client python /app/client.py --demo 2>&1 | tee /tmp/client_output.txt

# 4. Run detectability (can run on host, no network needed)
echo -e "\n[4/4] Detectability analysis…"
docker exec dns_client python /app/metrics.py 2>&1 | tee /tmp/metrics_output.txt

echo -e "\n════════════════════════════════════════════════"
echo "  Done. Results saved to /tmp/client_output.txt"
echo "  and /tmp/metrics_output.txt"
echo "════════════════════════════════════════════════"

# Optional: tail server logs
echo -e "\n[server log tail]"
docker exec dns_authoritative cat /logs/server_events.jsonl 2>/dev/null | tail -20 || true
