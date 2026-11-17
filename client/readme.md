# Client bandwidth and robustness metrics

This document describes the measurements implemented in `client.py`. They
measure the client-side transmission of a payload through the DNS lab tunnel;
they are not measurements of raw network capacity.

## Bandwidth

For each transmission, the client calculates effective payload bandwidth as:

```text
bandwidth (B/s) = UTF-8 payload size in bytes / elapsed transmission time in seconds
```

The timer starts immediately before the sequential DNS-query loop and stops
after the loop, including the configured 50 ms pause after each chunk. It
therefore includes query/response time and pauses, but excludes encoding and
chunk preparation. Only original payload bytes are counted: Base32 expansion,
DNS headers, query names, responses, and other protocol overhead are not
included. A zero-duration transmission reports `0 B/s`.

The bandwidth measurement tests 64-, 256-, and 1,024-byte ASCII payloads. Each
size is transmitted three times by default. The output reports the arithmetic
mean and sample standard deviation of the per-transmission bandwidths. A
single run has a standard deviation of zero.

## Robustness

Robustness is the fraction of chunks acknowledged during a transmission:

```text
robustness = acknowledged chunks / total chunks
```

A chunk counts as acknowledged only when its DNS response has a successful
response code, contains an answer, and the first answer record is `1.0.0.1`.
Other responses and request exceptions count as unacknowledged. If there are
no chunks, the metric is zero.

The robustness measurement applies artificial packet loss to the client's
`eth0` interface with `tc netem`, testing 0%, 5%, 10%, and 20% configured loss.
At each loss setting it sends the same fixed payload three times by default,
then reports the arithmetic mean of the per-run robustness ratios as the
delivery rate. The configured network loss percentage is an input condition;
the reported delivery rate is the observed acknowledged-chunk fraction and
need not equal 100% minus that percentage.

Applying and removing the `tc` queue discipline requires the appropriate
Linux networking tools and privileges (including `NET_ADMIN`). The script
attempts to remove the queue discipline before each setting and after the
measurement.

## Scope and interpretation

These are simple client-side lab metrics, not end-to-end guarantees. They
reflect the configured resolver, query timeout, traffic conditions, payload,
and number of runs. Bandwidth and robustness are measured separately; the
bandwidth runs do not inject the loss levels used by the robustness runs.
Use packet-loss experiments only on an isolated, authorized lab interface.
