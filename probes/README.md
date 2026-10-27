# Network characterization probes

Each script measures **one** aspect of the egress boundary. They are
**benign-target characterizations**: they measure a boundary without crossing it.
The targets of active tests are public test hosts (`scanme.nmap.org`, public DNS
resolvers, HTTP echo services) or reserved IPs (RFC 5737 / RFC 1918). No script
tries to reach a blocked host, exfiltrate data, or escape the sandbox.

## What the scripts measure

| Script | Measures |
|---|---|
| `01_egress_ports.py` | TCP port allowlist (scan) and UDP (53/123/443) |
| `02_hostname_and_tls.sh` | hostname block (`x-block-reason`) and TLS interception (certificate issuer) |
| `03_dns_interception.py` | transparent DNS interception and recursion to the internet |
| `04_icmp_topology.py` | ICMP reach and internal topology (TTL probe), requires `CAP_NET_RAW` |
| `05_tunnels.py` | UDP tunnels on 443, port-less IP protocols (GRE, ESP), multicast, `CAP_NET_RAW` |
| `06_ws_stun_turn_webrtc.py` | WebSocket, STUN, TURN, WebRTC ICE candidate gathering |
| `07_http_connect.py` | CONNECT tunnel over HTTP/1.1 and HTTP/2 |
| `08_domain_fronting.py` | proxy routing basis (SNI vs Host header) |
| `09_egress_identity.sh` | egress IP, comparison to Anthropic's published IP list and to Google Cloud ranges |
| `10_instrument_validation.py` | `socket` library validation (positive controls) |

## Requirements

```bash
pip install -r requirements.txt
```

- Python 3.9+.
- `curl` and `openssl` for the shell scripts.
- Scripts `04` and `05` use raw sockets and require the `CAP_NET_RAW`
  capability. Without it, they exit cleanly and report so.
- `06` requires `aiortc` (in `requirements.txt`) for the WebRTC part.
- `07` requires `h2`. The QUIC probe in `01`/`05` may use `aioquic` if present,
  otherwise it falls back to a low-level probe.

## Running

One script at a time:

```bash
python3 probes/01_egress_ports.py
bash    probes/02_hostname_and_tls.sh
```

Or run them all, with timestamped output in `probes/out/`:

```bash
bash probes/run_all.sh
```

## Interpretation

- **timeout** on a port or protocol = silent drop at egress (blocked).
- **fast Connection refused (RST)** = egress lets it through, the target simply
  does not answer on that port (so the port is allowed).
- **certificate issued by an internal CA** = TLS interception (MITM by the
  gateway).
- **DNS reply from a reserved IP** = transparent DNS interception.

These probes serve both to characterize the claude.ai sandbox and to **validate
your own lab stack**: if your setup returns the same timeouts, refusals, and
silences, it reaches the same level of containment.
