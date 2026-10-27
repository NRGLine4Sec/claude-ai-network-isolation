# Network isolation of the claude.ai code-execution sandbox

A measured characterization of the egress boundary of claude.ai's code-execution
sandbox, plus an open-source design pattern for reproducing an equivalent egress
containment.

---

## Summary

The code-execution environment of claude.ai (the create-and-edit-files feature)
runs inside a sandbox whose network egress is tightly controlled. This repository
documents, through direct measurement from inside that environment, how the
boundary is built, what it lets through, what it blocks, and how to reproduce it
with open-source tools.

The lens is strictly **network**: egress architecture, filtering, evasion,
containment. This is not a general survey of AI risk, but a focused study of the
network layer.

## Key findings

Every point below is established by direct measurement (see `probes/`).

- **Full TLS interception.** Egress on port 443 goes through a gateway that
  terminates and decrypts TLS, presenting a certificate issued by an internal
  authority (`Egress Gateway SDS Issuing CA`). Filtering is applied to the
  hostname after decryption.
- **Minimal port allowlist.** Confirmed across 1000+ ports: only **TCP 80,
  TCP 443, and UDP 53** egress. Everything else is silently dropped (timeout).
- **Intercepted DNS.** Port 53 is transparently redirected to an internal
  resolver (reserved IPs that host no resolver still return answers).
- **Confined ICMP.** Not routed to the internet; only internal hops respond.
- **Neutralized tunnels.** GRE, VXLAN, GENEVE, WireGuard, L2TP, SSTP, STUN, TURN
  and WebRTC are all blocked or inoperative. CONNECT (HTTP/1.1 and HTTP/2) is
  refused even to an allowed host. Only WebSocket passes, because it starts as
  HTTP over 443.
- **Declared egress identity.** Traffic exits from Google Cloud IPs published by
  Anthropic; the web-fetch User-Agent self-identifies (`Claude-User/1.0`). No
  residential proxy detected.
- **Likely implementation.** The evidence (CAs named `swp-*`, Envoy's `SDS`,
  egress via GCP) points to Google Cloud Secure Web Proxy. This is an inference,
  not a confirmation by Anthropic.

## Repository contents

### `docs/`

- **`01-network-characterization.md`**: the full study, covering egress architecture,
  port list, DNS, ICMP, tunnels, WebSocket / WebRTC / CONNECT, egress identity,
  instrument validation, epistemic limits.
- **`02-oss-containment-toolkit.md`**: the open-source toolkit for reproducing
  this containment (Squid, Envoy, mitmproxy, SSLproxy, PolarProxy, Smokescreen,
  Suricata, nftables, CoreDNS, gVisor, Firecracker, Cilium), with a lab build
  pattern.
- **`03-public-vulnerabilities.md`**: a sourced review of bypasses already found
  and fixed by other researchers (Guan, Rehberger, Ona, Habler et al.), with the
  detailed mechanism of each finding.

### `probes/`

Reproducible probe scripts, one per measured aspect. Each is a
**benign-target characterization**: it measures a boundary without crossing it.
See `probes/README.md`.

## Reproducing the measurements

```bash
git clone https://github.com/NRGLine4Sec/claude-ai-network-isolation
cd claude-ai-network-isolation
pip install -r probes/requirements.txt
bash probes/run_all.sh
```

The probes are meant to be run from inside an environment whose egress boundary
you want to characterize (claude.ai's sandbox, but also your own lab stack, for
comparison). Some probes (ICMP, raw protocols) require the `CAP_NET_RAW`
capability.

## Scope and disclaimers

This work is **defensive characterization**. There is no active operational
exploit here: the probes measure boundaries, they do not cross them. The
third-party vulnerabilities cited in `docs/03` have all been fixed. See
`SECURITY.md` for the full scope.

Two accuracy caveats, repeated throughout the documents:

1. The attribution to Google Cloud Secure Web Proxy is a strong-inference
   deduction, not confirmed by Anthropic.
2. The measurements describe one environment, at a given date, observed from the
   inside. They may not generalize and may become outdated.

## Methodology note

This characterization was carried out from inside the sandbox, with interactive
shell access allowing `curl`, Python, and raw sockets. That is a rare vantage
point: external researchers usually have only the chat interface, which is why
this particular network layer is so sparsely documented publicly. The
observations are dated and reproducible so that others can confirm or refute them.

## Licenses

- **Code** (`probes/`): MIT, see `LICENSE`.
- **Documentation** (`docs/`, this README): CC-BY-4.0, see `LICENSE-docs`.

## Acknowledgments

The third-party work reviewed in `docs/03` is due to Aonan Guan, Johann Rehberger
(Embrace The Red), the Ona team, and Idan Habler, Sagiv Antebi and Vineeth Sai
Narajala. The "lethal trifecta" framing is Simon Willison's. Precise sources are
listed in each document.
