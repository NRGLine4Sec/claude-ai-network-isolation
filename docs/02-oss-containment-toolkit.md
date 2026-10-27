# Open-source toolkit for reproducing a sandbox-grade network containment

*Companion to the network characterization document (`01-network-characterization.md`).
Goal: build, in a lab, a network isolation of the same caliber, using only
open-source tools (so, without Google Cloud's managed Secure Web Proxy).*

---

## 1. What needs to be reproduced

The sandbox analysis revealed not a single product but a stack of layers. No
single OSS tool covers all of them. The functional target:

| Layer             | Observed behavior                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------------- |
| Compute isolation | isolated environment, internal addressing in `192.0.2.0/24`                                               |
| L3/L4 firewall    | default-deny, allowlist TCP 80/443 and UDP 53, silent drop                                                |
| DNS               | intercepted via transparent DNAT to a controlled resolver                                                 |
| TLS proxy         | full TLS termination (internal CA), hostname filtering, refusal of CONNECT, tunnels, and non-HTTP methods |
| UDP / ICMP        | UDP closed except 53, ICMP confined to the internal network                                               |
| Egress identity   | published User-Agent and IP ranges                                                                        |

---

## 2. Essential correction: who actually decrypts TLS?

A point to clear up first, because it is a common confusion. **Suricata does not
decrypt TLS.** It reads the SNI (cleartext in the handshake), computes JA3
fingerprints, and can block on `tls.sni` in IPS mode, but it performs no TLS
interception. To inspect encrypted content, you need a separate TLS terminator
that decrypts and then hands it the plaintext.

The open-source TLS terminators available:

- **Squid** with `ssl_bump` (peek / bump)
- **SSLproxy** (decrypts and diverts to an inspection program)
- **PolarProxy** (decrypts and exports to PCAP for IDS)
- **mitmproxy** (scriptable, ideal in a lab)
- **Envoy** (TLS termination and forward proxy)

Suricata sits *after* one of them, never in its place.

---

## 3. The tools, layer by layer

### 3.1 Compute isolation

Network containment protects nothing if it wraps a porous compute environment.
The sandbox's internal TEST-NET addressing points to a locked-down VM or micro-VM.

| Tool                | Role                                             | Notes                                                                  |
| ------------------- | ------------------------------------------------ | ---------------------------------------------------------------------- |
| **gVisor**          | user-space kernel, syscall and network isolation | built by Google to run untrusted code, well-suited to an agent sandbox |
| **Firecracker**     | lightweight micro-VM                             | strong isolation, fast boot, used by AWS Lambda                        |
| **Kata Containers** | VM-backed containers                             | tradeoff between container and full VM                                 |

### 3.2 L3/L4 firewall

| Tool                       | Role                                                                                                                                               |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **nftables** (or iptables) | default-deny, port allowlist, DNAT to redirect 80/443 to the proxy and 53 to the resolver, silent drop of the rest (UDP, ICMP, unauthorized ports) |

This layer produces the silent timeouts measured in the characterization
document, and closes QUIC (UDP:443), NTP (UDP:123), WHOIS (TCP:43) and all UDP
tunnels.

### 3.3 Controlled DNS

| Tool        | Role                                                               |
| ----------- | ------------------------------------------------------------------ |
| **CoreDNS** | modular resolver, FQDN allowlist via plugins, ideal in a container |
| **Unbound** | validating resolver, `access-control` and views, very robust       |
| **dnsmasq** | lightweight, simple, suited to small labs                          |

Combined with the DNAT redirect of layer 3.2, this reproduces transparent DNS
interception. To harden: limit record types and monitor volume, because DNS
remains a potential exfiltration channel (see the characterization document).

### 3.4 The TLS-terminating proxy (the centerpiece)

This is where the essence lies. Four good choices depending on the goal.

**Squid with `ssl_bump`** is the pragmatic and best-documented choice.

- `peek` grabs the SNI, then `splice` turns into a TCP tunnel without decrypting,
  or `bump` fully decrypts, or `terminate` cuts.
- Domain filtering via `ssl::server_name` ACLs (HTTPS) and `dstdomain` (HTTP).
- `intercept` mode for transparency, fed by the iptables/nftables redirect.
- The exact allowlist egress-filtering pattern is publicly documented (AWS
  security blog).
- Required build options: `--enable-ssl-crtd`, `--with-openssl`.

**Envoy** is the most faithful choice to Anthropic's product, since Google Cloud
Secure Web Proxy is very likely derived from it.

- `dynamic_forward_proxy` routes on the Host header after TLS termination.
- `sni_dynamic_forward_proxy` routes on the SNI without decrypting, via the
  `tls_inspector`.
- Custom policies (refuse CONNECT, method filtering) via HTTP filters and
  `ext_authz` / `ext_proc`.
- More powerful than Squid, significantly more verbose to configure.

**mitmproxy** is the best for getting started and prototyping.

- Scriptable in Python, transparent mode, immediate iteration on policies.
- Perfect for understanding each decision, less suited to high throughput in
  production.

**SSLproxy** specializes in the termination + external-inspection pairing.

- Terminates TLS and re-encrypts to the original destination, diverting the
  plaintext to an inspection program (Suricata, Snort, a custom filter).
- Works on divert sockets: if no program re-injects the packets, the connection
  is blocked.
- `PassSite` rules let some sites pass through in passthrough mode (useful for
  applications that reject forged certificates).
- This is the tool presented in the reference talk on Suricata + TLS termination.

**PolarProxy** is the capture-oriented alternative.

- Terminates TLS and exports the decrypted traffic in PCAP format, consumable by
  any IDS (Suricata, Snort, Zeek) without re-decrypting.
- Widely used with Security Onion.

### 3.5 Lightweight SSRF-oriented alternative: Smokescreen

**Smokescreen** (Stripe) deserves a place of its own.

- HTTP/HTTPS forward proxy of the CONNECT type, with hostname ACLs, internal-IP
  blocking, and role-based access control via mTLS.
- Note the decisive architectural difference: it tunnels TLS and filters on the
  hostname **without decrypting it**. It gives you the domain allowlist and the
  anti-SSRF, but not the content inspection or method refusal observed at
  Anthropic.
- Ideal if the primary goal is egress centralization and anti-SSRF, not deep
  inspection.

### 3.6 IDS / IPS for defense in depth

| Tool         | Role                                                                          | Decrypts TLS?   |
| ------------ | ----------------------------------------------------------------------------- | --------------- |
| **Suricata** | SNI and JA3 blocking in IPS mode, plaintext inspection if fed by a terminator | no, never alone |
| **Zeek**     | deep network visibility and logging                                           | no              |

They come as a complement to the proxy, never in its place.

### 3.7 Kubernetes / eBPF alternative

| Tool       | Role                                                                                                              |
| ---------- | ----------------------------------------------------------------------------------------------------------------- |
| **Cilium** | L3-to-L7 network policies in eBPF, FQDN-based egress, natively very close to the "DNS + hostname allowlist" model |

If the environment is containerized under Kubernetes, Cilium elegantly replaces
the nftables + resolver + part-of-the-proxy combination.

---

## 4. Comparison summary table

| Tool              | Primary role            | Decrypts TLS        | Hostname filtering | Tunnel refusal | Profile        |
| ----------------- | ----------------------- | ------------------- | ------------------ | -------------- | -------------- |
| nftables          | L3/L4 firewall          | n/a                 | no (IP/port)       | n/a            | production     |
| CoreDNS / Unbound | controlled resolver     | n/a                 | yes (FQDN)         | n/a            | production     |
| Squid ssl_bump    | TLS proxy               | yes (bump)          | yes                | configurable   | production     |
| Envoy             | TLS proxy / forward     | yes                 | yes                | configurable   | production     |
| mitmproxy         | TLS proxy               | yes                 | yes (script)       | yes (script)   | lab            |
| SSLproxy          | terminator + IDS divert | yes                 | via the IDS        | via the IDS    | production     |
| PolarProxy        | terminator + PCAP       | yes                 | via the IDS        | via the IDS    | production     |
| Smokescreen       | CONNECT egress proxy    | no                  | yes                | n/a            | production     |
| Suricata          | IDS/IPS                 | no                  | yes (SNI)          | no             | production     |
| Cilium            | eBPF egress policy      | no (TLS visibility) | yes (FQDN)         | partial        | production k8s |

---

## 5. Recommended lab build

Suggested progression, from simplest to most faithful:

1. **Compute isolation first.** gVisor or a Firecracker micro-VM, otherwise the
   network containment protects a sieve.
2. **`nftables` default-deny.** Minimal allowlist 80, 443, 53. DNAT to the proxy
   (80/443) and the resolver (53). Silent drop of everything else.
3. **`CoreDNS`** with an FQDN allowlist, reachable only via the DNAT redirect.
4. **The proxy.** Start with **mitmproxy** to understand and prototype the
   policies (TLS termination, hostname allowlist, CONNECT refusal, WebSocket
   passthrough). Then move to **Squid ssl_bump** for a stable, documented setup.
   To stay as close as possible to the real product, redo it with **Envoy**.
5. **`Suricata` in IPS mode** alongside, fed by the proxy or by **SSLproxy** /
   **PolarProxy** for decrypted content.

Details not to forget to match the observed level:

- explicitly refuse the CONNECT method (Squid ACL or Envoy filter)
- allow the WebSocket upgrade only if the threat model permits, otherwise inspect
  the frames
- close UDP:443 (QUIC) and all UDP except 53 at the nftables layer
- confine ICMP to the internal segment
- route and filter on the decrypted Host header, not only on the SNI (the
  claude.ai sandbox routes on the Host)

---

## 6. The validation test

The best exercise is to replay against your stack all the probes from the
characterization document:

- port scan (expected: only 80 and 443 on TCP, 53 on UDP)
- UDP tunnels on 443, port-less protocols (GRE, ESP), SSTP, TURN-over-TLS
- STUN over UDP and WebRTC ICE candidate gathering (expected: no reflexive or
  relay candidate)
- CONNECT over HTTP/1.1 and HTTP/2 (expected: 403, even to an allowed host)
- WebSockets (expected: `101` to an allowed host, if you choose to allow it)

If your stack returns the same 403s, timeouts, and silences, you have matched the
level. Each test that passes when it should not points you precisely to the layer
to harden.

---

## 7. Verified references

All links below were checked at the time of writing.

**TLS-terminating proxies**

- Squid, Peek and Splice: https://wiki.squid-cache.org/Features/SslPeekAndSplice
- Squid, allowlist egress filtering (AWS blog): https://aws.amazon.com/blogs/security/how-to-add-dns-filtering-to-your-nat-instance-with-squid/
- SSLproxy: https://github.com/sonertari/SSLproxy
- PolarProxy with Security Onion: https://www.netresec.com/?page=Blog&month=2020-01&post=Sniffing-Decrypted-TLS-Traffic-with-Security-Onion
- mitmproxy: https://mitmproxy.org/
- Envoy, dynamic forward proxy: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/dynamic_forward_proxy_filter
- Envoy, SNI dynamic forward proxy: https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/sni_dynamic_forward_proxy_filter

**SSRF-oriented egress proxy**

- Smokescreen (Stripe): https://github.com/stripe/smokescreen

**IDS / IPS**

- Suricata, does not decrypt alone: https://forum.suricata.io/t/encrypted-traffic-inspection/2530
- Suricata, integration with an external decryptor: https://docs.suricata.io/en/latest/3rd-party-integration/symantec-sslv.html
- Zeek: https://zeek.org/

**Controlled DNS**

- CoreDNS: https://coredns.io/
- Unbound: https://nlnetlabs.nl/projects/unbound/about/

**Compute isolation**

- gVisor: https://gvisor.dev/
- Firecracker: https://firecracker-microvm.github.io/

**eBPF / Kubernetes**

- Cilium, FQDN-based egress: https://cilium.io/
