# Network characterization of the claude.ai code-execution sandbox

*A measured study of the egress boundary of claude.ai's code-execution
environment, strictly through a network lens: architecture, filtering, evasion,
containment. Every claim is established by direct measurement and reproducible via
the scripts in the `probes/` folder.*

*Caveats valid for the whole document: the attribution to Google Cloud Secure Web
Proxy is a strong-inference deduction, not confirmed by Anthropic; the
measurements describe one environment, at a given date, observed from the inside,
and may not generalize nor remain valid over time.*

## 1. Overview

The claude.ai code-execution environment runs inside a sandbox with fully mediated
network egress. No protocol has raw access to the internet. The measured summary:

| Layer / protocol | Egress treatment |
|---|---|
| DNS (UDP:53) | intercepted, redirected to an internal resolver (transparent DNAT) |
| DoH (TCP:443) | intercepted and decrypted by the TLS gateway |
| HTTP (TCP:80) | allowed |
| HTTPS (TCP:443) | terminated and decrypted, filtering on the hostname |
| WHOIS (TCP:43), SSH, SMTP, IRC | blocked (ports outside the allowlist) |
| NTP (UDP:123), QUIC (UDP:443) | blocked |
| Tunnels (GRE, VXLAN, GENEVE, WireGuard, L2TP, SSTP) | blocked or refused |
| STUN / TURN / WebRTC | inoperative |
| WebSocket | allowed (starts as HTTP over 443) |
| CONNECT (HTTP/1.1 and HTTP/2) | refused, even to an allowed host |
| ICMP | confined to the internal network, not routed to the internet |
| Internal LAN | `192.0.2.0/24`, gateway `192.0.2.1`, then GCP fabric |

The following sections detail each measurement. Part 2 covers the architecture and
the mapping of the stack. Part 3 covers the egress identity (and the absence of a
residential proxy). Part 4 states the limits.

To reproduce this containment with open source, see `02-oss-containment-toolkit.md`.
For bypasses already found and fixed by other researchers, see
`03-public-vulnerabilities.md`.

## 2. Egress architecture and full mapping of the stack

This part characterizes the wall precisely. All targets of active tests are benign
hosts (Google, Cloudflare), and no blocked host was reached. The goal is to
understand the barrier, not to break it.

### 2.1 The proxy is a full TLS interceptor (Secure Web Proxy)

The certificate presented for `www.google.com`, as for the DoH resolvers tested, is
issued by:

```
issuer  = O = Anthropic, CN = Egress Gateway SDS Issuing CA (production)
subject = CN = *.google.com
```

The corresponding CA is installed in the container's trust store:

```
/usr/local/share/ca-certificates/egress-gateway-ca-production.crt
/usr/local/share/ca-certificates/egress-gateway-ca-staging.crt
/usr/local/share/ca-certificates/swp-ca-production.crt
/usr/local/share/ca-certificates/swp-ca-staging.crt
```

Consequence: this is not a passive firewall, it is a proxy that **terminates and
decrypts all TCP/443 traffic**. It sees, in cleartext, the SNI, the `Host` header,
the path, and the body of every request. The `swp` acronym points to a Secure Web
Proxy.

### 2.2 Where the block happens exactly

Trace of a request to a blocked host:

1. DNS resolves correctly (`web.archive.org` to `207.241.237.3`).
2. The TCP connection is established to the real IP.
3. The TLS handshake completes.
4. At the HTTP layer, the proxy returns `403` with `x-block-reason: hostname_blocked`.

Filtering therefore applies to the **hostname, after DNS and after TLS
termination**. This is the point that invalidates the two bypass hypotheses (DoH
and QUIC).

### 2.3 DoH: intercepted, hence doubly useless

Direct measurement on two DoH resolvers:

| DoH resolver | Issuer of the received certificate |
|---|---|
| `cloudflare-dns.com` | Anthropic, Egress Gateway SDS Issuing CA |
| `dns.google` | Anthropic, Egress Gateway SDS Issuing CA |

A real benign DoH query (resolving `example.com`) succeeds, but through an HTTPS
tunnel the gateway decrypts. Two consequences:

- **No bypass gain.** The block is not at the DNS layer anyway (DNS already
  resolves). Changing the resolution method does not change the hostname the proxy
  inspects afterwards.
- **DoH's confidentiality is nullified.** DoH is designed to hide DNS queries from
  an observer *on the path*. But the proxy is not on the path, it is the TLS
  *endpoint*. It reads the DNS queries in cleartext inside the tunnel meant to
  protect them. Even ECH (Encrypted ClientHello) would be moot, since the proxy
  decrypts the inner ClientHello itself.

### 2.4 HTTP/3 and QUIC: there is no UDP:443 path

The hypothesis was that the proxy, unable to handle QUIC, would let HTTP/3 through.
The measurement closes it before that point.

Low-level QUIC probe: a long-header packet with an unsupported version normally
forces an HTTP/3 server to reply with a "Version Negotiation". Sent to two servers
that support HTTP/3:

| Benign target (known HTTP/3) | Result |
|---|---|
| `www.google.com` UDP:443 | silence (timeout) |
| `cloudflare-quic.com` UDP:443 | silence (timeout) |

Positive control at the same time: the same technique on UDP:53 gets 124-byte DNS
responses from `1.1.1.1` and `8.8.8.8`. The UDP socket therefore works; it is UDP
port 443 that is closed.

UDP egress is **allowed on port 53 (DNS) and closed on port 443 (QUIC)**. This is
exactly the posture adopted to neutralize QUIC-based bypass, a well-known
technique. The "the proxy cannot parse QUIC" hypothesis does not apply, since no
QUIC datagram egresses: there is nothing to parse. Incidentally, the environment's
`curl` (8.5.0) has no HTTP/3 compiled in.

### 2.5 Layer summary table

| Layer | Benign target | Blocked target |
|---|---|---|
| DNS | resolves OK | `web.archive.org` resolves OK (`207.241.237.3`) |
| TCP:443 (TLS) | google -> HTTP/2 200 | `web.archive.org` -> 403 `x-block-reason` |
| UDP:53 (DNS) | `1.1.1.1` and `8.8.8.8` -> 124-byte reply | n/a |
| UDP:443 (QUIC) | google and Cloudflare -> silence | no need to test |
| TLS certificate | issued by Anthropic's Egress Gateway CA | same (full interception) |

### 2.6 Why this analysis stops here

This study stops at characterizing the wall. The next steps of an actual attempt
(domain fronting via an allowed host sharing an IP, an application tunnel over an
open port, using an allowed third-party service as a relay) would amount to
building an operational bypass of the sandbox's own security boundary.
Understanding the barrier is legitimate; breaking it is not, and the line between
the two is exactly there.

### 2.7 Reproducible commands (network part)

```bash
# TLS interception: the certificate issuer should be Anthropic's Egress Gateway CA
echo | openssl s_client -connect www.google.com:443 -servername www.google.com 2>/dev/null \
  | openssl x509 -noout -issuer
# expected: issuer=O = Anthropic, CN = Egress Gateway SDS Issuing CA (production)

# Same interception on a DoH resolver
echo | openssl s_client -connect cloudflare-dns.com:443 -servername cloudflare-dns.com 2>/dev/null \
  | openssl x509 -noout -issuer

# Benign DoH query: succeeds, but through the MITM tunnel
curl -s -H "accept: application/dns-json" \
  "https://cloudflare-dns.com/dns-query?name=example.com&type=A"

# UDP:53 (DNS) works / UDP:443 (QUIC) does not answer
python3 - <<'PY'
import socket, os
def quic_vn_probe(ip):
    pkt = bytes([0xC0]) + b'\x1a\x2a\x3a\x4a' + bytes([8]) + os.urandom(8) + bytes([8]) + os.urandom(8)
    pkt += b'\x00' * (1200 - len(pkt))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
    try:
        s.sendto(pkt, (ip, 443)); d,_ = s.recvfrom(2048)
        print("UDP:443 -> reply", len(d), "bytes")
    except socket.timeout:
        print("UDP:443 -> silence (filtered)")
    finally:
        s.close()
quic_vn_probe(socket.gethostbyname("www.google.com"))
PY
```

### 2.8 Full mapping of the network stack (DNS, ICMP, WHOIS, NTP)

Beyond TCP/443, the other layers were characterized. The result is a fully mediated
egress, where each protocol is either proxied, confined, or simply blocked by a
port allowlist.

**Plain DNS (UDP:53): intercepted by a transparent resolver.** `/etc/resolv.conf`
lists `nameserver 8.8.8.8`, but the traffic does not reach 8.8.8.8 directly. Proof:
querying IPs that host no resolver still returns valid answers.

| Queried destination | Nature | Result |
|---|---|---|
| `1.1.1.1`, `8.8.8.8`, `9.9.9.9` | real resolvers | valid reply |
| `203.0.113.45` | TEST-NET-3 reserved | valid reply (2 answers) |
| `198.51.100.7` | TEST-NET-2 reserved | valid reply |
| `10.255.255.254` | RFC 1918 private | valid reply |
| `192.0.2.123` | sandbox local range | silence |

Getting a reply from servers that cannot exist proves a transparent DNAT on port
53, redirected to an internal resolver that spoofs the destination address. The
`192.0.2.0/24` exception illuminates the topology, since it is the container's
local network (gateway at `192.0.2.1`). A CHAOS-class query (`whoami.cloudflare`)
comes back empty, which is the typical behavior of an intermediate forwarder. DNS
egress IP as seen by Google: `34.134.124.0`, in Google Cloud.

**ICMP: confined to the internal network, not routed to the internet.** The
container has the `CAP_NET_RAW` capability, which allowed crafting the packets. An
echo to `8.8.8.8`, `1.1.1.1`, or Google gets no reply. An increasing-TTL probe
reveals the internal topology, then silence at the egress boundary.

| TTL | Revealed hop | Interpretation |
|---|---|---|
| 1 | `192.0.2.1` | internal gateway (TEST-NET-1 addressing) |
| 2 | `21.4.0.241` | internal fabric, likely GCP |
| 3 and beyond | silence | ICMP is dropped at the egress boundary |

An echo to `192.0.2.123` returns a "destination unreachable" from `192.0.2.2`.
ICMP therefore lives inside but does not cross the boundary. Caveat: `21.0.0.0/8`
is nominally assigned to the US DoD, but is used internally by some cloud
infrastructures. Given its position, it is almost certainly internal fabric.

**WHOIS (TCP:43) and NTP (UDP:123): blocked by the port policy.** Neither
intercepted nor resolved, simply no egress path. Three WHOIS servers (IANA, ARIN,
Verisign) on port 43 time out. The three public NTP servers tested
(`time.google.com`, `time.cloudflare.com`, `pool.ntp.org`) stay silent on UDP:123,
exactly like QUIC on UDP:443.

Probing several ports, the logic appears: **egress is a port allowlist, limited to
the web.**

| Port | Protocol | Result |
|---|---|---|
| TCP:80 | HTTP | open |
| TCP:443 | HTTPS | open (TLS-intercepted) |
| TCP:43 | WHOIS | blocked (timeout) |
| TCP:22 | SSH | blocked (timeout) |
| TCP:587 | SMTP submission | blocked (timeout) |
| TCP:6667 | IRC | blocked (timeout) |
| UDP:53 | DNS | open (intercepted) |
| UDP:123 | NTP | blocked (timeout) |
| UDP:443 | QUIC | blocked (timeout) |

**Full-stack summary table:**

| Layer / protocol | Egress treatment |
|---|---|
| DNS (UDP:53) | intercepted, redirected to an internal resolver (transparent DNAT) |
| DoH (TCP:443) | intercepted and decrypted by the TLS gateway |
| HTTP (TCP:80) | allowed |
| HTTPS (TCP:443) | terminated and decrypted, filtering on the hostname |
| WHOIS (TCP:43) | blocked (port outside the allowlist) |
| SSH, SMTP, IRC (various TCP) | blocked (ports outside the allowlist) |
| NTP (UDP:123) | blocked |
| QUIC (UDP:443) | blocked |
| ICMP | confined to the internal network, not routed to the internet |
| Internal LAN | `192.0.2.0/24`, gateway `192.0.2.1`, then GCP fabric |

The consistency is total: only the web (80, 443) and DNS resolution (53) egress,
and everything that egresses is proxied or intercepted. No protocol has raw, direct
access to the internet. This is exactly what makes DoH, QUIC, WHOIS, and NTP moot
as alternative paths.

### 2.9 Reproducible commands (WHOIS, NTP, ports)

```bash
# WHOIS (TCP:43) - expected: timeout, port outside the allowlist
python3 -c "
import socket
ip=socket.gethostbyname('whois.iana.org')
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(8)
try: s.connect((ip,43)); print('43 open')
except Exception as e: print('TCP:43 ->', type(e).__name__)
"

# NTP (UDP:123) - expected: silence
python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(6)
s.sendto(b'\x1b'+47*b'\0',(socket.gethostbyname('time.google.com'),123))
try: d,_=s.recvfrom(512); print('NTP replies', len(d),'B')
except socket.timeout: print('UDP:123 -> silence (blocked)')
"

# DNS interception - a reply from a reserved IP = transparent proxy
python3 -c "
import socket,struct
q=struct.pack('>HHHHHH',0x1234,0x0100,1,0,0,0)+b'\x07example\x03com\x00'+struct.pack('>HH',1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(6)
s.sendto(q,('203.0.113.45',53))
try: d,a=s.recvfrom(512); print('reply from',a[0],'=> DNS intercepted')
except socket.timeout: print('silence')
"
```

### 2.10 The exact port allowlist

By methodically probing each port against a host that actually runs the
corresponding service (so timeout = blocked at egress, fast RST or connection =
allowed), then confirming with a broad scan, the allowlist turns out to be
extremely spare.

Scan of **1049 TCP ports** (the whole 1-1023 range plus notable high ports)
against `scanme.nmap.org`, a host that returns a fast RST on its closed ports:

| Protocol | Allowed ports | Result of the rest |
|---|---|---|
| TCP | **80, 443** only | 1047 of 1049 ports in timeout (silent drop) |
| UDP | **53** only (and intercepted) | 123 (NTP), 443 (QUIC) and the rest blocked |
| ICMP | internal only | not routed to the internet |

It is not even "web ports in a broad sense": `8080`, `8443`, DNS over TCP
(`53/tcp`), DNS-over-TLS (`853`) are all closed. Literally two TCP ports and one
UDP port. Since UDP scanning is inherently unreliable (the absence of a reply is
ambiguous), only `53` open and `123`/`443` closed are asserted with certainty,
tested directly.

### 2.11 Tunneling protocols and multicast

A natural question when seeking to bypass L7 filtering: can an encapsulation
protocol get through? Tested on port 443 where it makes sense, they fall into three
families, all neutralized.

**Family 1, UDP-encapsulated tunnels (VXLAN, GENEVE, WireGuard, L2TP).** Putting
them "on 443" means UDP:443. Sending correctly formed datagrams for each to
UDP:443: total silence in all four cases. They are blocked by the closure of
UDP:443, regardless of content. Since the only open UDP port is 53, no UDP tunnel
egresses.

**Family 2, IP protocols that are neither TCP nor UDP (GRE = protocol 47, ESP/IPsec
= 50, native L2TP = 115, IP-in-IP = 4).** They have no notion of port, so "on 443"
does not apply. An increasing-TTL probe shows they enter the internal fabric
(`192.0.2.1` at hop 1, `21.4.x` at hop 2) then die at the same boundary as ICMP,
never reaching the internet. An egress based on a TCP/UDP port allowlist
structurally cannot relay a port-less protocol.

| IP protocol | Hop 1 | Hop 2 | Hop 3+ | Egresses to internet? |
|---|---|---|---|---|
| GRE (47) | `192.0.2.1` | `21.4.1.199` | silence | no |
| ICMP (1) | `192.0.2.1` | `21.4.0.241` | silence | no |

**Family 3, SSTP (the interesting case).** SSTP runs over TLS on TCP:443, so it
passes the port allowlist. But it is defeated on two fronts at once. First, the
proxy terminates TLS: opening a session to `www.google.com:443`, the received
certificate is issued by `O = Anthropic, CN = Egress Gateway SDS Issuing CA`, not by
an SSTP server. An SSTP client can therefore never establish end-to-end TLS with
its server. Second, the proxy is HTTP-aware: the `SSTP_DUPLEX_POST` request gets an
`HTTP/1.1 400 Bad Request`, and any attempt to an unauthorized server returns
`HTTP/1.1 403 Forbidden` with `x-block-reason: hostname_blocked`.

**Multicast.** Sending to a group (`239.255.255.250:443`) and the IGMP join
(`224.0.0.251`) are accepted at the socket level, but multicast does not route to
the internet and egress is a unicast TCP/UDP proxy. It is therefore unusable to get
out, whatever the port.

**Summary:** no tunneling protocol crosses the barrier. UDP tunnels fall on the
closure of UDP:443, port-less protocols cannot traverse a port-based egress, and
SSTP is broken by TLS termination and HTTP inspection.

### 2.12 The likely product: Google Cloud Secure Web Proxy

Several converging clues point to Google Cloud Secure Web Proxy (SWP) as the
implementation. The container's trust store contains CAs named `swp-ca-production.crt`
and `swp-ca-staging.crt`, `swp` being precisely the product's acronym. The gateway
identifies as `Egress Gateway SDS Issuing CA`, where `SDS` (Secret Discovery
Service) is an Envoy mechanism, the proxy on which SWP is built. The whole
infrastructure egresses via Google Cloud (IPs in `34.x`, `35.x`, `146.148.x`). The
observed pattern (TLS-terminating proxy, hostname allowlist, L7 filtering)
corresponds exactly to what SWP productizes.

### 2.13 Instrument validation

A negative result is only worth something once the measurement tool is proven to
work. Each blocked test was therefore controlled against an equivalent positive.

- **The `socket` library works fully.** It imports, creates the three socket types
  (TCP, UDP, RAW/ICMP), and a full client-server exchange succeeds in loopback
  (`bind`, `listen`, `accept`, `connect`, `sendto`, `recvfrom`).
- **Differential test, same code, different port.** The same connection function
  succeeds to `example.com:80` (40 ms) and `google:443` (5 ms), and times out to
  `whois.iana.org:43` and `github.com:22`, while DNS resolution and socket creation
  succeed in all cases. The only factor that changes is the port.
- **Nature of the failure.** A closed port in loopback (`127.0.0.1:9`) returns
  `Connection refused` (RST) in 1 ms, which proves the TCP stack can receive a
  rejection. A port blocked at egress times out after several seconds. A timeout,
  rather than an immediate rejection, is the signature of a packet silently dropped
  by an egress firewall, not of a library restriction.

Conclusion: the failures do not come from an inability to use `socket`, but from
the network policy applied at egress. The tools are not crippled; the network path
is controlled.

### 2.14 Reusable design pattern for a contained environment

This stack is a clean model for anyone building a tightly controlled egress
environment. The observed principles:

1. **Default-deny egress.** Everything is blocked, opened by exception, and the
   allowlist is tiny (two TCP ports, one UDP).
2. **Silent drop rather than reject.** Blocked ports swallow the packet instead of
   returning an RST, which slows and complicates internal reconnaissance.
3. **TLS-terminating web proxy with a hostname allowlist.** The only real traffic
   (80/443) goes through a proxy that decrypts and filters on the hostname. Nothing
   egresses without inspection.
4. **DNS forced to a controlled resolver** via transparent DNAT, which forbids
   exfiltration through a third-party resolver or an arbitrary DNS tunnel.
5. **UDP almost entirely closed**, leaving only DNS. QUIC and all UDP tunnels are
   cut, closing the modern escape hatch from L7 filtering.
6. **ICMP and port-less protocols confined** to the internal fabric, never routed
   to the internet.
7. **Internal addressing in reserved ranges** (`192.0.2.0/24`, TEST-NET), avoiding
   any overlap with real destinations.
8. **Published egress identity** (User-Agent and IP list), assumed transparency
   rather than stealth.

Usual building blocks to reproduce this pattern: an L7 proxy (Envoy, Squid) with a
domain allowlist, an intercepting resolver (CoreDNS, dnsmasq), and default-deny
nftables rules with a port allowlist. The corresponding managed product is Google
Cloud Secure Web Proxy.

### 2.15 WebSockets, STUN, TURN, and WebRTC

These three mechanisms are the ones used to traverse NATs and restrictive
firewalls, so they warranted a dedicated test. The result clearly contrasts
WebSockets, which works, with the rest, which is closed.

| Mechanism | Measured result | Cause |
|---|---|---|
| WebSockets (Upgrade over TLS:443) | `101 Switching Protocols` | start as HTTP, the L7 proxy relays the upgrade to a non-blocked host |
| STUN over UDP (19302, 3478) | silence | no UDP port except 53, no reflexive address discoverable |
| TURN/TCP (3478) and TURNS/TCP (5349) | timeout | ports outside the allowlist |
| TURN-over-TLS on 443 | `400 Bad Request` | the proxy terminates TLS and expects HTTP, like SSTP |
| WebRTC (ICE gathering via aiortc) | a single candidate `typ=host 192.0.2.2` | neither `srflx` (STUN blocked) nor `relay` (TURN blocked) |

The WebRTC case is the most demonstrative. ICE gathering produces only a single
candidate of type `host` bearing the non-routable internal address `192.0.2.2`,
with no reflexive or relay candidate. An external peer therefore has no reachable
address. Signaling can go through WebSocket or HTTPS, but the media path does not
exist. WebRTC is structurally impossible toward the outside.

WebSockets is the only tested mechanism that crosses the barrier, and it is a
design lesson. It passes because a WebSocket is HTTP to begin with: the `Upgrade`
request over 443 matches the proxy's model. The consequence for containment: an L7
proxy with a hostname allowlist, however strict, opens by default a persistent
bidirectional channel to any allowed host that accepts the upgrade. This is not a
bypass of hostname filtering, but if the threat model includes exfiltration, one
must either inspect the WebSocket frames or restrict which hosts may open an
Upgrade. This is the natural complement of principle 3 of the previous section.

### 2.16 HTTP CONNECT (HTTP/1.1 and HTTP/2)

The CONNECT tunnel is the most direct attempt against a proxy: if the gateway
honored the CONNECT method, it would open a TCP tunnel to any host:port, which would
nullify all hostname filtering. Tested in all its forms, it is categorically
refused.

| Request | Result |
|---|---|
| `CONNECT web.archive.org:443` (HTTP/1.1 over TLS) | `403 Forbidden` |
| `CONNECT 1.1.1.1:22` (HTTP/1.1 over TLS) | `403 Forbidden` |
| `CONNECT example.com:443` to an **allowed** host | `403 Forbidden` |
| `CONNECT` in HTTP/2 (`:method CONNECT`) | `:status 403` |
| `CONNECT` in cleartext on port 80 | `403 Forbidden` |

The decisive point is the third row: even to a non-blocked host, CONNECT is refused.
It is therefore not the destination that is filtered but the method itself. The
gateway refuses to establish any opaque tunnel, because a CONNECT tunnel would be a
byte stream it could no longer inspect or filter by hostname. It only accepts
inspectable HTTP(S) requests to hostnames, never a raw pipe. This is consistent with
the refusal of SSTP and TURN-over-TLS: no opaque end-to-end channel is tolerated,
whatever protocol is used to request it.

---

## 3. Egress identity and absence of a residential proxy

### 3.1 Question and hypotheses

**Concrete question:** does the web-fetch traffic transit through a residential
proxy network (rotating consumer IPs) to evade IP-based blocks, or does it egress
from declared datacenter IPs?

- **H1**: declared datacenter egress, self-identifying agent, no evasion.
- **H2**: third-party residential proxy network, consumer-ISP ASNs, rotation,
  evasion.
- **H3**: hybrid.

### 3.2 Measuring the web-fetch egress IP

| Measurement | Value |
|---|---|
| IP | `34.162.230.222` |
| ASN | AS396982 Google LLC |
| Reverse DNS | `222.230.162.34.bc.googleusercontent.com` |
| Range | `34.162.192.0/18` |
| AS Type | **hosting** |
| Abuse contact | `google-cloud-compliance@google.com` |
| Geolocation | Columbus, Ohio (GCP us-east5) |

IPinfo's "Anonymization" panel: **Hosting detected**. VPN, Proxy, Tor, Relay, and
**Residential Proxy not detected**. IPinfo sells a dedicated residential-proxy
detection product, so this negative comes from a specialized instrument.

### 3.3 Measuring the web-fetch User-Agent

Captured via an HTTP echo service:

```
Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible;
Claude-User/1.0; +claude-user@anthropic.com)
```

Headers sent in total: `Accept`, `Accept-Encoding`, `Host`, `User-Agent`. No
spoofed browser fingerprint (no `Sec-CH-UA`, no `Accept-Language`, no cookies). It
is the exact opposite of a stealth crawler.

### 3.4 Instrument validation

The three observed IPs were cross-referenced with the canonical list published by
Google itself (`gstatic.com/ipranges/cloud.json`), 997 prefixes:

| Observed IP | Google prefix | Region |
|---|---|---|
| `34.69.247.5` | `34.68.0.0/14` | us-central1 |
| `146.148.68.33` | `146.148.64.0/19` | us-central1 |
| `34.162.230.222` | `34.162.0.0/16` | us-east5 |

3/3 match against an independent primary source.

### 3.5 The verification loop closes

Anthropic **now publishes** its crawler IP list at
`https://claude.com/crawling/bots.json`, replacing its earlier "we do not publish IP
ranges" stance. This change is after January 2026.

The fetched file contains 20 IPv4 prefixes, `creationTime` on 2026-05-01. It
includes **`34.162.230.222/32`**, that is, exactly the IP measured blind before even
knowing the file existed. An independent third-party directory (DataFast) observes
the same IP on the server side.

### 3.6 Full classification of the 20 official prefixes

| Category | Count | Detail |
|---|---|---|
| Confirmed Google Cloud | 19 | regions us-east4 and us-east5 |
| Anthropic-owned AWS block | 1 | `216.73.216.0/22` |
| **Consumer / residential ranges** | **0** | |

ARIN's RDAP for `216.73.216.0/22` returns:

```
handle      : NET-216-73-216-0-1
name        : AWS-ANTHROPIC
registrant  : Anthropic, PBC
```

**Shape analysis:** 1043 declared addresses total, of which 18 of 20 entries are
single addresses (`/32`). A residential proxy network has the opposite shape, with
tens of thousands to millions of consumer IPs scattered across ISPs and countries.

**Conclusion: H1 confirmed, H2 contradicted by every instrument.**

### 3.7 Why Anthropic does not do it: the Perplexity case

In August 2025, Cloudflare de-listed Perplexity from its Verified Bots program after
finding the use of undeclared IPs from different ASNs, IP and ASN rotation, and a
spoofed User-Agent impersonating Chrome on macOS, activated specifically when the
declared crawler was blocked. Reported scale: 3 to 6 million daily requests across
tens of thousands of domains. Cloudflare re-tested OpenAI's crawler and found it
stopped properly when denied.

Cloudflare's transparency criterion for a well-behaved crawler: identify honestly
via a unique User-Agent, a published IP list or Web Bot Auth, and provide a contact.

Anthropic satisfies all three: unique User-Agent, published IP list, contact
address. The setup imagined in the question is precisely the line Perplexity crossed
and that cost it its verification.

### 3.8 Anthropic's official commitments

Excerpts from support article 8896518, updated 2026-04-07:

- Data collection should be transparent.
- Crawling should not be intrusive or disruptive, respecting `Crawl-delay`.
- The bots respect "do not crawl" signals via standard robots.txt directives.
- The bots respect anti-circumvention technologies, explicitly stating they will
  not attempt to bypass CAPTCHAs.

Three declared agents: `ClaudeBot` (training), `Claude-User` (user-initiated
fetch), `Claude-SearchBot` (search indexing).

### 3.9 Counterpoint: what Anthropic is actually criticized for

For balance, criticisms exist and are serious, but concern a different grievance.

- iFixit reported about 1 million requests in 24 hours.
- Freelancer reported about 3.5 million visits in 4 hours, calling ClaudeBot the
  most aggressive scraper by far.
- Cloudflare data from late 2025 placed Anthropic at the worst crawl-to-referral
  ratio among major AI platforms, about 38,000 pages crawled per referral in July
  2025, versus about 286,930 in January 2025.
- Reddit alleges continued access more than 100,000 times after Anthropic said it
  had stopped.

**The decisive point: none of these accusations concern residential proxies, ASN
rotation, or User-Agent spoofing.** That grievance targets Perplexity, not
Anthropic. Note also that iFixit's leadership stated the crawling stopped after the
robots.txt directive was added, which shows the declared mechanism works.

---

## 4. Limits and epistemic honesty

**Established by direct measurement:**
- The hostname block on `web.archive.org` and `reddit.com` from the claude.ai
  environment.
- The egress IP and User-Agent of web-fetch.
- The full TLS interception by Anthropic's egress gateway (certificate issued by
  its internal CA, including on DoH resolvers).
- The block applies to the hostname, after DNS and after TLS termination.
- UDP egress is open on port 53 and closed on port 443, which neutralizes QUIC.
- DoH is intercepted and decrypted, hence with no bypass or confidentiality effect
  here.
- Plain DNS (UDP:53) is intercepted by a transparent resolver (valid replies from
  reserved IPs).
- ICMP is confined to the internal network (topology `192.0.2.1` then `21.4.0.241`)
  and not routed to the internet.
- WHOIS (TCP:43) and NTP (UDP:123) are blocked. Egress is a port allowlist limited
  to 80, 443, and 53.
- The TCP allowlist reduces to 80 and 443, confirmed by a 1049-port scan (1047 in
  timeout).
- Tunneling protocols are all neutralized: UDP tunnels by the closure of UDP:443,
  port-less protocols (GRE, ESP, L2TP-IP) confined internally, SSTP broken by TLS
  termination and HTTP inspection.
- STUN, TURN, and WebRTC are closed (STUN silent, TURN ports blocked,
  TURN-over-TLS:443 at 400, WebRTC reduced to a non-routable internal candidate),
  but WebSockets work to non-blocked hosts (`101` upgrade relayed by the proxy).
- The CONNECT tunnel is categorically refused (403 in HTTP/1.1 and HTTP/2, even to
  an allowed host); the gateway establishes no opaque tunnel.
- The `socket` library works fully (validated in loopback), so the negative results
  come from the network and not from the tool.

**Deduced with high confidence:**
- The implementation is Google Cloud Secure Web Proxy (CAs `swp-*`, Envoy's `SDS`,
  egress via GCP), a strong convergence of clues but not confirmed by an Anthropic
  source.
- Port-less protocols do not reach the internet (proven up to the internal boundary
  by TTL probe; the absence of egress rests on the port-based architecture plus the
  absence of any responder).

**Strongly supported but not measured here:**
- The behavior of Claude Code (User-Agent `claude-code/`, robots.txt compliance),
  which comes from documentation and third-party sources.
- That claude.ai's web-fetch tool uses exactly the same blocklist as the code
  environment. The observable behavior is identical, but it cannot be inspected from
  the inside.

**Remains hypothesis:**
- The precise reason for the `web.archive.org` block (no official statement names
  it).
- The link between the Reddit litigation and the `reddit.com` block.

**General caveats:**
- A negative result is not proof of absence. These measurements cover two network
  paths, at a given date. They do not rule out other infrastructure on unobservable
  paths.
- `bots.json` remains Anthropic's declaration about itself, even though it is here
  corroborated by a blind measurement and by a third-party observer.
- A legitimate edge case not measured: Claude in Chrome runs in your browser and
  therefore uses your own residential connection. That is your IP, not a rented
  proxy network.
