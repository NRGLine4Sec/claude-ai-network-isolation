#!/usr/bin/env python3
"""
Probe 01: egress port allowlist (TCP and UDP).
Characterization, benign targets.

Method: against a host that returns a fast RST on its closed ports
(scanme.nmap.org, meant to be scanned), each port is classified:
  - OPEN or REFUSED (fast RST)  -> egress lets the SYN through (port allowed)
  - TIMEOUT                     -> silent drop at egress (port blocked)
For UDP, ports 53 (DNS), 123 (NTP), and 443 (QUIC) are tested directly.
"""
import socket, concurrent.futures as cf, struct

TCP_HOST = "scanme.nmap.org"
WELL_KNOWN = list(range(1, 1024))
NOTABLE_HIGH = [1080, 1194, 1433, 1521, 2049, 2222, 3306, 3389, 5060, 5222,
                5432, 5900, 6379, 6667, 8000, 8080, 8443, 8888, 9000, 9200, 27017]


def tcp_probe(ip, port, timeout=4):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return port, "OPEN"
    except ConnectionRefusedError:
        return port, "REFUSED"
    except socket.timeout:
        return port, "TIMEOUT"
    except Exception as e:
        return port, type(e).__name__
    finally:
        s.close()


def scan_tcp():
    ip = socket.gethostbyname(TCP_HOST)
    ports = WELL_KNOWN + NOTABLE_HIGH
    print(f"[TCP] target {TCP_HOST} ({ip}) — scanning {len(ports)} ports")
    allowed, blocked = [], 0
    with cf.ThreadPoolExecutor(max_workers=80) as ex:
        for port, status in ex.map(lambda p: tcp_probe(ip, p), ports):
            if status in ("OPEN", "REFUSED"):
                allowed.append(port)
            elif status == "TIMEOUT":
                blocked += 1
    print(f"[TCP] ports let through by egress: {sorted(allowed)}")
    print(f"[TCP] ports in timeout (blocked)  : {blocked}/{len(ports)}")


def udp_probe(host, port, payload, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (socket.gethostbyname(host), port))
        data, _ = s.recvfrom(512)
        return f"REPLY ({len(data)} B) — port open"
    except socket.timeout:
        return "SILENCE — blocked (or no reply from the service)"
    except Exception as e:
        return f"{type(e).__name__}"
    finally:
        s.close()


def scan_udp():
    print("\n[UDP] direct tests")
    dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    dns += b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    print(f"  UDP:53  DNS  to 8.8.8.8          -> {udp_probe('8.8.8.8', 53, dns)}")
    ntp = b"\x1b" + 47 * b"\x00"
    print(f"  UDP:123 NTP  to time.google.com  -> {udp_probe('time.google.com', 123, ntp)}")
    print(f"  UDP:443 QUIC to www.google.com   -> {udp_probe('www.google.com', 443, b'\\x00' * 64)}")


if __name__ == "__main__":
    scan_tcp()
    scan_udp()
