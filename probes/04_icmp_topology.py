#!/usr/bin/env python3
"""
Probe 04: ICMP reach and internal topology.
Characterization, benign target (8.8.8.8). Requires CAP_NET_RAW.

Send ICMP echoes to an external host (which normally answers ping), then an
increasing-TTL probe to reveal the internal hops. If external echoes get no reply
but internal hops answer time-exceeded, ICMP is confined to the internal network
and not routed to the internet.
"""
import socket, struct, os, select, sys


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def icmp_echo(dst, ttl=64, timeout=4):
    ident = os.getpid() & 0xFFFF
    payload = b"net-isolation-probe"
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
    pkt = struct.pack("!BBHHH", 8, 0, checksum(hdr + payload), ident, 1) + payload
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return ("no-cap", None)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (dst, 0))
        r, _, _ = select.select([s], [], [], timeout)
        if not r:
            return ("timeout", None)
        data, addr = s.recvfrom(1024)
        return (data[20], addr[0])  # ICMP type (after the 20-byte IP header)
    except Exception as e:
        return (f"err:{type(e).__name__}", None)
    finally:
        s.close()


def main():
    print("== ICMP echo to external hosts (expected: timeout if not routed) ==")
    for dst in ["8.8.8.8", "1.1.1.1"]:
        t, src = icmp_echo(dst)
        if t == "no-cap":
            print("  CAP_NET_RAW missing: ICMP probe unavailable in this environment.")
            sys.exit(0)
        label = {0: "ECHO REPLY", "timeout": "TIMEOUT"}.get(t, t)
        print(f"  {dst:<10} -> {label}" + (f" (from {src})" if src else ""))

    print("\n== Increasing-TTL probe to 8.8.8.8 (reveals internal topology) ==")
    for ttl in range(1, 6):
        t, src = icmp_echo("8.8.8.8", ttl=ttl, timeout=3)
        if t == 11:
            print(f"  TTL={ttl}: intermediate hop {src}")
        elif t == 0:
            print(f"  TTL={ttl}: REACHED 8.8.8.8 via {src}")
            break
        else:
            print(f"  TTL={ttl}: {t}")


if __name__ == "__main__":
    main()
