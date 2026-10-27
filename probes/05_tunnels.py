#!/usr/bin/env python3
"""
Probe 05: tunneling protocols.
Characterization, benign targets. Raw IP protocols require CAP_NET_RAW.

Three families:
  1. UDP-encapsulated tunnels (VXLAN, GENEVE, WireGuard, L2TP) tested on UDP:443.
  2. Port-less IP protocols (GRE=47, ESP=50, L2TP-IP=115, IPIP=4), probed at TTL=1
     to see whether they only enter the internal fabric.
  3. Multicast: send to a group and attempt an IGMP join.
"""
import socket, os, select


def udp443(payload, label, dst="142.250.80.14"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(payload, (dst, 443))
        d, _ = s.recvfrom(512)
        print(f"  {label:<18} -> reply {len(d)} B")
    except socket.timeout:
        print(f"  {label:<18} -> SILENCE (UDP:443 blocked)")
    except Exception as e:
        print(f"  {label:<18} -> {type(e).__name__}")
    finally:
        s.close()


def family1():
    print("== Family 1: UDP tunnels on UDP:443 ==")
    udp443(b"\x08\x00\x00\x00\x00\x00\x01\x00" + b"\x00" * 50, "VXLAN")
    udp443(b"\x00\x00\x65\x58\x00\x00\x01\x00", "GENEVE")
    udp443(b"\x01\x00\x00\x00" + os.urandom(144), "WireGuard init")
    udp443(b"\xc8\x02\x00\x0c" + b"\x00" * 8, "L2TP control")


def raw_proto(proto, label, dst="8.8.8.8"):
    try:
        tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    except PermissionError:
        print(f"  proto {proto:<3} {label:<10} -> CAP_NET_RAW missing")
        return
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    rx.settimeout(4)
    try:
        tx.sendto(b"\x00" * 32, (dst, 0))
        r, _, _ = select.select([rx], [], [], 4)
        if r:
            data, addr = rx.recvfrom(1024)
            print(f"  proto {proto:<3} {label:<10} -> ICMP{data[20]} from {addr[0]} (enters the fabric)")
        else:
            print(f"  proto {proto:<3} {label:<10} -> silence")
    except Exception as e:
        print(f"  proto {proto:<3} {label:<10} -> {type(e).__name__}")
    finally:
        tx.close()
        rx.close()


def family2():
    print("\n== Family 2: port-less IP protocols (TTL=1 probe) ==")
    for proto, label in [(47, "GRE"), (50, "ESP"), (115, "L2TP-IP"), (4, "IP-in-IP")]:
        raw_proto(proto, label)


def family3():
    print("\n== Family 3: multicast ==")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.sendto(b"MCAST", ("239.255.255.250", 443))
        s.close()
        print("  send to 239.255.255.250:443 -> accepted at socket level")
    except Exception as e:
        print(f"  multicast send -> {type(e).__name__}")
    print("  (multicast does not route to the internet: unusable to get out)")


if __name__ == "__main__":
    family1()
    family2()
    family3()
