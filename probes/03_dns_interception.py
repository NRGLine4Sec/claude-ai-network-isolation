#!/usr/bin/env python3
"""
Probe 03: transparent DNS interception and recursion to the internet.
Characterization, benign targets.

Principle: query, on UDP:53, RESERVED IPs that host no resolver (RFC 5737 /
RFC 1918). If a valid answer still comes back, a transparent DNS proxy intercepts
port 53 and answers in their place. Then verify that the resolver recurses to the
internet (tunneling potential) by resolving a real name and then a unique random
subdomain.
"""
import socket, struct, os


def build_query(name, qtype=1, qclass=1, qid=0x1234):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", qtype, qclass)
    return q


def query(server, name, qtype=1, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_query(name, qtype), (server, 53))
        data, addr = s.recvfrom(1024)
        ancount = struct.unpack(">H", data[6:8])[0]
        rcode = data[3] & 0x0F
        return {"src": addr[0], "answers": ancount, "rcode": rcode, "len": len(data)}
    except socket.timeout:
        return None
    except Exception as e:
        return {"error": type(e).__name__}
    finally:
        s.close()


def main():
    print("== Interception test: reserved IPs with no resolver ==")
    print("   (a reply from these IPs proves a transparent DNAT on port 53)")
    reserved = ["203.0.113.45", "198.51.100.7", "10.255.255.254", "192.0.2.123"]
    for ip in reserved:
        r = query(ip, "example.com")
        if r is None:
            print(f"  {ip:<16} -> silence")
        elif "error" in r:
            print(f"  {ip:<16} -> {r['error']}")
        else:
            print(f"  {ip:<16} -> REPLY (src={r['src']}, {r['answers']} ans.) => intercepted")

    print("\n== Recursion to the internet (DNS tunneling potential) ==")
    r = query("8.8.8.8", "google.com", qtype=1)
    if r and r.get("answers"):
        print(f"  google.com A -> {r['answers']} answer(s): the resolver recurses to the internet")
    rnd = os.urandom(4).hex() + ".example.com"
    r = query("8.8.8.8", rnd, qtype=1)
    if r and "error" not in r:
        rc = {0: "NOERROR", 3: "NXDOMAIN"}.get(r["rcode"], f"rcode{r['rcode']}")
        print(f"  {rnd} -> {rc}")
        print("  (a reply to a unique subdomain proves the query reaches the")
        print("   authoritative server: the QNAME leaves toward the internet)")


if __name__ == "__main__":
    main()
