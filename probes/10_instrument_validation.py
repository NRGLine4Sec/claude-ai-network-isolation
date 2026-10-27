#!/usr/bin/env python3
"""
Probe 10: instrument validation.
Proves the socket library works, so that the negative results of the other probes
(timeouts) are attributable to the network and not to the tool.

  A. Import and creation of the three socket types.
  B. Full client-server exchange in loopback (TCP).
  C. Differential test: the SAME code succeeds on an allowed port and fails only
     on a blocked port.
  D. Nature of the failure: a closed port in loopback returns an immediate RST, a
     port blocked at egress returns a timeout (silent drop).
"""
import socket, threading, time


def part_a():
    print("== A. Import and socket creation ==")
    for typ, proto, label in [(socket.SOCK_STREAM, 0, "TCP"),
                              (socket.SOCK_DGRAM, 0, "UDP"),
                              (socket.SOCK_RAW, socket.IPPROTO_ICMP, "RAW/ICMP")]:
        try:
            s = socket.socket(socket.AF_INET, typ, proto)
            s.close()
            print(f"  socket {label} -> created")
        except Exception as e:
            print(f"  socket {label} -> {type(e).__name__} (e.g. CAP_NET_RAW missing)")


def part_b():
    print("\n== B. Full loopback exchange ==")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        c, _ = srv.accept()
        c.sendall(b"PONG:" + c.recv(1024))
        c.close()

    t = threading.Thread(target=serve)
    t.start()
    cli = socket.create_connection(("127.0.0.1", port), timeout=5)
    cli.sendall(b"PING")
    resp = cli.recv(1024)
    cli.close()
    t.join()
    srv.close()
    print(f"  TCP loopback -> {resp}  (bind, listen, accept, connect, send, recv: OK)")


def tcp_connect(host, port, timeout=8):
    t0 = time.time()
    ip = socket.gethostbyname(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return f"SUCCESS ({(time.time() - t0) * 1000:.0f} ms)"
    except Exception as e:
        return f"{type(e).__name__} ({(time.time() - t0) * 1000:.0f} ms)"
    finally:
        s.close()


def part_c():
    print("\n== C. Differential test (same code, different port) ==")
    for host, port, label in [("example.com", 80, "HTTP allowed"),
                              ("www.google.com", 443, "HTTPS allowed"),
                              ("whois.iana.org", 43, "WHOIS blocked"),
                              ("github.com", 22, "SSH blocked")]:
        print(f"  {label:<16} -> {tcp_connect(host, port)}")


def part_d():
    print("\n== D. Nature of the failure (immediate RST vs timeout) ==")

    def classify(host, port, timeout=5):
        ip = socket.gethostbyname(host)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        try:
            s.connect((ip, port))
            return "connected"
        except ConnectionRefusedError:
            return f"REFUSED/immediate RST ({(time.time() - t0) * 1000:.0f} ms) = active rejection"
        except socket.timeout:
            return f"TIMEOUT ({(time.time() - t0) * 1000:.0f} ms) = silent drop (firewall)"
        except Exception as e:
            return type(e).__name__
        finally:
            s.close()

    print(f"  127.0.0.1:9 (closed)    -> {classify('127.0.0.1', 9, 3)}")
    print(f"  whois.iana.org:43       -> {classify('whois.iana.org', 43)}")


if __name__ == "__main__":
    part_a()
    part_b()
    part_c()
    part_d()
