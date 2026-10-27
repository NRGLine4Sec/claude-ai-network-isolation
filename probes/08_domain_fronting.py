#!/usr/bin/env python3
"""
Probe 08: proxy routing basis (SNI vs Host header).
Characterization, TWO allowed hosts only (no blocked target).

Open a TLS session with SNI=A and send a request with Host=B, both allowed, then
observe which one answers. This reveals whether the proxy routes on the SNI or on
the decrypted Host header, without ever targeting a blocked host.
Implication: if routing follows the Host, SNI-based domain fronting is
structurally ineffective here.
"""
import socket, ssl


def front(sni_host, host_header):
    ctx = ssl.create_default_context()
    try:
        ip = socket.gethostbyname(sni_host)
        raw = socket.create_connection((ip, 443), timeout=10)
        tls = ctx.wrap_socket(raw, server_hostname=sni_host)
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode())
        tls.settimeout(8)
        buf = b""
        while len(buf) < 1500:
            d = tls.recv(1500)
            if not d:
                break
            buf += d
        tls.close()
        head = buf.decode("latin1", "replace")
        status = head.split("\r\n")[0]
        server = next((l for l in head.split("\r\n") if l.lower().startswith("server:")), "")
        low = head.lower()
        marker = "example" if "example domain" in low else ("google" if "google" in low else "?")
        return f"{status} | {server} | content~{marker}"
    except Exception as e:
        return f"{type(e).__name__}: {str(e)[:50]}"


if __name__ == "__main__":
    print("== Routing: SNI vs Host header (two allowed hosts) ==")
    print("  SNI=www.google.com, Host=example.com ->", front("www.google.com", "example.com"))
    print("  SNI=example.com, Host=www.google.com ->", front("example.com", "www.google.com"))
    print("\nIf the returned content follows the Host (not the SNI), routing and")
    print("filtering are on the decrypted Host header: SNI fronting is pointless.")
