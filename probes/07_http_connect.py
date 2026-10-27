#!/usr/bin/env python3
"""
Probe 07: CONNECT tunnel (HTTP/1.1 and HTTP/2).
Characterization. Ask the gateway to open a CONNECT tunnel and observe its reply.
A serious filtering proxy refuses CONNECT, even to an allowed host, because a
tunnel would be an opaque, non-inspectable stream.

An ALLOWED target (example.com) is tested explicitly to show that it is the method
that is refused, not the destination.
"""
import socket, ssl


def http11_connect(via_host, target):
    ctx = ssl.create_default_context()
    try:
        ip = socket.gethostbyname(via_host)
        raw = socket.create_connection((ip, 443), timeout=10)
        tls = ctx.wrap_socket(raw, server_hostname=via_host)
        tls.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        tls.settimeout(6)
        line = tls.recv(200).decode("latin1").split("\r\n")[0]
        tls.close()
        return line
    except Exception as e:
        return f"{type(e).__name__}: {str(e)[:60]}"


def http2_connect(via_host, authority):
    try:
        import h2.connection, h2.config
    except ImportError:
        return "h2 not installed (pip install h2)"
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        ip = socket.gethostbyname(via_host)
        raw = socket.create_connection((ip, 443), timeout=10)
        tls = ctx.wrap_socket(raw, server_hostname=via_host)
        if tls.selected_alpn_protocol() != "h2":
            tls.close()
            return f"ALPN = {tls.selected_alpn_protocol()} (no h2)"
        conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
        conn.initiate_connection()
        tls.sendall(conn.data_to_send())
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [(":method", "CONNECT"), (":authority", authority)], end_stream=False)
        tls.sendall(conn.data_to_send())
        tls.settimeout(6)
        status = reset = None
        for _ in range(5):
            data = tls.recv(4096)
            if not data:
                break
            for ev in conn.receive_data(data):
                n = type(ev).__name__
                if n == "ResponseReceived":
                    status = dict(ev.headers).get(b":status", b"?").decode()
                elif n == "StreamReset":
                    reset = ev.error_code
            if status or reset is not None:
                break
            tls.sendall(conn.data_to_send())
        tls.close()
        if status:
            return f":status {status}"
        if reset is not None:
            return f"RST_STREAM code {reset}"
        return "no usable response"
    except Exception as e:
        return f"{type(e).__name__}: {str(e)[:60]}"


if __name__ == "__main__":
    print("== CONNECT over HTTP/1.1 (via a benign host) ==")
    print(f"  CONNECT web.archive.org:443 (blocked)  -> {http11_connect('www.google.com', 'web.archive.org:443')}")
    print(f"  CONNECT example.com:443 (ALLOWED)      -> {http11_connect('www.google.com', 'example.com:443')}")
    print("\n== CONNECT over HTTP/2 ==")
    print(f"  h2 CONNECT web.archive.org:443         -> {http2_connect('www.google.com', 'web.archive.org:443')}")
    print("\nNote: a 403 even to the allowed host shows that it is the METHOD that is")
    print("refused, not the destination. No opaque tunnel is tolerated.")
