#!/usr/bin/env python3
"""
Probe 06: WebSocket, STUN, TURN, WebRTC.
Characterization, benign targets.

  - WebSocket: Upgrade over TLS:443 to a public echo server.
  - STUN: Binding Request over UDP to public STUN servers.
  - TURN: connect to the relay ports and test TURN-over-TLS:443.
  - WebRTC: ICE candidate gathering via aiortc (shows whether a reflexive/relay
    candidate exists, i.e. a path to an external peer).
"""
import socket, ssl, os, base64, struct


def websocket():
    print("== WebSocket (Upgrade over TLS:443) ==")
    for host, path in [("echo.websocket.org", "/"), ("ws.postman-echo.com", "/raw")]:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n")
        try:
            ip = socket.gethostbyname(host)
            raw = socket.create_connection((ip, 443), timeout=10)
            tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            tls.sendall(req.encode())
            tls.settimeout(8)
            line = tls.recv(200).decode("latin1").split("\r\n")[0]
            tls.close()
            print(f"  {host:<22} -> {line}")
        except Exception as e:
            print(f"  {host:<22} -> {type(e).__name__}")


def stun():
    print("\n== STUN (UDP) ==")
    msg = struct.pack(">HHI", 0x0001, 0x0000, 0x2112A442) + os.urandom(12)
    for host, port in [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        try:
            s.sendto(msg, (socket.gethostbyname(host), port))
            d, _ = s.recvfrom(512)
            print(f"  {host}:{port} -> reply ({len(d)} B): reflexive address obtained")
        except socket.timeout:
            print(f"  {host}:{port} -> SILENCE (UDP blocked, no reflexive address)")
        except Exception as e:
            print(f"  {host}:{port} -> {type(e).__name__}")
        finally:
            s.close()


def turn_over_tls():
    print("\n== TURN-over-TLS:443 ==")
    alloc = struct.pack(">HHI", 0x0003, 0x0000, 0x2112A442) + os.urandom(12)
    host = "openrelay.metered.ca"
    try:
        ip = socket.gethostbyname(host)
        raw = socket.create_connection((ip, 443), timeout=10)
        tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        issuer = dict(x[0] for x in tls.getpeercert().get("issuer", []))
        tls.sendall(alloc)
        tls.settimeout(6)
        resp = tls.recv(120)
        tls.close()
        head = resp.split(b"\r\n")[0].decode("latin1") if b"HTTP" in resp else repr(resp[:32])
        print(f"  cert issued by {issuer.get('organizationName')} ; Allocate reply: {head}")
    except Exception as e:
        print(f"  {type(e).__name__}: {str(e)[:60]}")


def webrtc():
    print("\n== WebRTC: ICE candidate gathering ==")
    try:
        import asyncio
        from aiortc import RTCPeerConnection, RTCConfiguration, RTCIceServer
    except ImportError:
        print("  aiortc not installed (pip install aiortc) — step skipped")
        return

    async def gather():
        cfg = RTCConfiguration(iceServers=[RTCIceServer(urls="stun:stun.l.google.com:19302")])
        pc = RTCPeerConnection(configuration=cfg)
        pc.createDataChannel("probe")
        await pc.setLocalDescription(await pc.createOffer())
        cands = [l for l in pc.localDescription.sdp.splitlines() if l.startswith("a=candidate")]
        types = set()
        for c in cands:
            parts = c.split()
            typ = parts[parts.index("typ") + 1] if "typ" in parts else "?"
            types.add(typ)
            print(f"  candidate: typ={typ} addr={parts[4] if len(parts) > 4 else '?'}")
        print(f"  reflexive (srflx) present? {'YES' if 'srflx' in types else 'NO'}")
        print(f"  relay present?             {'YES' if 'relay' in types else 'NO'}")
        await pc.close()

    try:
        asyncio.run(asyncio.wait_for(gather(), timeout=60))
    except Exception as e:
        print(f"  {type(e).__name__}: {str(e)[:80]}")


if __name__ == "__main__":
    websocket()
    stun()
    turn_over_tls()
    webrtc()
