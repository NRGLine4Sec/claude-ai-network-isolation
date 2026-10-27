#!/usr/bin/env bash
# Probe 02: hostname block + TLS interception.
# Characterization, benign targets.
#
# 1) Hostname block: observe the x-block-reason header returned by the gateway.
#    A known-blocked host (web.archive.org) and a control host (archive.org) are
#    used. The block is OBSERVED, not bypassed: the request is blocked, as
#    expected.
# 2) TLS interception: the issuer of the certificate presented for a benign host
#    reveals whether the gateway terminates TLS (MITM with its own CA).
set -u

echo "== 1. Hostname block (observing x-block-reason) =="
echo "-- control host (expected: HTTP 200 or a normal response) --"
curl -sS -m 15 -o /dev/null -w "  archive.org -> HTTP %{http_code} in %{time_total}s\n" \
  "https://archive.org/" 2>&1 || true

echo "-- known-blocked host (expected: 403 + x-block-reason: hostname_blocked) --"
curl -sS -m 15 -D - -o /dev/null "https://web.archive.org/" 2>&1 \
  | grep -iE "HTTP/|x-block-reason|blocked" | sed 's/^/  /' || true

echo
echo "== 2. TLS interception (certificate issuer for a benign host) =="
for host in www.google.com cloudflare-dns.com; do
  echo "-- $host --"
  echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null \
    | openssl x509 -noout -issuer 2>/dev/null | sed 's/^/  /' \
    || echo "  (handshake unavailable)"
done
echo
echo "Note: an issuer such as 'O = Anthropic, CN = Egress Gateway ...' indicates"
echo "TLS termination by the gateway (traffic is decrypted and inspected)."
