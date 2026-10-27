#!/usr/bin/env bash
# Probe 09: egress identity.
# Characterization, benign targets.
#
# 1) Sandbox egress IP (via a public echo service), with ASN/org.
# 2) Comparison to Anthropic's published crawler IP list.
# 3) Comparison to Google Cloud ranges published by Google.
# Goal: verify egress comes from declared datacenter IPs, not a residential proxy
# network.
set -u

echo "== 1. Egress IP (ipinfo) =="
curl -sS -m 20 "https://ipinfo.io/json" 2>/dev/null | sed 's/^/  /' || echo "  (unavailable)"

echo
echo "== 2. Anthropic's official crawler IP list =="
echo "   (source: https://claude.com/crawling/bots.json)"
curl -sS -m 20 "https://claude.com/crawling/bots.json" 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('  published prefixes:', len(d.get('prefixes',[]))); print('  created', d.get('creationTime'))" \
  2>/dev/null || echo "  (unavailable)"

echo
echo "== 3. Classifying the published prefixes against Google Cloud ranges =="
python3 - <<'PY' 2>/dev/null || echo "  (unavailable)"
import json, ipaddress, urllib.request
def get(u):
    r = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
    return json.loads(urllib.request.urlopen(r, timeout=30).read())
try:
    anth = get("https://claude.com/crawling/bots.json")
    goog = get("https://www.gstatic.com/ipranges/cloud.json")
    gnets = [ipaddress.ip_network(p["ipv4Prefix"]) for p in goog["prefixes"] if "ipv4Prefix" in p]
    cloud = other = 0
    for p in anth["prefixes"]:
        net = ipaddress.ip_network(p["ipv4Prefix"])
        if any(net.subnet_of(g) for g in gnets):
            cloud += 1
        else:
            other += 1
            print("  not Google Cloud:", p["ipv4Prefix"])
    print(f"  Google Cloud: {cloud} | other: {other} | total: {cloud + other}")
    print("  (the 'other' entries are typically an Anthropic-owned AWS block;")
    print("   no consumer / residential range expected)")
except Exception as e:
    print("  error:", e)
PY
