#!/usr/bin/env bash
# Runs all probes in sequence and writes timestamped output to probes/out/.
# Benign-target characterization only.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
mkdir -p "$OUT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$OUT/report-$STAMP.txt"

run() {
  local title="$1"; shift
  echo "############################################################"
  echo "# $title"
  echo "############################################################"
  "$@" 2>&1 || echo "[probe interrupted: $?]"
  echo
}

{
  echo "Network characterization — $STAMP"
  echo "Environment: $(uname -a)"
  echo

  run "01 — Port allowlist"                   python3 "$HERE/01_egress_ports.py"
  run "02 — Hostname and TLS interception"    bash    "$HERE/02_hostname_and_tls.sh"
  run "03 — DNS interception"                 python3 "$HERE/03_dns_interception.py"
  run "04 — ICMP and topology"                python3 "$HERE/04_icmp_topology.py"
  run "05 — Tunneling protocols"              python3 "$HERE/05_tunnels.py"
  run "06 — WebSocket / STUN / TURN / WebRTC" python3 "$HERE/06_ws_stun_turn_webrtc.py"
  run "07 — CONNECT tunnel"                   python3 "$HERE/07_http_connect.py"
  run "08 — Domain fronting (routing)"        python3 "$HERE/08_domain_fronting.py"
  run "09 — Egress identity"                  bash    "$HERE/09_egress_identity.sh"
  run "10 — Instrument validation"            python3 "$HERE/10_instrument_validation.py"
} | tee "$REPORT"

echo "Report written to: $REPORT"
