#!/usr/bin/env bash
# Live demo for the final presentation. Runs the whole QuantumDrive flow in a
# throwaway folder and pauses before each step (press Enter).
#   ./scripts/demo.sh            pauses between steps
#   DEMO_FAST=1 ./scripts/demo.sh   no pauses (rehearsal, screenshots)
# Steps: server starts; a farm sensor makes signed readings and uploads them over
# the ML-KEM + AES-GCM connection; list; download and verify; tamper with the
# stored copy on the server; download again and watch it get rejected.
# Owner: Shalom.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=$ROOT/build
PORT=${DEMO_PORT:-9555}
ID=field-a-01
WORK=$(mktemp -d /tmp/qd-demo-XXXXXX)
SERVER=
trap 'kill $SERVER 2>/dev/null; rm -rf "$WORK"' EXIT

bold=$(tput bold 2>/dev/null || true); off=$(tput sgr0 2>/dev/null || true)
step() {
  echo
  echo "${bold}== $1${off}"
  if [ -z "${DEMO_FAST:-}" ]; then read -r -p "   (Enter) " _; fi
}

make -s -C "$ROOT" all || exit 1
cd "$WORK"

step "1. Start the server (it makes a fresh ML-KEM-768 key pair for every connection)"
"$BIN/server" "$PORT" server-data > server.log 2>&1 &
SERVER=$!
sleep 0.5
kill -0 $SERVER 2>/dev/null && echo "server running on port $PORT, storing files in server-data/" || { cat server.log; exit 1; }

step "2. Farm sensor $ID: 30 readings, 10 per signed file, uploaded automatically"
"$ROOT/scripts/sensor_upload.sh" "$ID" 30 10 127.0.0.1 "$PORT"

step "3. One reading next to its signature"
LINE=$(head -1 "$(ls sensor-data/$ID/*.csv | head -1)")
echo "reading:   $LINE   ($(( ${#LINE} + 1 )) bytes)"
echo "signature: 3309 bytes (ML-DSA-65), about $(( 3309 / (${#LINE} + 1) )) times the reading"

step "4. List what the server holds"
echo list | "$BIN/client" "$ID" 127.0.0.1 "$PORT"

FILE=$(basename "$(ls sensor-data/$ID/*.csv | head -1)")
step "5. Download $FILE and check its ML-DSA-65 signature"
echo "download $ID $FILE" | "$BIN/client" "$ID" 127.0.0.1 "$PORT"

step "6. Attacker changes one byte of the stored copy on the server"
STORED=$(grep -l "$FILE" server-data/qd-*/meta | head -1)
DATA=$(dirname "$STORED")/data
echo "before: $(head -1 "$DATA")"
printf '9' | dd of="$DATA" bs=1 seek=25 conv=notrunc status=none
echo "after:  $(head -1 "$DATA")"

step "7. Download again: the hash no longer matches the signed record"
rm -rf client-data
echo "download $ID $FILE" | "$BIN/client" "$ID" 127.0.0.1 "$PORT"
ls client-data/"$FILE" 2>/dev/null && echo "(file was saved)" || echo "(nothing saved: tampered file rejected)"

echo
echo "${bold}Demo finished.${off}"
