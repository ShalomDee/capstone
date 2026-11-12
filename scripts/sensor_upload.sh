#!/usr/bin/env bash
# Farm sensor with automatic upload: makes <count> readings in signed files of
# <batch> readings, then registers the sensor and uploads every file to the
# server over the encrypted connection. Needs a running server.
#   ./scripts/sensor_upload.sh <id> [count] [batch] [host] [port]
# Example:  ./build/server 9000 server-data &      then
#           ./scripts/sensor_upload.sh field-a-01 30 10
# Run from the folder that holds keys/ for this sensor (default: repo root).
# Owner: Shalom.
set -euo pipefail
BIN=$(cd "$(dirname "$0")/../build" && pwd)
ID=${1:?usage: sensor_upload.sh <id> [count] [batch] [host] [port]}
COUNT=${2:-30}
BATCH=${3:-10}
HOST=${4:-127.0.0.1}
PORT=${5:-9000}
DIR=sensor-data/$ID

rm -rf "$DIR"
mkdir -p sensor-data
"$BIN/sensor" "$ID" "$COUNT" "$BATCH" "$DIR" | sed -n '/^sensor /,$p' | grep -v '^BENCH'

FILES=$(ls "$DIR"/*.csv | sort)
{
  echo register
  for f in $FILES; do echo "upload $f"; done
} | "$BIN/client" "$ID" "$HOST" "$PORT"
echo "sensor $ID: $(echo "$FILES" | wc -l) file(s) uploaded automatically"
