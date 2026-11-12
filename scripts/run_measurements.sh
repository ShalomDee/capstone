#!/usr/bin/env bash
# Runs every QuantumDrive timing and byte measurement in one sitting, on one
# machine, so all numbers in the results are comparable.
#   make measure            (or: ./scripts/run_measurements.sh)
# Does QD_RUNS complete runs (default 3) back to back, so the summary can show
# how much the numbers move between runs.
# Raw output:  bench/results/<date-time>/   one folder per run (not committed)
# Summary:     docs/results/results-<env>.md and docs/results/figures/<env>/
# Keep conditions the same for a whole sitting: laptop plugged in, other apps closed.
# Owner: Shalom.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
B=$ROOT/build
RUNS=${QD_RUNS:-3}
PORT=${QD_PORT:-9440}
ID=field-a-01
SERVER=
WORK=
trap 'kill $SERVER 2>/dev/null || true; [ -n "$WORK" ] && rm -rf "$WORK"' EXIT

environment() {
  echo "date: $(date -Is)"
  echo "kernel: $(uname -sr)"
  grep -m1 "model name" /proc/cpuinfo | sed 's/.*: /cpu: /'
  echo "logical cpus: $(nproc)"
  grep -h PRETTY_NAME /etc/os-release | sed 's/PRETTY_NAME=/os: /'
  grep -qi microsoft /proc/version && echo "environment: WSL2" || true
  [ -n "${CODESPACES:-}" ] && echo "environment: GitHub Codespaces" || true
  [ -f /.dockerenv ] && echo "environment: Docker container" || true
  echo "liboqs: $(grep -h OQS_VERSION_TEXT /usr/local/include/oqs/oqsconfig.h | cut -d'"' -f2)"
  echo "openssl: $(openssl version)"
  echo "gcc: $(gcc -dumpfullversion)"
  echo "git: $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)$(git diff --quiet || echo ' (uncommitted changes)')"
  grep -q "^/\* STUB" common/securenet.c && echo "securenet: STUB (network numbers are not real)" || echo "securenet: real (Carvin's code)"
}

one_run() {
  local OUT=$1
  mkdir -p "$OUT"
  WORK=$(mktemp -d /tmp/qd-measure-XXXXXX)
  environment > "$OUT/environment.txt"

  echo "  liboqs operations, 1000 runs each"
  "$B/time_pqc" 1000 > "$OUT/time_pqc.txt"
  echo "  id_sign / id_verify through our code, 1000 runs"
  "$B/time_sign" 1000 > "$OUT/time_sign.txt"

  echo "  sensor CPU time and memory: 1000 readings, batch 1 / 10 / 100, 11 runs each"
  cd "$WORK"
  echo "batch,run,label,value,unit" > "$OUT/sensor_cpu.csv"
  for batch in 1 10 100; do
    for run in $(seq 1 11); do
      rm -rf cpu-data
      "$B/sensor" $ID 1000 $batch cpu-data | grep '^BENCH' | cut -d, -f2- | sed "s/^/$batch,$run,/" >> "$OUT/sensor_cpu.csv"
    done
  done
  rm -rf cpu-data

  echo "  sensor files for the network run: 100 readings, batch 1 / 10 / 100"
  for batch in 1 10 100; do
    "$B/sensor" $ID 100 $batch "batch-$batch" > "$OUT/sensor_sizes_batch$batch.txt"
  done

  echo "  network: handshake, uploads and sensor files over the real encrypted connection"
  "$B/server" "$PORT" "$WORK/store" > "$OUT/server.log" 2>&1 &
  SERVER=$!
  sleep 0.5
  "$B/net_measure" 127.0.0.1 "$PORT" "$OUT/net.csv" $ID \
    "$WORK/batch-1" "$WORK/batch-10" "$WORK/batch-100" 2> "$OUT/net.txt"
  kill $SERVER; wait $SERVER 2>/dev/null || true; SERVER=
  cd "$ROOT"
  rm -rf "$WORK"; WORK=
}

make -s all
environment
echo "== warm-up (not recorded): lets the CPU reach its normal speed before timing"
"$B/time_pqc" 3000 > /dev/null

DIRS=()
for i in $(seq 1 "$RUNS"); do
  OUT=$ROOT/bench/results/$(date +%Y-%m-%d-%H%M%S)-run$i
  echo "== run $i of $RUNS -> $OUT"
  one_run "$OUT"
  DIRS+=("$OUT")
done

echo "== summary"
python3 bench/report.py "${DIRS[@]}"
