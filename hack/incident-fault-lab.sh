#!/usr/bin/env bash
set -Eeuo pipefail

ACTION="${1:-run}"

COROOT_URL="${COROOT_URL:-http://127.0.0.1:8080}"
COROOT_COOKIE_FILE="${COROOT_COOKIE_FILE:-/tmp/coroot-ee.cookie}"
PROJECT_ID="${PROJECT_ID:-}"
NETWORK="${NETWORK:-coroot_default}"
IMAGE="${IMAGE:-python:3.12-alpine}"

SERVER_NAME="${SERVER_NAME:-coroot-incident-bad-api}"
LOADGEN_NAME="${LOADGEN_NAME:-coroot-incident-loadgen}"
CPU_NAME="${CPU_NAME:-coroot-incident-cpu-hog}"

ERROR_RATE="${ERROR_RATE:-100}"
DELAY_MS="${DELAY_MS:-750}"
WORKERS="${WORKERS:-32}"
REQUEST_PATH="${REQUEST_PATH:-/checkout}"
WAIT_SECONDS="${WAIT_SECONDS:-720}"
POLL_SECONDS="${POLL_SECONDS:-15}"

usage() {
  cat <<EOF
Usage:
  bash hack/incident-fault-lab.sh [run|start|wait|status|logs|stop|restart]

Actions:
  run      Start the fault workload and wait until Coroot opens an incident.
  start    Start the fault workload only.
  wait     Poll Coroot until an incident appears for the fault workload.
  status   Show workload containers plus Coroot app/incident status.
  logs     Tail workload container logs.
  stop     Remove workload containers.
  restart  stop + start.

Useful env vars:
  COROOT_URL=http://127.0.0.1:8080
  PROJECT_ID=3wgteurw              # auto-detected when omitted
  NETWORK=coroot_default
  IMAGE=python:3.12-alpine
  ERROR_RATE=100                   # 0..100 HTTP 500 percentage
  DELAY_MS=750                     # server-side delay per request
  WORKERS=32                       # load generator worker threads
  WAIT_SECONDS=720
  POLL_SECONDS=15

Cleanup:
  bash hack/incident-fault-lab.sh stop
EOF
}

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

ensure_tools() {
  need_cmd docker
  need_cmd curl
  need_cmd python3
}

curl_json() {
  if [[ -f "$COROOT_COOKIE_FILE" ]]; then
    curl -fsS -b "$COROOT_COOKIE_FILE" "$1"
  else
    curl -fsS "$1"
  fi
}

detect_project_id() {
  if [[ -n "$PROJECT_ID" ]]; then
    printf '%s' "$PROJECT_ID"
    return
  fi
  curl_json "$COROOT_URL/api/user" | python3 -c '
import json, sys
data = json.load(sys.stdin)
projects = data.get("projects") or []
if not projects:
    raise SystemExit("no Coroot project found")
print(projects[0]["id"], end="")
'
}

ensure_coroot() {
  curl_json "$COROOT_URL/api/user" >/dev/null
}

ensure_network() {
  docker network inspect "$NETWORK" >/dev/null 2>&1 || {
    echo "docker network not found: $NETWORK" >&2
    echo "Start Coroot compose first, or set NETWORK=<compose_network>." >&2
    exit 1
  }
}

ensure_image() {
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    return
  fi
  log "pulling $IMAGE"
  docker pull "$IMAGE"
}

remove_container() {
  local name="$1"
  docker rm -f "$name" >/dev/null 2>&1 || true
}

stop_lab() {
  log "removing lab containers"
  remove_container "$LOADGEN_NAME"
  remove_container "$SERVER_NAME"
  remove_container "$CPU_NAME"
}

server_py() {
  cat <<'PY'
import http.server
import json
import os
import random
import socketserver
import sys
import time

error_rate = max(0, min(100, int(os.environ.get("ERROR_RATE", "100"))))
delay_ms = max(0, int(os.environ.get("DELAY_MS", "750")))
port = int(os.environ.get("PORT", "8080"))

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write("%s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), fmt % args))
        sys.stdout.flush()

    def send_payload(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/health"):
            self.send_payload(200, {"ok": True})
            return
        if delay_ms:
            time.sleep(delay_ms / 1000.0)
        fail = random.randint(1, 100) <= error_rate
        if fail:
            sys.stderr.write("ERROR recommendation cache unavailable: dial tcp 10.13.37.42:6379: connect: connection refused path=%s\n" % self.path)
            sys.stderr.flush()
            self.send_payload(500, {"ok": False, "error": "recommendation cache unavailable"})
            return
        self.send_payload(200, {"ok": True})

class ReuseTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

print("bad api listening on :%d error_rate=%d delay_ms=%d" % (port, error_rate, delay_ms), flush=True)
with ReuseTCPServer(("", port), Handler) as httpd:
    httpd.serve_forever()
PY
}

loadgen_py() {
  cat <<'PY'
import os
import random
import threading
import time
import urllib.error
import urllib.request

target = os.environ["TARGET"].rstrip("/")
path = os.environ.get("REQUEST_PATH", "/checkout")
workers = int(os.environ.get("WORKERS", "32"))
timeout = float(os.environ.get("TIMEOUT", "3"))

counts = {"ok": 0, "err": 0}
lock = threading.Lock()

def worker(worker_id):
    n = 0
    while True:
        n += 1
        url = "%s%s?worker=%d&n=%d&trace=%d" % (target, path, worker_id, n, random.randint(1, 999999))
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                resp.read(64)
                key = "ok" if resp.status < 500 else "err"
        except urllib.error.HTTPError as e:
            key = "err" if e.code >= 500 else "ok"
        except Exception:
            key = "err"
        with lock:
            counts[key] += 1

for i in range(workers):
    threading.Thread(target=worker, args=(i,), daemon=True).start()

print("loadgen started target=%s workers=%d path=%s" % (target, workers, path), flush=True)
last_ok = last_err = 0
while True:
    time.sleep(10)
    with lock:
        ok = counts["ok"]
        err = counts["err"]
    print("loadgen totals ok=%d err=%d rate_ok=%d/10s rate_err=%d/10s" % (ok, err, ok - last_ok, err - last_err), flush=True)
    last_ok, last_err = ok, err
PY
}

cpu_py() {
  cat <<'PY'
import math
import os
import threading
import time

workers = int(os.environ.get("CPU_WORKERS", "2"))

def burn(idx):
    x = 0.001 + idx
    while True:
        x = math.sin(x) * math.cos(x) + math.sqrt(abs(x) + 1.0)

for i in range(workers):
    threading.Thread(target=burn, args=(i,), daemon=True).start()

print("cpu hog started workers=%d" % workers, flush=True)
while True:
    time.sleep(60)
PY
}

start_lab() {
  ensure_tools
  ensure_coroot
  ensure_network
  ensure_image

  log "cleaning previous lab containers"
  stop_lab

  log "starting $SERVER_NAME"
  docker run -d \
    --name "$SERVER_NAME" \
    --hostname "$SERVER_NAME" \
    --network "$NETWORK" \
    --label "coroot.incident-lab=true" \
    --label "coroot.incident-lab.role=bad-api" \
    -e ERROR_RATE="$ERROR_RATE" \
    -e DELAY_MS="$DELAY_MS" \
    -e PORT=8080 \
    "$IMAGE" python -u -c "$(server_py)" >/dev/null

  log "waiting for bad api health"
  for _ in $(seq 1 60); do
    if docker run --rm --network "$NETWORK" "$IMAGE" python -c "import urllib.request; urllib.request.urlopen('http://$SERVER_NAME:8080/health', timeout=2).read()" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  log "starting $LOADGEN_NAME"
  docker run -d \
    --name "$LOADGEN_NAME" \
    --hostname "$LOADGEN_NAME" \
    --network "$NETWORK" \
    --label "coroot.incident-lab=true" \
    --label "coroot.incident-lab.role=loadgen" \
    -e TARGET="http://$SERVER_NAME:8080" \
    -e REQUEST_PATH="$REQUEST_PATH" \
    -e WORKERS="$WORKERS" \
    "$IMAGE" python -u -c "$(loadgen_py)" >/dev/null

  log "starting $CPU_NAME"
  docker run -d \
    --name "$CPU_NAME" \
    --hostname "$CPU_NAME" \
    --network "$NETWORK" \
    --label "coroot.incident-lab=true" \
    --label "coroot.incident-lab.role=cpu" \
    -e CPU_WORKERS="${CPU_WORKERS:-2}" \
    "$IMAGE" python -u -c "$(cpu_py)" >/dev/null

  log "fault workload is running"
  docker ps --filter "label=coroot.incident-lab=true" --format '  {{.Names}}\t{{.Status}}\t{{.Image}}'
}

print_app_status() {
  local project_id="$1"
  curl_json "$COROOT_URL/api/project/$project_id/overview/applications" | python3 -c '
import json, sys
names = set(sys.argv[1:])
data = json.load(sys.stdin)
apps = (data.get("data") or {}).get("applications") or []
for app in apps:
    app_id = app.get("id", "")
    if any(name in app_id for name in names):
        print("  app=%s status=%s errors=%s latency=%s logs=%s" % (
            app_id,
            app.get("status", ""),
            (app.get("errors") or {}).get("value", ""),
            (app.get("latency") or {}).get("value", ""),
            (app.get("logs") or {}).get("value", ""),
        ))
' "$SERVER_NAME" "$LOADGEN_NAME" "$CPU_NAME"
}

find_incidents() {
  local project_id="$1"
  curl_json "$COROOT_URL/api/project/$project_id/incidents?limit=100" | python3 -c '
import json, sys
names = sys.argv[1:]
data = json.load(sys.stdin)
incidents = data.get("data") or []
matches = []
for incident in incidents:
    app_id = str(incident.get("application_id", ""))
    if any(name in app_id for name in names):
        matches.append(incident)
print(len(matches))
for incident in matches:
    print("%s\t%s\t%s\timpact=%.2f\t%s" % (
        incident.get("key", ""),
        incident.get("severity", ""),
        incident.get("application_id", ""),
        float(incident.get("impact") or 0),
        incident.get("short_description", ""),
    ))
' "$SERVER_NAME" "$LOADGEN_NAME" "$CPU_NAME"
}

status_lab() {
  ensure_tools
  ensure_coroot
  local project_id
  project_id="$(detect_project_id)"
  log "Coroot project: $project_id"
  log "Docker lab containers:"
  docker ps -a --filter "label=coroot.incident-lab=true" --format '  {{.Names}}\t{{.Status}}\t{{.Image}}' || true
  log "Coroot applications:"
  print_app_status "$project_id" || true
  log "Coroot incidents:"
  find_incidents "$project_id" || true
}

wait_for_incident() {
  ensure_tools
  ensure_coroot
  local project_id
  project_id="$(detect_project_id)"
  log "waiting for incident in project=$project_id timeout=${WAIT_SECONDS}s"
  log "Coroot opens SLO incidents after the 5m short burn-rate window has enough samples."

  local deadline
  deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    log "checking applications"
    print_app_status "$project_id" || true

    local found
    found="$(find_incidents "$project_id" || true)"
    local count
    count="$(printf '%s\n' "$found" | sed -n '1p')"
    if [[ "${count:-0}" =~ ^[0-9]+$ ]] && (( count > 0 )); then
      log "incident detected"
      printf '%s\n' "$found" | sed '1d'
      log "open: $COROOT_URL/p/$project_id/incidents"
      return 0
    fi
    log "no incident yet; sleeping ${POLL_SECONDS}s"
    sleep "$POLL_SECONDS"
  done

  echo "timed out waiting for incident" >&2
  echo "Try increasing WAIT_SECONDS or keeping the workload running longer." >&2
  return 1
}

logs_lab() {
  ensure_tools
  for name in "$SERVER_NAME" "$LOADGEN_NAME" "$CPU_NAME"; do
    echo "===== $name ====="
    docker logs --tail=80 "$name" 2>/dev/null || true
  done
}

case "$ACTION" in
  run)
    start_lab
    wait_for_incident
    ;;
  start)
    start_lab
    ;;
  wait)
    wait_for_incident
    ;;
  status)
    status_lab
    ;;
  logs)
    logs_lab
    ;;
  stop)
    ensure_tools
    stop_lab
    ;;
  restart)
    ensure_tools
    stop_lab
    start_lab
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
