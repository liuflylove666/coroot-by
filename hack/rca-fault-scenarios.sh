#!/usr/bin/env bash
set -Eeuo pipefail

ACTION="${1:-run}"

COROOT_URL="${COROOT_URL:-http://127.0.0.1:8080}"
PROJECT_ID="${PROJECT_ID:-}"
NETWORK="${NETWORK:-coroot_default}"
IMAGE="${IMAGE:-python:3.12-alpine}"
SCENARIO="${SCENARIO:-db-query}"
PREFIX="${PREFIX:-coroot-rca}"

WORKERS="${WORKERS:-24}"
WAIT_SECONDS="${WAIT_SECONDS:-720}"
POLL_SECONDS="${POLL_SECONDS:-15}"
DB_DELAY_MS="${DB_DELAY_MS:-850}"
CATALOG_QUERIES="${CATALOG_QUERIES:-18}"
ERROR_RATE="${ERROR_RATE:-35}"
CPU_WORKERS="${CPU_WORKERS:-4}"
EXPECTED_INCIDENTS="${EXPECTED_INCIDENTS:-}"
OFFICIAL_NETWORK_NAMES="${OFFICIAL_NETWORK_NAMES:-true}"

usage() {
  cat <<EOF
Usage:
  bash hack/rca-fault-scenarios.sh [run|start|wait|status|logs|stop|restart]

Scenarios:
  SCENARIO=db-query        Front-end errors caused by catalog rollout/query amplification against db-main.
  SCENARIO=network-chaos   Front-end errors caused by injected network delay between catalog and db-main.
  SCENARIO=cpu-saturation  Front-end/catalog/db-main latency caused by analytics-updater CPU saturation.
  SCENARIO=all             Start all three scenarios.

Examples:
  bash hack/rca-fault-scenarios.sh run
  SCENARIO=network-chaos bash hack/rca-fault-scenarios.sh start
  SCENARIO=cpu-saturation WAIT_SECONDS=900 bash hack/rca-fault-scenarios.sh run

Useful env vars:
  COROOT_URL=http://127.0.0.1:8080
  PROJECT_ID=3wgteurw
  NETWORK=coroot_default
  IMAGE=python:3.12-alpine
  WORKERS=24
  DB_DELAY_MS=850
  CATALOG_QUERIES=18
  ERROR_RATE=35
  CPU_WORKERS=4
  OFFICIAL_NETWORK_NAMES=true
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
  curl -fsS "$1"
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
  curl -fsS "$COROOT_URL/api/user" >/dev/null
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

scenario_list() {
  case "$SCENARIO" in
    all) printf '%s\n' db-query network-chaos cpu-saturation ;;
    db-query|network-chaos|cpu-saturation) printf '%s\n' "$SCENARIO" ;;
    *)
      echo "unknown SCENARIO=$SCENARIO" >&2
      usage
      exit 1
      ;;
  esac
}

expected_incidents() {
  if [[ -n "$EXPECTED_INCIDENTS" ]]; then
    printf '%s' "$EXPECTED_INCIDENTS"
    return
  fi
  scenario_list | wc -l | tr -d ' '
}

scenario_slug() {
  printf '%s' "$1" | tr '_' '-'
}

scenario_prefix() {
  printf '%s-%s' "$PREFIX" "$(scenario_slug "$1")"
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
import urllib.error
import urllib.request

role = os.environ["ROLE"]
scenario = os.environ["SCENARIO"]
port = int(os.environ.get("PORT", "8080"))
target = os.environ.get("TARGET", "").rstrip("/")
order_target = os.environ.get("ORDER_TARGET", "").rstrip("/")
kafka_target = os.environ.get("KAFKA_TARGET", "").rstrip("/")
cache_target = os.environ.get("CACHE_TARGET", "").rstrip("/")
cart_target = os.environ.get("CART_TARGET", "").rstrip("/")
db_delay_ms = max(0, int(os.environ.get("DB_DELAY_MS", "850")))
catalog_queries = max(1, int(os.environ.get("CATALOG_QUERIES", "18")))
error_rate = max(0, min(100, int(os.environ.get("ERROR_RATE", "35"))))
timeout = float(os.environ.get("TIMEOUT", "4"))

def log(line, err=False):
    stream = sys.stderr if err else sys.stdout
    stream.write("%s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), line))
    stream.flush()

def fetch(url):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.status, resp.read(128)

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log(fmt % args)

    def send_payload(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/health"):
            self.send_payload(200, {"ok": True, "role": role, "scenario": scenario})
            return
        if role == "db-main":
            time.sleep(db_delay_ms / 1000.0)
            statement = 'select * from "products" where brand = ?'
            log('postgres query total_time_ms=%d calls=1 rows=743 table_size_mb=105 statement=%s brand=Kamba' % (db_delay_ms, statement))
            self.send_payload(200, {"ok": True, "rows": 743, "statement": statement})
            return
        if role == "catalog":
            started = time.time()
            failures = 0
            for i in range(catalog_queries):
                try:
                    fetch("%s/query?brand=Kamba&i=%d" % (target, i))
                except Exception as e:
                    failures += 1
                    log('ERROR gorm.Query context canceled statement=select * from "products" where brand = ? error=%s' % e, True)
            elapsed_ms = int((time.time() - started) * 1000)
            if scenario == "network-chaos":
                log("NetworkChaos net-delay-catalog-pg-bwpfn injected delay between catalog and db-main target=db-main-0 schedule=net-delay-catalog-pg", True)
            if failures or random.randint(1, 100) <= error_rate or elapsed_ms > 1800:
                log('ERROR catalog request failed status=500 elapsed_ms=%d error=context canceled statement=select * from "products" where brand = ?' % elapsed_ms, True)
                self.send_payload(500, {"ok": False, "error": "context canceled", "elapsed_ms": elapsed_ms})
                return
            self.send_payload(200, {"ok": True, "elapsed_ms": elapsed_ms})
            return
        if role == "order":
            started = time.time()
            try:
                status, _ = fetch("%s/catalog/order/%d" % (target, random.randint(1, 999999)))
                elapsed_ms = int((time.time() - started) * 1000)
                if status >= 500:
                    raise RuntimeError("catalog returned %d" % status)
                if elapsed_ms > 1200:
                    log("WARN order latency from catalog elapsed_ms=%d" % elapsed_ms, True)
                self.send_payload(200, {"ok": True, "elapsed_ms": elapsed_ms})
            except Exception as e:
                log("ERROR order upstream catalog timed out path=/orders error=%s" % e, True)
                self.send_payload(500, {"ok": False, "error": "catalog timeout", "cause": str(e)})
            return
        if role in ("kafka", "cache", "cart"):
            if scenario in ("network-chaos", "cpu-saturation"):
                time.sleep(0.12)
            log("%s request processed path=%s" % (role, self.path))
            self.send_payload(200, {"ok": True})
            return
        if role == "front-end":
            errors = []
            try:
                status, _ = fetch("%s/catalog/brand/Kamba" % target)
                if status >= 500:
                    raise RuntimeError("catalog returned %d" % status)
            except Exception as e:
                errors.append("catalog: %s" % e)
            if order_target:
                try:
                    status, _ = fetch("%s/orders" % order_target)
                    if status >= 500:
                        raise RuntimeError("order returned %d" % status)
                except Exception as e:
                    errors.append("order: %s" % e)
            if kafka_target:
                try:
                    status, _ = fetch("%s/produce" % kafka_target)
                    if status >= 500:
                        raise RuntimeError("kafka returned %d" % status)
                except Exception as e:
                    errors.append("kafka: %s" % e)
            if cache_target:
                try:
                    status, _ = fetch("%s/cache/products" % cache_target)
                    if status >= 500:
                        raise RuntimeError("cache returned %d" % status)
                except Exception as e:
                    errors.append("cache: %s" % e)
            if cart_target:
                try:
                    status, _ = fetch("%s/cart" % cart_target)
                    if status >= 500:
                        raise RuntimeError("cart returned %d" % status)
                except Exception as e:
                    errors.append("cart: %s" % e)
            if errors:
                cause = "; ".join(errors)
                log("ERROR front-end upstream returned 502 path=/catalog/brands error=%s" % cause, True)
                self.send_payload(502, {"ok": False, "error": "bad gateway", "cause": cause})
                return
            self.send_payload(200, {"ok": True})
            return
        self.send_payload(404, {"ok": False, "error": "unknown role"})

class ReuseTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

log("service listening role=%s scenario=%s port=%d target=%s db_delay_ms=%d catalog_queries=%d" % (role, scenario, port, target, db_delay_ms, catalog_queries))
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
workers = int(os.environ.get("WORKERS", "24"))
path = os.environ.get("REQUEST_PATH", "/catalog/brands")
timeout = float(os.environ.get("TIMEOUT", "5"))
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

workers = int(os.environ.get("CPU_WORKERS", "4"))

def burn(idx):
    x = 0.001 + idx
    while True:
        x = math.sin(x) * math.cos(x) + math.sqrt(abs(x) + 1.0)

for i in range(workers):
    threading.Thread(target=burn, args=(i,), daemon=True).start()

print("analytics-updater cpu hog started workers=%d; simulated CronJob scheduled on node3" % workers, flush=True)
while True:
    time.sleep(15)
    print("CronJob analytics-updater running on node3; CPU pressure warning on node3", flush=True)
PY
}

remove_lab() {
  docker rm -f $(docker ps -aq --filter "label=coroot.rca-fault-lab=true") >/dev/null 2>&1 || true
}

remove_scenario() {
  local scenario="$1" ids
  ids="$(docker ps -aq --filter "label=coroot.rca-fault-lab.scenario=$scenario")"
  if [[ -n "$ids" ]]; then
    docker rm -f $ids >/dev/null 2>&1 || true
  fi
}

run_service() {
  local name="$1" role="$2" scenario="$3" target="${4:-}" order_target="${5:-}" kafka_target="${6:-}"
  local cache_target="${7:-}" cart_target="${8:-}"
  docker run -d \
    --name "$name" \
    --hostname "$name" \
    --network "$NETWORK" \
    --label "coroot.rca-fault-lab=true" \
    --label "coroot.rca-fault-lab.scenario=$scenario" \
    --label "coroot.rca-fault-lab.role=$role" \
    -e ROLE="$role" \
    -e SCENARIO="$scenario" \
    -e TARGET="$target" \
    -e ORDER_TARGET="$order_target" \
    -e KAFKA_TARGET="$kafka_target" \
    -e CACHE_TARGET="$cache_target" \
    -e CART_TARGET="$cart_target" \
    -e DB_DELAY_MS="$DB_DELAY_MS" \
    -e CATALOG_QUERIES="$CATALOG_QUERIES" \
    -e ERROR_RATE="$ERROR_RATE" \
    -e PORT=8080 \
    "$IMAGE" python -u -c "$(server_py)" >/dev/null
}

wait_health() {
  local name="$1"
  for _ in $(seq 1 60); do
    if docker run --rm --network "$NETWORK" "$IMAGE" python -c "import urllib.request; urllib.request.urlopen('http://$name:8080/health', timeout=2).read()" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "service did not become healthy: $name" >&2
  return 1
}

start_one() {
  local scenario="$1" base
  base="$(scenario_prefix "$scenario")"
  local front="${base}-front-end"
  local catalog="${base}-catalog"
  local db="${base}-db-main"
  local order="${base}-order"
  local kafka="${base}-kafka"
  local cache="${base}-cache"
  local cart="${base}-cart"
  local loadgen="${base}-loadgen"
  local cpu="${base}-analytics-updater"
  if [[ "$scenario" == "network-chaos" && "$OFFICIAL_NETWORK_NAMES" == "true" ]]; then
    front="front-end"
    catalog="catalog"
    db="db-main"
    order="order"
    loadgen="network-chaos-loadgen"
  fi
  local include_kafka="true"
  if [[ "$scenario" == "network-chaos" && "$OFFICIAL_NETWORK_NAMES" == "true" ]]; then
    include_kafka="false"
  fi

  log "starting scenario=$scenario"
  remove_scenario "$scenario"
  docker rm -f "$front" "$catalog" "$db" "$order" "$kafka" "$cache" "$cart" "$loadgen" "$cpu" >/dev/null 2>&1 || true
  run_service "$db" "db-main" "$scenario"
  wait_health "$db"
  run_service "$catalog" "catalog" "$scenario" "http://$db:8080"
  wait_health "$catalog"
  run_service "$order" "order" "$scenario" "http://$catalog:8080"
  wait_health "$order"
  if [[ "$include_kafka" == "true" ]]; then
    run_service "$kafka" "kafka" "$scenario"
    wait_health "$kafka"
    if [[ "$scenario" == "cpu-saturation" ]]; then
      run_service "$cache" "cache" "$scenario"
      wait_health "$cache"
      run_service "$cart" "cart" "$scenario"
      wait_health "$cart"
      run_service "$front" "front-end" "$scenario" "http://$catalog:8080" "http://$order:8080" "http://$kafka:8080" "http://$cache:8080" "http://$cart:8080"
    else
      run_service "$front" "front-end" "$scenario" "http://$catalog:8080" "http://$order:8080" "http://$kafka:8080"
    fi
  else
    run_service "$front" "front-end" "$scenario" "http://$catalog:8080" "http://$order:8080"
  fi
  wait_health "$front"
  docker run -d \
    --name "$loadgen" \
    --hostname "$loadgen" \
    --network "$NETWORK" \
    --label "coroot.rca-fault-lab=true" \
    --label "coroot.rca-fault-lab.scenario=$scenario" \
    --label "coroot.rca-fault-lab.role=loadgen" \
    -e TARGET="http://$front:8080" \
    -e WORKERS="$WORKERS" \
    "$IMAGE" python -u -c "$(loadgen_py)" >/dev/null
  if [[ "$scenario" == "cpu-saturation" ]]; then
    docker run -d \
      --name "$cpu" \
      --hostname "$cpu" \
      --network "$NETWORK" \
      --label "coroot.rca-fault-lab=true" \
      --label "coroot.rca-fault-lab.scenario=$scenario" \
      --label "coroot.rca-fault-lab.role=analytics-updater" \
      -e CPU_WORKERS="$CPU_WORKERS" \
      "$IMAGE" python -u -c "$(cpu_py)" >/dev/null
  fi
}

start_lab() {
  ensure_tools
  ensure_coroot
  ensure_network
  ensure_image
  for scenario in $(scenario_list); do
    start_one "$scenario"
  done
  docker ps --filter "label=coroot.rca-fault-lab=true" --format '  {{.Names}}\t{{.Status}}\t{{.Image}}'
}

status_lab() {
  ensure_tools
  ensure_coroot
  local project_id
  project_id="$(detect_project_id)"
  log "Coroot project: $project_id"
  log "Fault containers:"
  docker ps -a --filter "label=coroot.rca-fault-lab=true" --format '  {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Labels}}' || true
  log "Matching Coroot applications:"
  curl_json "$COROOT_URL/api/project/$project_id/overview/applications" | SCENARIO="$SCENARIO" OFFICIAL_NETWORK_NAMES="$OFFICIAL_NETWORK_NAMES" python3 -c '
import json, sys
import os
data = json.load(sys.stdin)
apps = (data.get("data") or {}).get("applications") or []
scenario = os.environ.get("SCENARIO", "")
official_network = os.environ.get("OFFICIAL_NETWORK_NAMES", "") == "true"
official_names = ("front-end", "catalog", "order", "kafka", "db-main", "analytics-updater")
def match(app_id):
    if scenario == "network-chaos" and official_network:
        return any((":%s" % n) in app_id for n in official_names)
    if scenario and scenario != "all":
        return "coroot-rca-%s" % scenario in app_id
    return "coroot-rca" in app_id or any((":%s" % n) in app_id for n in official_names)
for app in apps:
    app_id = str(app.get("id", ""))
    if match(app_id):
        print("  app=%s status=%s" % (app_id, app.get("status", "")))
'
  log "Matching incidents:"
  curl_json "$COROOT_URL/api/project/$project_id/incidents?limit=200" | SCENARIO="$SCENARIO" OFFICIAL_NETWORK_NAMES="$OFFICIAL_NETWORK_NAMES" python3 -c '
import json, sys
import os
data = json.load(sys.stdin)
scenario = os.environ.get("SCENARIO", "")
official_network = os.environ.get("OFFICIAL_NETWORK_NAMES", "") == "true"
official_names = ("front-end", "catalog", "order", "kafka", "db-main", "analytics-updater")
def match(app_id):
    if scenario == "network-chaos" and official_network:
        return any((":%s" % n) in app_id for n in official_names)
    if scenario and scenario != "all":
        return "coroot-rca-%s" % scenario in app_id
    return "coroot-rca" in app_id or any((":%s" % n) in app_id for n in official_names)
for incident in data.get("data") or []:
    app_id = str(incident.get("application_id", ""))
    if match(app_id):
        print("  %s\t%s\t%s\t%s" % (incident.get("key", ""), incident.get("severity", ""), app_id, incident.get("short_description", "")))
'
}

wait_lab() {
  ensure_tools
  ensure_coroot
  local project_id deadline
  project_id="$(detect_project_id)"
  local expected
  expected="$(expected_incidents)"
  deadline=$((SECONDS + WAIT_SECONDS))
  log "waiting for rca fault incidents project=$project_id expected=${expected} timeout=${WAIT_SECONDS}s"
  while (( SECONDS < deadline )); do
    local count
    count="$(curl_json "$COROOT_URL/api/project/$project_id/incidents?limit=200" | SCENARIO="$SCENARIO" OFFICIAL_NETWORK_NAMES="$OFFICIAL_NETWORK_NAMES" python3 -c '
import json, sys
import os
data = json.load(sys.stdin)
scenario = os.environ.get("SCENARIO", "")
official_network = os.environ.get("OFFICIAL_NETWORK_NAMES", "") == "true"
official_names = ("front-end", "catalog", "order", "kafka", "db-main", "analytics-updater")
def match(app_id):
    if scenario == "network-chaos" and official_network:
        return any((":%s" % n) in app_id for n in official_names)
    if scenario and scenario != "all":
        return "coroot-rca-%s" % scenario in app_id
    return "coroot-rca" in app_id or any((":%s" % n) in app_id for n in official_names)
print(sum(1 for i in data.get("data") or [] if match(str(i.get("application_id", "")))))
')"
    if [[ "$count" =~ ^[0-9]+$ ]] && (( count >= expected )); then
      log "detected $count incident(s)"
      status_lab
      return 0
    fi
    log "detected ${count:-0}/${expected} incident(s); sleeping ${POLL_SECONDS}s"
    sleep "$POLL_SECONDS"
  done
  echo "timed out waiting for rca fault incidents" >&2
  return 1
}

logs_lab() {
  ensure_tools
  for name in $(docker ps -a --filter "label=coroot.rca-fault-lab=true" --format '{{.Names}}'); do
    echo "===== $name ====="
    docker logs --tail=80 "$name" 2>/dev/null || true
  done
}

case "$ACTION" in
  run)
    start_lab
    wait_lab
    ;;
  start)
    start_lab
    ;;
  wait)
    wait_lab
    ;;
  status)
    status_lab
    ;;
  logs)
    logs_lab
    ;;
  stop)
    ensure_tools
    log "removing RCA fault containers"
    remove_lab
    ;;
  restart)
    ensure_tools
    remove_lab
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
