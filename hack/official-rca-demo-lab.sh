#!/usr/bin/env bash
set -Eeuo pipefail

ACTION="${1:-run}"

COROOT_URL="${COROOT_URL:-http://127.0.0.1:8080}"
PROJECT_ID="${PROJECT_ID:-}"
INCIDENT_KEY="${INCIDENT_KEY:-}"
SERVER_NAME="${SERVER_NAME:-coroot-incident-bad-api}"

export ERROR_RATE="${ERROR_RATE:-100}"
export DELAY_MS="${DELAY_MS:-900}"
export WORKERS="${WORKERS:-48}"
export CPU_WORKERS="${CPU_WORKERS:-3}"
export REQUEST_PATH="${REQUEST_PATH:-/checkout}"
export WAIT_SECONDS="${WAIT_SECONDS:-720}"
export POLL_SECONDS="${POLL_SECONDS:-15}"

usage() {
  cat <<EOF
Usage:
  bash hack/official-rca-demo-lab.sh [run|start|wait|rca|status|logs|stop|restart]

Purpose:
  Runs the local incident fault workload and triggers the built-in official
  RCA demo fixture enabled by AI_RCA_DEMO_SCENARIO=official.

Recommended local Coroot start:
  docker compose -f deploy/docker-compose.yaml -f deploy/docker-compose.local-image.yaml up -d

Useful env vars:
  COROOT_URL=http://127.0.0.1:8080
  PROJECT_ID=3wgteurw
  INCIDENT_KEY=4s27bu0z
  ERROR_RATE=100
  DELAY_MS=900
  WORKERS=48

Actions:
  run      Start workload, wait for incident, trigger RCA refresh.
  start    Start workload only.
  wait     Wait until Coroot opens an incident for the workload.
  rca      Trigger RCA refresh for INCIDENT_KEY or latest lab incident.
  status   Show workload containers and matching incidents.
  logs     Tail workload logs.
  stop     Remove workload containers.
  restart  stop + start.
EOF
}

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
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

latest_lab_incident() {
  local project_id="$1"
  if [[ -n "$INCIDENT_KEY" ]]; then
    printf '%s' "$INCIDENT_KEY"
    return
  fi
  curl_json "$COROOT_URL/api/project/$project_id/incidents?limit=100" | python3 -c '
import json, sys
server = sys.argv[1]
data = json.load(sys.stdin)
for incident in data.get("data") or []:
    if server in str(incident.get("application_id", "")):
        print(incident.get("key", ""), end="")
        raise SystemExit(0)
raise SystemExit("no incident found for " + server)
' "$SERVER_NAME"
}

trigger_rca() {
  local project_id incident_key
  project_id="$(detect_project_id)"
  incident_key="$(latest_lab_incident "$project_id")"
  log "triggering RCA project=$project_id incident=$incident_key"
  curl -fsS -X POST "$COROOT_URL/api/project/$project_id/incident/$incident_key/rca" \
    -H 'Content-Type: application/json' \
    -d '{}' >/dev/null
  for _ in $(seq 1 60); do
    local job
    job="$(curl_json "$COROOT_URL/api/project/$project_id/incident/$incident_key/rca/job" || true)"
    printf '%s\n' "$job" | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    print("pending")
    raise SystemExit(1)
data = json.loads(raw)
status = data.get("status") or data.get("data", {}).get("status") or "unknown"
print(status)
raise SystemExit(0 if status.lower() in {"done", "completed", "succeeded", "ok", "failed"} else 1)
' && break || true
    sleep 2
  done
  log "open: $COROOT_URL/p/$project_id/incidents?incident=$incident_key"
}

case "$ACTION" in
  run)
    bash hack/incident-fault-lab.sh start
    bash hack/incident-fault-lab.sh wait
    trigger_rca
    ;;
  start)
    bash hack/incident-fault-lab.sh start
    ;;
  wait)
    bash hack/incident-fault-lab.sh wait
    ;;
  rca)
    trigger_rca
    ;;
  status)
    bash hack/incident-fault-lab.sh status
    ;;
  logs)
    bash hack/incident-fault-lab.sh logs
    ;;
  stop)
    bash hack/incident-fault-lab.sh stop
    ;;
  restart)
    bash hack/incident-fault-lab.sh restart
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
