#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || date +%Y%m%d%H%M%S)}"
IMAGE="${IMAGE:-coroot:${VERSION}}"
NODE_IMAGE="${NODE_IMAGE:-node:24-bookworm}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"
PLATFORM="${PLATFORM:-}"
PUSH="${PUSH:-false}"
PULL="${PULL:-false}"
NO_CACHE="${NO_CACHE:-false}"
SKIP_FRONTEND_BUILD="${SKIP_FRONTEND_BUILD:-false}"

usage() {
  cat <<EOF
Usage:
  bash hack/build-production-image.sh

Purpose:
  Build a production Coroot image on servers that do not have npm installed.
  The frontend is built inside a Node.js container, then the production
  Dockerfile builds the final Coroot image.

Examples:
  VERSION=v1.0.0 IMAGE=registry.example.com/coroot:v1.0.0 bash hack/build-production-image.sh
  VERSION=v1.0.0 IMAGE=registry.example.com/coroot:v1.0.0 PUSH=true bash hack/build-production-image.sh
  VERSION=v1.0.0 IMAGE=registry.example.com/coroot:v1.0.0 PLATFORM=linux/amd64,linux/arm64 PUSH=true bash hack/build-production-image.sh

Environment:
  VERSION              Image/application version. Default: git describe or timestamp.
  IMAGE                Final image tag. Default: coroot:\$VERSION.
  NODE_IMAGE           Node image used to build frontend. Default: node:24-bookworm.
  DOCKERFILE           Production Dockerfile path. Default: Dockerfile.
  PLATFORM             Optional buildx platform, for example linux/amd64.
  PUSH                 Use buildx --push. Default: false.
  PULL                 Pass --pull to docker build. Default: false.
  NO_CACHE             Pass --no-cache to docker build. Default: false.
  SKIP_FRONTEND_BUILD  Skip npm ci/build-prod when static/ is already built. Default: false.
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

bool_is_true() {
  [[ "$1" == "true" || "$1" == "1" || "$1" == "yes" ]]
}

build_frontend() {
  log "building frontend in ${NODE_IMAGE}"
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e NPM_CONFIG_CACHE=/tmp/.npm \
    -v "${ROOT_DIR}:/workspace" \
    -w /workspace/front \
    "$NODE_IMAGE" \
    sh -lc 'npm ci && npm run build-prod'
}

build_image() {
  local dockerfile_path="${ROOT_DIR}/${DOCKERFILE}"
  [[ -f "$dockerfile_path" ]] || {
    echo "Dockerfile not found: $dockerfile_path" >&2
    exit 1
  }

  log "building image ${IMAGE} with VERSION=${VERSION}"

  local common_args=(
    --file "$dockerfile_path"
    --build-arg "VERSION=$VERSION"
    --tag "$IMAGE"
  )

  if bool_is_true "$PULL"; then
    common_args+=(--pull)
  fi
  if bool_is_true "$NO_CACHE"; then
    common_args+=(--no-cache)
  fi

  if [[ -n "$PLATFORM" || "$(printf '%s' "$PUSH" | tr '[:upper:]' '[:lower:]')" != "false" ]]; then
    if [[ "$PLATFORM" == *,* ]] && ! bool_is_true "$PUSH"; then
      echo "multi-platform builds require PUSH=true because Docker cannot --load a manifest list" >&2
      exit 1
    fi

    local buildx_args=(buildx build "${common_args[@]}")
    if [[ -n "$PLATFORM" ]]; then
      buildx_args+=(--platform "$PLATFORM")
    fi
    if bool_is_true "$PUSH"; then
      buildx_args+=(--push)
    else
      buildx_args+=(--load)
    fi
    buildx_args+=("$ROOT_DIR")
    docker "${buildx_args[@]}"
  else
    docker build "${common_args[@]}" "$ROOT_DIR"
  fi
}

main() {
  case "${1:-}" in
    -h|--help|help)
      usage
      exit 0
      ;;
  esac

  need_cmd docker

  if bool_is_true "$SKIP_FRONTEND_BUILD"; then
    log "skipping frontend build"
  else
    build_frontend
  fi

  build_image
  log "done: ${IMAGE}"
}

main "$@"
