#!/usr/bin/env bash
# Builds our backend images locally (amd64), the same way .github/workflows/durio-images.yaml does.
#
#   scripts/durio/build-images.sh [--tag TAG] [--skip-base] [--smoke] [service...]
#
# Images: durio-base:local and durio-<service>:TAG (default TAG=local).
# Services: api events file-server proxy gifbox crond pushd voice-ingress (default: all).
set -euo pipefail

cd "$(dirname "$0")/../.."

tag="local"
skip_base=0
smoke=0
services=()
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) tag="$2"; shift 2 ;;
    --skip-base) skip_base=1; shift ;;
    --smoke) smoke=1; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) services+=("$1"); shift ;;
  esac
done

declare -A dockerfiles=(
  [api]=crates/delta/Dockerfile
  [events]=crates/bonfire/Dockerfile
  [file-server]=crates/services/autumn/Dockerfile
  [proxy]=crates/services/january/Dockerfile
  [gifbox]=crates/services/gifbox/Dockerfile
  [crond]=crates/daemons/crond/Dockerfile
  [pushd]=crates/daemons/pushd/Dockerfile
  [voice-ingress]=crates/daemons/voice-ingress/Dockerfile
)
[ ${#services[@]} -gt 0 ] || services=(api events file-server proxy gifbox crond pushd voice-ingress)

if [ "$skip_base" -eq 0 ]; then
  echo "==> durio-base:local"
  # Release builds use LTO; too many parallel jobs can exhaust Docker Desktop memory.
  docker build --platform linux/amd64 \
    --build-arg CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-6}" \
    -t durio-base:local .
fi

for service in "${services[@]}"; do
  file="${dockerfiles[$service]:-}"
  [ -n "$file" ] || { echo "unknown service: $service" >&2; exit 1; }
  echo "==> durio-$service:$tag"
  docker build --platform linux/amd64 \
    --build-arg BASE_IMAGE=durio-base:local \
    -f "$file" -t "durio-$service:$tag" .
done

if [ "$smoke" -eq 1 ]; then
  export DURIO_API_IMAGE="durio-api:$tag"
  docker compose -f .github/durio/compose.smoke.yml up -d --wait
  trap 'docker compose -f .github/durio/compose.smoke.yml down -v' EXIT
  ./scripts/durio/smoke-version.sh "http://localhost:14702/"
fi
