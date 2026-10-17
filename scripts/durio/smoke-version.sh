#!/usr/bin/env bash
# Checks that the API at $1 answers GET / and reports our fork version.
# $2 is the git ref name: for a tag vX.Y.Z-fork.N the API must report X.Y.Z+fork.N,
# for anything else it is enough that the version carries a +fork suffix.
set -euo pipefail

url="${1:?usage: smoke-version.sh <api-url> [ref-name]}"
ref="${2:-}"

body=""
for _ in $(seq 1 60); do
  if body="$(curl -fsS "$url")"; then
    break
  fi
  sleep 2
done
[ -n "$body" ] || { echo "API at $url did not answer" >&2; exit 1; }

version="$(printf '%s' "$body" | sed -n 's/.*"revolt":"\([^"]*\)".*/\1/p')"
echo "API reports version: ${version:-<none>}"

if [[ "$ref" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-fork\.([0-9]+)$ ]]; then
  expected="${BASH_REMATCH[1]}+fork.${BASH_REMATCH[2]}"
  [ "$version" = "$expected" ] || { echo "expected $expected" >&2; exit 1; }
else
  [[ "$version" == *+fork.* ]] || { echo "version has no +fork suffix" >&2; exit 1; }
fi
echo "ok"
