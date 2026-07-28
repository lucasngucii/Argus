#!/usr/bin/env bash
# Cross-compile the release matrix, archive + checksum each, and assemble the
# npm platform packages. Usage: scripts/build-dist.sh [version]
set -euo pipefail
VERSION="${1:-0.0.0-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
LDFLAGS="-s -w -X github.com/lucasngucii/argus/internal/version.version=${VERSION}"

rm -rf "$DIST"; mkdir -p "$DIST"

# "GOOS GOARCH node-suffix"
targets=(
  "darwin arm64 darwin-arm64"
  "darwin amd64 darwin-x64"
  "linux  arm64 linux-arm64"
  "linux  amd64 linux-x64"
)
for t in "${targets[@]}"; do
  read -r goos goarch suffix <<<"$t"
  bin="$DIST/argus-$suffix"
  echo "building $suffix ..."
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -ldflags "$LDFLAGS" -o "$bin" "$ROOT/cmd/argus"
  ( cd "$DIST" && tar -czf "argus-$suffix.tar.gz" "argus-$suffix" )
  pkgbin="$ROOT/npm/argus-$suffix/bin"
  mkdir -p "$pkgbin"; cp "$bin" "$pkgbin/argus"; chmod +x "$pkgbin/argus"
done
( cd "$DIST" && shasum -a 256 argus-*.tar.gz > checksums.txt )

node "$ROOT/scripts/set-versions.mjs" "$VERSION"
echo "built $VERSION -> $DIST (and assembled npm/ platform packages)"
