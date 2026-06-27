#!/usr/bin/env bash
# Build the unified, self-contained `decentid` single binary.
#
# Usage:
#   scripts/build.sh                # build for the host platform -> dist/decentid[.exe]
#   scripts/build.sh all            # cross-compile release matrix into dist/
#
# The binary is pure Go (CGO disabled) and embeds all web templates/static
# assets via go:embed, so each artifact is a standalone single file.
set -euo pipefail

cd "$(dirname "$0")/.."

PKG="./cmd/decentid"
OUT="dist"
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
LDFLAGS="-s -w -X main.version=${VERSION}"
export CGO_ENABLED=0

mkdir -p "$OUT"

build_one() {
  local goos="$1" goarch="$2"
  local name="decentid_${goos}_${goarch}"
  local ext=""
  [ "$goos" = "windows" ] && ext=".exe"
  echo ">> $goos/$goarch"
  GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "$LDFLAGS" \
    -o "$OUT/${name}${ext}" "$PKG"
}

if [ "${1:-host}" = "all" ]; then
  build_one linux   amd64
  build_one linux   arm64
  build_one darwin  amd64
  build_one darwin  arm64
  build_one windows amd64
  echo
  echo "Artifacts in $OUT/:"
  ls -lh "$OUT"
else
  ext=""
  [ "$(go env GOOS)" = "windows" ] && ext=".exe"
  go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/decentid${ext}" "$PKG"
  echo "Built $OUT/decentid${ext} (version ${VERSION})"
fi
