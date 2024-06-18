#!/bin/sh
set -e

BIN='ztman'
DIST='dist-linux'
VERSION=$(cat VERSION)

mkdir -p $DIST
rm -rf $DIST/*

for ARCH in amd64; do
    OUT="$DIST/ztman_linux_$ARCH"
    docker run -i --rm \
        -v "$(pwd):/go/src/github.com/feeltheajf/ztman:rw" \
        -w /go/src/github.com/feeltheajf/ztman \
        -e CGO_ENABLED=1 \
        ztman-xgo \
        --build-cmd "go build -ldflags \"-s -w -X main.version=$VERSION\" -o $OUT" \
        -p "linux/amd64"
    cp "$OUT" "$BIN"
    zip "$OUT.zip" "$BIN" README.md VERSION
done
