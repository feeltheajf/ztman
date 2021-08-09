#!/bin/sh
set -e

BIN='ztman'
DIST='dist-linux'
VERSION=$(cat VERSION)

mkdir -p $DIST
rm -rf $DIST/*

for ARCH in amd64; do
    OUT="$DIST/ztman_linux_$ARCH"
	xgo -image ztman-xgo \
		-dest "$OUT" \
		-ldflags "-s -w -X main.version=$VERSION" \
		-targets "linux/$ARCH" .
	cp "$OUT/ztman-linux-$ARCH" "$BIN"
    zip "$OUT.zip" "$BIN" README.md VERSION
done
