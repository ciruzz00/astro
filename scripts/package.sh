#!/bin/sh
# Build and package astro for one target.
# Usage: scripts/package.sh <version> <date YYYY-MM-DD> <goos> <goarch>
set -eu

version="$1"
date="$2"
goos="$3"
goarch="$4"

name="astro_${version}_${date}_${goos}_${goarch}"
out="dist/${name}"
bin="astro"
[ "$goos" = "windows" ] && bin="astro.exe"

rm -rf "$out"
mkdir -p "$out"

CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
    -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=${version} -X main.date=${date}" \
    -o "${out}/${bin}" ./cmd/astro

cp README.md LICENSE "$out/"

cd dist
if [ "$goos" = "windows" ]; then
    rm -f "${name}.zip"
    zip -qr "${name}.zip" "$name"
else
    tar -czf "${name}.tar.gz" "$name"
fi
rm -rf "$name"
echo "built dist/${name}"
