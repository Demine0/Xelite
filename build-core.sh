#!/bin/sh
# Builds xelite-core.exe (Xray-core + gVisor bridge) for the UWP package.
#
#   build/ARM/xelite-core.exe  - Windows 10 Mobile phones, ARMv7
#   build/x64/xelite-core.exe  - Windows 10/11 PC, for testing the app on desktop
#
# Go 1.26 removed the 32-bit windows/arm port, so Go 1.25.x is required.
# If `go` on PATH is not 1.25, the toolchain is downloaded to .toolchain/.
set -eu

GO_VERSION=1.25.14
ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

GO=go
if ! command -v go >/dev/null 2>&1 || ! go version | grep -q "go1\.25\."; then
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
    if [ ! -x ".toolchain/go/bin/go" ]; then
        echo "Downloading Go $GO_VERSION ($os-$arch)..."
        mkdir -p .toolchain
        curl -fSL --retry 5 -o .toolchain/go.tar.gz "https://go.dev/dl/go$GO_VERSION.$os-$arch.tar.gz"
        tar -xzf .toolchain/go.tar.gz -C .toolchain
        rm .toolchain/go.tar.gz
    fi
    GO="$ROOT/.toolchain/go/bin/go"
fi
export GOTOOLCHAIN=local CGO_ENABLED=0

build() {
    mkdir -p "build/$1"
    echo "Building build/$1/xelite-core.exe ($2/$3)"
    (cd core && GOOS=windows GOARCH=$3 GOARM=7 "$GO" build -trimpath \
        -ldflags "-s -w -buildid=" -o "../build/$1/xelite-core.exe" .)
}

build ARM windows arm
build x64 windows amd64
