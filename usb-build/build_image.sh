#!/usr/bin/env bash
# GARUDA USB Image Builder Script
# Assembles portable Alpine Linux ISO/IMG with SquashFS root and LUKS2 storage partition

set -euo pipefail

VERSION="${1:-0.3.0}"
IMAGE_NAME="garuda-usb-${VERSION}.img"
IMAGE_SIZE_MB=2048

echo "=== Building GARUDA USB Agent Image v${VERSION} ==="
echo "Target Image: ${IMAGE_NAME} (${IMAGE_SIZE_MB}MB)"

# 1. Allocate sparse disk image
dd if=/dev/zero of="${IMAGE_NAME}" bs=1M count=0 seek="${IMAGE_SIZE_MB}" status=none

# 2. Partition GPT
bash usb-build/partition_setup.sh "${IMAGE_NAME}"

# 3. Create SquashFS Root from usb-agent and garuda-agent
BUILD_ROOT="$(mktemp -d)"
mkdir -p "${BUILD_ROOT}/opt/garuda/usb-agent"
mkdir -p "${BUILD_ROOT}/etc/udev/rules.d"
mkdir -p "${BUILD_ROOT}/etc/local.d"

cp -r usb-agent/garuda_usb_agent "${BUILD_ROOT}/opt/garuda/usb-agent/"
cp usb-build/alpine_setup/overlay/etc/local.d/garuda.start "${BUILD_ROOT}/etc/local.d/" || true
cp usb-build/alpine_setup/overlay/etc/udev/rules.d/99-garuda-canary.rules "${BUILD_ROOT}/etc/udev/rules.d/" || true

echo "Generating squashfs root: garuda-readonly.squashfs..."
if command -v mksquashfs &> /dev/null; then
    mksquashfs "${BUILD_ROOT}" garuda-readonly.squashfs -comp xz -noappend
else
    echo "mksquashfs not found, creating dummy squashfs artifact for container build."
    touch garuda-readonly.squashfs
fi

rm -rf "${BUILD_ROOT}"

echo "=== Image build completed: ${IMAGE_NAME} ==="
