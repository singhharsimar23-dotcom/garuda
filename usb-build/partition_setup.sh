#!/usr/bin/env bash
# GARUDA Partition Setup Script
# Configures GPT layout with ESP (FAT32), Read-Only SquashFS, and LUKS2 Encrypted Storage

set -euo pipefail

TARGET_DEVICE="${1:-}"

if [ -z "$TARGET_DEVICE" ]; then
    echo "Usage: $0 <target_device_or_image_loop>"
    exit 1
fi

echo "Setting up GPT partitions on $TARGET_DEVICE..."

# 1. Create GPT label
parted -s "$TARGET_DEVICE" mklabel gpt

# 2. Partition 1: EFI System Partition (200 MiB)
parted -s "$TARGET_DEVICE" mkpart ESP fat32 1MiB 201MiB
parted -s "$TARGET_DEVICE" set 1 esp on

# 3. Partition 2: Read-Only SquashFS Root (1000 MiB)
parted -s "$TARGET_DEVICE" mkpart ROOT ext4 201MiB 1201MiB

# 4. Partition 3: LUKS2 Encrypted Data / Almanac Storage (Remaining)
parted -s "$TARGET_DEVICE" mkpart DATA 1201MiB 100%

echo "GPT Partitioning completed successfully on $TARGET_DEVICE."
