#!/usr/bin/env bash
# Convenience wrapper for running the port scanner Docker image.
# Usage: ./docker-run.sh --host <host> --ports 1-1024 [options]
#
# NOTE: --network=host is Linux-only. On Windows/Mac, Docker runs inside a VM
# and --network=host gives VM network access, not the host's LAN.
set -euo pipefail

mkdir -p "$(pwd)/reports"

docker run -it --rm \
  --network=host \
  --cap-add=NET_RAW \
  -v "$(pwd)/reports:/reports" \
  port-scanner "$@"
