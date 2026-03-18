#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# jpackage-linux.sh — Build a Linux .deb or .rpm package for port-scanner
#
# Prerequisites:
#   - JDK 21+ on PATH (includes jpackage and jlink)
#   - dpkg-deb (for .deb) — install via: sudo apt-get install dpkg
#   - rpmbuild (for .rpm) — install via: sudo yum install rpm-build
#   - Run: mvn package -DskipTests  before this script
#
# Usage:
#   ./scripts/jpackage-linux.sh [deb|rpm]   (default: deb)
#
# Output: target/port-scanner_1.0_amd64.deb  (or .rpm)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

TYPE="${1:-deb}"
JAR="target/port-scanner-1.0-shaded.jar"

if [ ! -f "$JAR" ]; then
    echo "ERROR: $JAR not found. Run: mvn package -DskipTests"
    exit 1
fi

if ! command -v jpackage &>/dev/null; then
    echo "ERROR: jpackage not found. Ensure JDK 21+ bin/ is on PATH."
    exit 1
fi

echo "Building Linux $TYPE package..."

jpackage \
    --type "$TYPE" \
    --name "port-scanner" \
    --app-version "1.0" \
    --description "Multithreaded TCP/UDP port scanner with service detection" \
    --vendor "port-scanner" \
    --input target \
    --main-jar "port-scanner-1.0-shaded.jar" \
    --main-class "com.portscanner.Main" \
    --dest target \
    --linux-shortcut \
    --linux-menu-group "Utilities" \
    --java-options "-Xmx512m"

echo
echo "Package built in target/"
echo "Install with:"
if [ "$TYPE" = "deb" ]; then
    echo "  sudo dpkg -i target/port-scanner_1.0_amd64.deb"
else
    echo "  sudo rpm -ivh target/port-scanner-1.0-1.x86_64.rpm"
fi
