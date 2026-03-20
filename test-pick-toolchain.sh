#!/usr/bin/env bash
# Test the toolchain via Pick connector

set -euo pipefail

echo "═══════════════════════════════════════════════════"
echo "🧪 Testing Toolchain via Pick Connector"
echo "═══════════════════════════════════════════════════"
echo ""

# Check if DVWA is running
if ! curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 | grep -q "302\|200"; then
    echo "⚠️  DVWA not running. Starting DVWA..."
    docker rm -f dvwa 2>/dev/null || true
    docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
    echo "⏳ Waiting for DVWA to start..."
    sleep 10
fi

echo "✓ DVWA is running at http://localhost:8080"
echo ""

echo "🚀 Launching Pick in headless mode..."
echo ""
echo "You can now use the Strike48 chat interface to run:"
echo ""
echo "  autopwn_webapp target=http://localhost:8080"
echo ""
echo "Or test with manual mode:"
echo ""
echo "  autopwn_webapp target=http://localhost:8080 execution_mode=manual"
echo ""
echo "───────────────────────────────────────────────────"
echo ""

# Launch Pick
./run-pentest.sh headless dev
