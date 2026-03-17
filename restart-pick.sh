#!/usr/bin/env bash
# Quick restart script for Pick

echo "🔄 Restarting Pick..."
echo ""

# Kill any running Pick instances
pkill -f "pentest-connector\|pentest-agent" 2>/dev/null || true

echo "✓ Stopped old instances"
echo ""
echo "🚀 Starting Pick with sandbox DISABLED..."
echo ""

# Start Pick
./run-pentest.sh headless dev
