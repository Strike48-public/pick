#!/usr/bin/env bash
# Run Playwright E2E tests for Pick
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

echo "🧪 Running Playwright E2E Tests"
echo

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    npx playwright install chromium
    echo
fi

# Parse arguments
MODE="${1:-headless}"

case "$MODE" in
    headless)
        echo "▶️  Running tests (headless)"
        npm test
        ;;
    headed)
        echo "▶️  Running tests (visible browser)"
        npm run test:headed
        ;;
    ui)
        echo "▶️  Opening Playwright UI"
        npm run test:ui
        ;;
    debug)
        echo "▶️  Running tests (debug mode)"
        npm run test:debug
        ;;
    cyberchef)
        echo "▶️  Running CyberChef tests only"
        npm run test:cyberchef
        ;;
    *)
        echo "Usage: $0 [headless|headed|ui|debug|cyberchef]"
        exit 1
        ;;
esac
