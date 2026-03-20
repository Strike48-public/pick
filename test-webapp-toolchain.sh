#!/usr/bin/env bash
# Test the Web Application Toolchain against DVWA

set -euo pipefail

DVWA_TARGET="http://10.10.2.169"

echo "═══════════════════════════════════════════════════"
echo "🧪 Testing Web Application Toolchain"
echo "═══════════════════════════════════════════════════"
echo "Target: $DVWA_TARGET"
echo ""

echo "📋 Testing autopwn_webapp tool..."
echo ""

# Create a simple test using the headless app
./target/release/pentest-headless <<EOF
{
  "tool": "autopwn_webapp",
  "params": {
    "target": "$DVWA_TARGET",
    "execution_mode": "autonomous",
    "attack_profile": "normal"
  }
}
EOF

echo ""
echo "═══════════════════════════════════════════════════"
echo "✅ Test complete!"
echo "═══════════════════════════════════════════════════"
