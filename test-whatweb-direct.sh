#!/usr/bin/env bash
# Test whatweb directly against DVWA

echo "Testing whatweb against localhost:8080..."
echo ""

whatweb -v http://localhost:8080

echo ""
echo "✅ Direct whatweb test complete"
