#!/usr/bin/env bash
# Test the seeding system

set -euo pipefail

echo "========================================"
echo "Pick Seeding System Test"
echo "========================================"
echo ""

# Check if Pick's resources directory exists
RESOURCES_DIR="$HOME/.pick/resources"

echo "1. Checking resources directory..."
if [ -d "$RESOURCES_DIR" ]; then
    echo "   ✓ Resources directory exists: $RESOURCES_DIR"
    echo ""
    echo "   Current contents:"
    find "$RESOURCES_DIR" -type f 2>/dev/null | head -10 || echo "   (empty)"
else
    echo "   ℹ Resources directory doesn't exist yet (will be created on first seed)"
fi

echo ""
echo "2. Checking wordlist search paths..."
echo "   Priority order:"
echo "   1. $HOME/.pick/resources/wordlists/ (Pick's seeded wordlists)"
echo "   2. /usr/share/wordlists/ (system wordlists)"
echo "   3. /usr/share/seclists/ (SecLists package)"
echo "   4. /opt/wordlists/ (manual install)"

echo ""
echo "3. Searching for existing wordlists..."

# Check each location
for path in \
    "$HOME/.pick/resources/wordlists/passwords/rockyou.txt" \
    "$HOME/.pick/resources/wordlists/passwords/common-10k.txt" \
    "/usr/share/wordlists/rockyou.txt" \
    "/usr/share/wordlists/rockyou.txt.gz"; do

    if [ -f "$path" ]; then
        size=$(du -h "$path" | cut -f1)
        echo "   ✓ Found: $path ($size)"
    fi
done

echo ""
echo "4. Summary:"
echo "   - Pick will check ~/.pick/resources/ FIRST"
echo "   - No wordlists found = will attempt download"
echo "   - Download falls back to embedded URLs"
echo ""
echo "========================================"
echo "To seed resources manually, you can:"
echo "  1. Create the directory: mkdir -p ~/.pick/resources/wordlists/passwords"
echo "  2. Download rockyou: wget <url> -O ~/.pick/resources/wordlists/passwords/rockyou.txt"
echo "  3. Or wait for Settings UI with Seed buttons"
echo "========================================"
