#!/usr/bin/env bash
# Install wordlists for Pick AutoPwn

set -euo pipefail

echo "=========================================="
echo "Pick Wordlist Installer"
echo "=========================================="
echo ""

WORDLIST_DIR="/usr/share/wordlists"
TEMP_DIR="/tmp/pick-wordlists"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Create directories
mkdir -p "$WORDLIST_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

echo "📥 Downloading RockYou wordlist..."
echo ""

# Try multiple sources for rockyou
if curl -L -o rockyou.txt.gz "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" 2>/dev/null; then
    echo "✓ Downloaded from naive-hashcat"
    mv rockyou.txt.gz "$WORDLIST_DIR/rockyou.txt"
elif curl -L -o rockyou.txt.gz "https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz" 2>/dev/null; then
    echo "✓ Downloaded from Kali Linux"
    gunzip -c rockyou.txt.gz > "$WORDLIST_DIR/rockyou.txt"
    rm rockyou.txt.gz
elif curl -L -o rockyou.txt "https://download.weakpass.com/wordlists/90/rockyou.txt" 2>/dev/null; then
    echo "✓ Downloaded from WeakPass"
    mv rockyou.txt "$WORDLIST_DIR/rockyou.txt"
else
    echo "❌ Failed to download rockyou.txt from all sources"
    echo ""
    echo "Manual installation:"
    echo "  1. Download rockyou.txt manually"
    echo "  2. Place it in $WORDLIST_DIR/rockyou.txt"
    echo "  3. Common sources:"
    echo "     - https://github.com/brannondorsey/naive-hashcat/releases"
    echo "     - https://github.com/danielmiessler/SecLists"
    exit 1
fi

# Verify file size (rockyou should be ~130MB uncompressed)
FILESIZE=$(stat -c%s "$WORDLIST_DIR/rockyou.txt" 2>/dev/null || echo "0")
if [[ $FILESIZE -lt 10000000 ]]; then
    echo "⚠️  Warning: rockyou.txt seems too small ($FILESIZE bytes)"
    echo "   Expected ~130MB. File may be incomplete."
fi

echo ""
echo "✓ RockYou wordlist installed successfully!"
echo ""
echo "📊 Wordlist info:"
ls -lh "$WORDLIST_DIR/rockyou.txt"
echo ""
echo "Lines: $(wc -l < "$WORDLIST_DIR/rockyou.txt")"
echo ""
echo "✓ Installation complete!"
echo ""
echo "Pick will now automatically detect and use this wordlist."
echo "No download required during AutoPwn operations."

# Cleanup
rm -rf "$TEMP_DIR"
