#!/usr/bin/env bash
# Pick Dependency Checker - Validates prerequisites before building
# Run this before building if you didn't use install.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Detect OS
OS="unknown"
DISTRO="unknown"

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        DISTRO="$ID"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
fi

# Print functions
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Pick Dependency Checker${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

print_check() {
    echo -ne "${BLUE}[CHECK]${NC} $1... "
}

print_ok() {
    echo -e "${GREEN}OK${NC}"
}

print_missing() {
    echo -e "${RED}MISSING${NC}"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

print_fix() {
    echo -e "${BLUE}[FIX]${NC} $*"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if library exists (Linux)
library_exists() {
    if [[ "$OS" == "linux" ]]; then
        pkg-config --exists "$1" 2>/dev/null
    else
        return 0  # Skip on non-Linux
    fi
}

# Track missing dependencies
MISSING_COUNT=0
MISSING_DEPS=()

# Check Rust and Cargo
check_rust() {
    print_check "Rust (rustc)"
    if command_exists rustc; then
        RUST_VERSION=$(rustc --version | cut -d' ' -f2)
        RUST_MAJOR=$(echo "$RUST_VERSION" | cut -d'.' -f1)
        RUST_MINOR=$(echo "$RUST_VERSION" | cut -d'.' -f2)

        if [[ $RUST_MAJOR -gt 1 ]] || [[ $RUST_MAJOR -eq 1 && $RUST_MINOR -ge 70 ]]; then
            print_ok
            echo "    Version: $RUST_VERSION"
        else
            print_missing
            echo "    Found: $RUST_VERSION (need 1.70+)"
            MISSING_COUNT=$((MISSING_COUNT + 1))
            MISSING_DEPS+=("rust")
        fi
    else
        print_missing
        MISSING_COUNT=$((MISSING_COUNT + 1))
        MISSING_DEPS+=("rust")
    fi

    print_check "Cargo"
    if command_exists cargo; then
        print_ok
        echo "    Version: $(cargo --version | cut -d' ' -f2)"
    else
        print_missing
        MISSING_COUNT=$((MISSING_COUNT + 1))
        MISSING_DEPS+=("cargo")
    fi
}

# Check build tools
check_build_tools() {
    case "$OS" in
        linux)
            print_check "C compiler (gcc/clang)"
            if command_exists gcc || command_exists clang; then
                print_ok
            else
                print_missing
                MISSING_COUNT=$((MISSING_COUNT + 1))
                MISSING_DEPS+=("gcc")
            fi

            print_check "pkg-config"
            if command_exists pkg-config; then
                print_ok
            else
                print_missing
                MISSING_COUNT=$((MISSING_COUNT + 1))
                MISSING_DEPS+=("pkg-config")
            fi

            print_check "OpenSSL development headers"
            if library_exists openssl; then
                print_ok
            else
                print_missing
                MISSING_COUNT=$((MISSING_COUNT + 1))
                MISSING_DEPS+=("libssl-dev")
            fi

            print_check "Protocol Buffers compiler (protoc)"
            if command_exists protoc; then
                print_ok
            else
                print_missing
                MISSING_COUNT=$((MISSING_COUNT + 1))
                MISSING_DEPS+=("protobuf-compiler")
            fi
            ;;

        macos)
            print_check "Xcode Command Line Tools"
            if command_exists xcode-select && xcode-select -p >/dev/null 2>&1; then
                print_ok
            else
                print_missing
                MISSING_COUNT=$((MISSING_COUNT + 1))
                MISSING_DEPS+=("xcode-cli")
            fi
            ;;
    esac
}

# Check optional desktop dependencies
check_desktop_deps() {
    if [[ "$OS" == "linux" ]]; then
        echo ""
        echo -e "${BLUE}Optional Desktop Dependencies:${NC}"

        print_check "WebKit2GTK"
        if library_exists webkit2gtk-4.0; then
            print_ok
        else
            print_warn "Not installed (needed for desktop app)"
        fi

        print_check "GTK3"
        if library_exists gtk+-3.0; then
            print_ok
        else
            print_warn "Not installed (needed for desktop app)"
        fi
    fi
}

# Check WiFi tools
check_wifi_tools() {
    echo ""
    echo -e "${BLUE}Optional WiFi Tools:${NC}"

    print_check "wireless-tools"
    if command_exists iwconfig; then
        print_ok
    else
        print_warn "Not installed (needed for WiFi scanning)"
    fi

    print_check "aircrack-ng"
    if command_exists aircrack-ng; then
        print_ok
    else
        print_warn "Not installed (needed for advanced WiFi features)"
    fi
}

# Generate fix commands
generate_fix_commands() {
    if [[ $MISSING_COUNT -eq 0 ]]; then
        echo ""
        echo -e "${GREEN}All required dependencies are installed!${NC}"
        echo ""
        echo "You can now build Pick:"
        echo "  cargo build --package pentest-headless"
        return 0
    fi

    echo ""
    echo -e "${RED}Missing $MISSING_COUNT required dependencies${NC}"
    echo ""
    echo "To fix this, run the following commands:"
    echo ""

    case "$OS" in
        linux)
            case "$DISTRO" in
                ubuntu|debian)
                    print_fix "Debian/Ubuntu:"
                    echo "    sudo apt update"
                    if [[ " ${MISSING_DEPS[*]} " =~ " gcc " ]] || [[ " ${MISSING_DEPS[*]} " =~ " pkg-config " ]] || [[ " ${MISSING_DEPS[*]} " =~ " libssl-dev " ]] || [[ " ${MISSING_DEPS[*]} " =~ " protobuf-compiler " ]]; then
                        echo "    sudo apt install -y build-essential pkg-config libssl-dev protobuf-compiler"
                    fi
                    ;;
                fedora|rhel|centos)
                    print_fix "Fedora/RHEL:"
                    if [[ " ${MISSING_DEPS[*]} " =~ " gcc " ]] || [[ " ${MISSING_DEPS[*]} " =~ " pkg-config " ]] || [[ " ${MISSING_DEPS[*]} " =~ " libssl-dev " ]] || [[ " ${MISSING_DEPS[*]} " =~ " protobuf-compiler " ]]; then
                        echo "    sudo dnf install -y gcc gcc-c++ make openssl-devel protobuf-compiler"
                    fi
                    ;;
                *)
                    print_fix "Linux:"
                    echo "    Install: build-essential, pkg-config, libssl-dev (or equivalents)"
                    ;;
            esac
            ;;

        macos)
            print_fix "macOS:"
            if [[ " ${MISSING_DEPS[*]} " =~ " xcode-cli " ]]; then
                echo "    xcode-select --install"
            fi
            ;;

        windows)
            print_fix "Windows:"
            echo "    Install Visual Studio Build Tools with C++ workload"
            echo "    Or: winget install Microsoft.VisualStudio.2022.BuildTools"
            ;;
    esac

    if [[ " ${MISSING_DEPS[*]} " =~ " rust " ]] || [[ " ${MISSING_DEPS[*]} " =~ " cargo " ]]; then
        echo ""
        print_fix "Install Rust:"
        echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo "    source \$HOME/.cargo/env"
    fi

    echo ""
    echo "Or run the automated installer:"
    echo "    ./install.sh"
    echo ""

    return 1
}

# Main
main() {
    print_header
    echo "Detected OS: $OS ($DISTRO)"
    echo ""
    echo -e "${BLUE}Required Dependencies:${NC}"

    check_rust
    check_build_tools
    check_desktop_deps
    check_wifi_tools

    generate_fix_commands
}

main "$@"
