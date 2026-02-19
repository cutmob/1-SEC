#!/bin/sh
# 1-SEC Installer
# Usage: curl -fsSL https://1-sec.dev/get | sh
#
# Detects OS/arch, downloads the latest release from GitHub, and installs
# the 1sec binary to /usr/local/bin (or ~/.local/bin if no root access).

set -e

REPO="cutmob/1-SEC"
BINARY="1sec"
INSTALL_DIR="/usr/local/bin"

# Colors (if terminal supports it)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { printf "${CYAN}[1sec]${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}[1sec]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[1sec]${NC} %s\n" "$1"; }
fail()  { printf "${RED}[1sec]${NC} %s\n" "$1" >&2; exit 1; }

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)   echo "linux" ;;
        Darwin*)  echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)        fail "Unsupported OS: $(uname -s)" ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)              fail "Unsupported architecture: $(uname -m)" ;;
    esac
}

# Get latest release tag from GitHub API
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
    else
        fail "Neither curl nor wget found. Please install one and try again."
    fi
}

# Download a URL to a file
download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    fi
}

main() {
    info "Detecting system..."
    OS=$(detect_os)
    ARCH=$(detect_arch)
    info "OS: ${OS}, Arch: ${ARCH}"

    info "Fetching latest release..."
    VERSION=$(get_latest_version)
    if [ -z "$VERSION" ]; then
        fail "Could not determine latest version. Check https://github.com/${REPO}/releases"
    fi
    # Strip leading 'v' for the archive name
    VERSION_NUM=$(echo "$VERSION" | sed 's/^v//')
    info "Latest version: ${VERSION}"

    # Build download URL (matches GoReleaser naming)
    if [ "$OS" = "windows" ]; then
        ARCHIVE="1sec_${VERSION_NUM}_${OS}_${ARCH}.zip"
    else
        ARCHIVE="1sec_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
    fi
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    info "Downloading ${ARCHIVE}..."
    download "$URL" "${TMP_DIR}/${ARCHIVE}"

    info "Extracting..."
    if [ "$OS" = "windows" ]; then
        unzip -q "${TMP_DIR}/${ARCHIVE}" -d "$TMP_DIR"
    else
        tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"
    fi

    # Determine install location
    if [ -w "$INSTALL_DIR" ]; then
        TARGET="$INSTALL_DIR"
    elif [ "$(id -u)" = "0" ]; then
        TARGET="$INSTALL_DIR"
    else
        TARGET="${HOME}/.local/bin"
        mkdir -p "$TARGET"
        warn "No root access. Installing to ${TARGET}"
        warn "Make sure ${TARGET} is in your PATH."
    fi

    # Install
    cp "${TMP_DIR}/${BINARY}" "${TARGET}/${BINARY}"
    chmod +x "${TARGET}/${BINARY}"

    ok "Installed 1sec ${VERSION} to ${TARGET}/${BINARY}"
    echo ""
    info "Get started:"
    echo "  ${BINARY} up        # Start all defense modules"
    echo "  ${BINARY} status    # Check engine status"
    echo "  ${BINARY} modules   # List all modules"
    echo ""
    ok "Done. Stay secure."
}

main
