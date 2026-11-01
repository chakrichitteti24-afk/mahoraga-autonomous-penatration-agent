#!/usr/bin/env bash
# ==============================================================================
# CIPHERFLUX LABS — KALI LINUX & DEBIAN INSTALLATION SCRIPT
# Product: CipherFlux — Advanced Vulnerability Assessment Framework
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

echo -e "${CYAN}"
echo "================================================================================"
echo "                   ◈ CIPHERFLUX LABS INSTALLATION WIZARD ◈"
echo "             ADVANCED VULNERABILITY ASSESSMENT FRAMEWORK FOR KALI LINUX"
echo "================================================================================"
echo -e "${NC}"

# 1. Platform Detection
echo -e "${CYAN}[*] Step 1: Detecting Host Operating System...${NC}"
IS_KALI=false
OS_NAME="Unknown Linux"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="${PRETTY_NAME:-$NAME}"
    if echo "$OS_NAME" | grep -iq "kali"; then
        IS_KALI=true
        echo -e "${GREEN}[✓] Platform Verified: Kali Linux (${OS_NAME})${NC}"
    elif echo "$OS_NAME" | grep -iq "debian" || echo "$OS_NAME" | grep -iq "ubuntu"; then
        echo -e "${GREEN}[✓] Platform Verified: Debian-compatible distribution (${OS_NAME})${NC}"
    else
        echo -e "${YELLOW}[!] Notice: Running on ${OS_NAME}. Proceeding with Linux installation.${NC}"
    fi
else
    echo -e "${YELLOW}[!] Warning: /etc/os-release not detected.${NC}"
fi

# 2. Python Version Check
echo -e "\n${CYAN}[*] Step 2: Checking Python Runtime Version...${NC}"
PYTHON_BIN=""
for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        MAJOR=$("$cmd" -c 'import sys; print(sys.version_info.major)')
        MINOR=$("$cmd" -c 'import sys; print(sys.version_info.minor)')
        if [ "$MAJOR" -eq 3 ] && [ "$MINOR" -ge 10 ]; then
            PYTHON_BIN="$cmd"
            echo -e "${GREEN}[✓] Qualified Python Runtime Found: ${cmd} (v${VER})${NC}"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[✗] Error: Python 3.10 or higher is required. Please install Python 3.10+ and re-run.${NC}"
    echo -e "    On Kali/Debian: sudo apt update && sudo apt install -y python3 python3-pip python3-venv"
    exit 1
fi

# 3. System Dependencies Check
echo -e "\n${CYAN}[*] Step 3: Verifying System Dependencies...${NC}"
REQUIRED_PKGS=()
if ! command -v git &>/dev/null; then REQUIRED_PKGS+=("git"); fi

if [ ${#REQUIRED_PKGS[@]} -gt 0 ]; then
    echo -e "${YELLOW}[!] Missing system packages: ${REQUIRED_PKGS[*]}${NC}"
    if [ "$(id -u)" -eq 0 ]; then
        apt-get update && apt-get install -y "${REQUIRED_PKGS[@]}"
    elif command -v sudo &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y "${REQUIRED_PKGS[@]}"
    else
        echo -e "${RED}[✗] Cannot install dependencies: root or sudo required.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}[✓] System dependencies verified.${NC}"

# 4. Isolated Virtual Environment Installation
INSTALL_DIR="${HOME}/.local/share/cipherflux"
BIN_DIR="${HOME}/.local/bin"
VENV_DIR="${INSTALL_DIR}/venv"

echo -e "\n${CYAN}[*] Step 4: Installing CipherFlux in Isolated Environment...${NC}"
mkdir -p "${INSTALL_DIR}"
mkdir -p "${BIN_DIR}"

if command -v pipx &>/dev/null; then
    echo -e "${CYAN}[*] Utilizing pipx for isolated application management...${NC}"
    pipx install --force .
else
    echo -e "${CYAN}[*] Setting up dedicated virtual environment at ${VENV_DIR}...${NC}"
    "$PYTHON_BIN" -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel
    "${VENV_DIR}/bin/pip" install .

    # Symlink CLI wrapper
    ln -sf "${VENV_DIR}/bin/cipherflux" "${BIN_DIR}/cipherflux"
    chmod +x "${BIN_DIR}/cipherflux"
fi

# Ensure ~/.local/bin is in PATH
if ! echo "$PATH" | grep -q "${BIN_DIR}"; then
    echo -e "${YELLOW}[!] Adding ${BIN_DIR} to your shell profile (~/.bashrc and ~/.zshrc)...${NC}"
    export PATH="${BIN_DIR}:${PATH}"
    for rc in "${HOME}/.bashrc" "${HOME}/.zshrc"; do
        if [ -f "$rc" ] && ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$rc"; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
        fi
    done
fi

echo -e "${GREEN}[✓] CLI executable registered: ${BIN_DIR}/cipherflux${NC}"

# 5. Icon & Desktop Integration
echo -e "\n${CYAN}[*] Step 5: Installing Kali Application Menu & Icons...${NC}"
ICON_SIZES=(16 32 48 64 128 256 512)
for size in "${ICON_SIZES[@]}"; do
    TARGET_ICON_DIR="${HOME}/.local/share/icons/hicolor/${size}x${size}/apps"
    mkdir -p "${TARGET_ICON_DIR}"
    if [ -f "assets/icons/icon-${size}.png" ]; then
        cp "assets/icons/icon-${size}.png" "${TARGET_ICON_DIR}/cipherflux.png"
    fi
done

# Scalable SVG Icon
SCALABLE_DIR="${HOME}/.local/share/icons/hicolor/scalable/apps"
mkdir -p "${SCALABLE_DIR}"
if [ -f "assets/cipherflux-logo.svg" ]; then
    cp "assets/cipherflux-logo.svg" "${SCALABLE_DIR}/cipherflux.svg"
fi

# Desktop Entry
APP_DIR="${HOME}/.local/share/applications"
mkdir -p "${APP_DIR}"
if [ -f "assets/cipherflux.desktop" ]; then
    cp "assets/cipherflux.desktop" "${APP_DIR}/cipherflux.desktop"
    chmod +x "${APP_DIR}/cipherflux.desktop"
fi

# Refresh desktop database caches if utilities present
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "${APP_DIR}" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f -t "${HOME}/.local/share/icons/hicolor" 2>/dev/null || true
fi

echo -e "${GREEN}[✓] Kali Application Menu and Desktop integration complete.${NC}"

# 6. Installation Verification via Diagnostics
echo -e "\n${CYAN}[*] Step 6: Executing System Diagnostics Verification ('cipherflux doctor')...${NC}"
if [ -x "${BIN_DIR}/cipherflux" ]; then
    "${BIN_DIR}/cipherflux" doctor || true
fi

echo -e "\n${GREEN}================================================================================${NC}"
echo -e "${GREEN}      ◈ CIPHERFLUX LABS SUCCESSFULLY INSTALLED ON KALI LINUX ◈${NC}"
echo -e "${GREEN}================================================================================${NC}"
echo -e "${WHITE}To start the interactive terminal framework:${NC}"
echo -e "    ${CYAN}cipherflux${NC}"
echo -e ""
echo -e "${WHITE}To run direct CLI vulnerability commands:${NC}"
echo -e "    ${CYAN}cipherflux scan <target-url>${NC}"
echo -e "    ${CYAN}cipherflux doctor${NC}"
echo -e "    ${CYAN}cipherflux report --format pdf${NC}"
echo -e ""
echo -e "${WHITE}You can also launch CipherFlux directly from the Kali Applications Menu:${NC}"
echo -e "    ${CYAN}Applications -> 02 - Vulnerability Analysis -> CipherFlux${NC}"
echo -e "${GREEN}================================================================================${NC}"
