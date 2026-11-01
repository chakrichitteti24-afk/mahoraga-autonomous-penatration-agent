#!/usr/bin/env bash
# ==============================================================================
# CIPHERFLUX LABS — SAFE UNINSTALLATION SCRIPT
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${YELLOW}"
echo "================================================================================"
echo "                  ◈ CIPHERFLUX LABS UNINSTALLATION WIZARD ◈"
echo "================================================================================"
echo -e "${NC}"

read -r -p "Are you sure you want to uninstall CipherFlux? [y/N]: " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}[*] Uninstallation cancelled.${NC}"
    exit 0
fi

# 1. Remove CLI binary wrapper
BIN_PATH="${HOME}/.local/bin/cipherflux"
if [ -f "$BIN_PATH" ] || [ -L "$BIN_PATH" ]; then
    rm -f "$BIN_PATH"
    echo -e "${GREEN}[✓] Removed CLI binary: ${BIN_PATH}${NC}"
fi

# 2. Remove isolated installation directory
INSTALL_DIR="${HOME}/.local/share/cipherflux"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo -e "${GREEN}[✓] Removed installation directory: ${INSTALL_DIR}${NC}"
fi

# 3. Remove Desktop Entry
DESKTOP_PATH="${HOME}/.local/share/applications/cipherflux.desktop"
if [ -f "$DESKTOP_PATH" ]; then
    rm -f "$DESKTOP_PATH"
    echo -e "${GREEN}[✓] Removed Kali application launcher: ${DESKTOP_PATH}${NC}"
fi

# 4. Remove Icons
ICON_SIZES=(16 32 48 64 128 256 512)
for size in "${ICON_SIZES[@]}"; do
    ICON_FILE="${HOME}/.local/share/icons/hicolor/${size}x${size}/apps/cipherflux.png"
    if [ -f "$ICON_FILE" ]; then
        rm -f "$ICON_FILE"
    fi
done
SVG_FILE="${HOME}/.local/share/icons/hicolor/scalable/apps/cipherflux.svg"
if [ -f "$SVG_FILE" ]; then
    rm -f "$SVG_FILE"
fi
echo -e "${GREEN}[✓] Removed application icons.${NC}"

# Refresh desktop database caches
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "${HOME}/.local/share/applications" 2>/dev/null || true
fi

# 5. User Data & Scan Reports
DATA_DIR="${HOME}/.cipherflux"
echo ""
echo -e "${YELLOW}[!] User Data & Audit Reports are located at: ${DATA_DIR}${NC}"
read -r -p "Do you also want to delete all historical scan reports and targets? [y/N]: " purge_data
if [[ "$purge_data" =~ ^[Yy]$ ]]; then
    if [ -d "$DATA_DIR" ]; then
        rm -rf "$DATA_DIR"
        echo -e "${RED}[✓] Purged user reports and configurations: ${DATA_DIR}${NC}"
    fi
else
    echo -e "${GREEN}[✓] Preserved user scan reports and target database in ${DATA_DIR}${NC}"
fi

echo -e "\n${GREEN}[✓] CipherFlux has been safely uninstalled from your system.${NC}\n"
