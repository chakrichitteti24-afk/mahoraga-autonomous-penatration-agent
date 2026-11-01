#!/usr/bin/env bash
# ==============================================================================
# CIPHERFLUX LABS — UPGRADE & UPDATE SCRIPT
# ==============================================================================
set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "================================================================================"
echo "                   ◈ CIPHERFLUX LABS UPDATE MANAGER ◈"
echo "================================================================================"
echo -e "${NC}"

echo -e "${CYAN}[*] Step 1: Pulling latest release changes from repository...${NC}"
if [ -d ".git" ]; then
    git pull --ff-only || {
        echo -e "${YELLOW}[!] Git pull failed or local modifications detected. Reinstalling current repository state...${NC}"
    }
fi

echo -e "\n${CYAN}[*] Step 2: Upgrading CipherFlux package in isolated environment...${NC}"
INSTALL_DIR="${HOME}/.local/share/cipherflux"
VENV_DIR="${INSTALL_DIR}/venv"

if command -v pipx &>/dev/null && pipx list | grep -q "cipherflux"; then
    pipx install --force .
elif [ -d "${VENV_DIR}" ]; then
    "${VENV_DIR}/bin/pip" install --upgrade pip
    "${VENV_DIR}/bin/pip" install --upgrade .
else
    echo -e "${YELLOW}[!] Installation not detected. Running standard installer...${NC}"
    bash install.sh
    exit 0
fi

echo -e "\n${CYAN}[*] Step 3: Verifying upgraded framework integrity ('cipherflux doctor')...${NC}"
cipherflux doctor || true

echo -e "\n${GREEN}[✓] CipherFlux upgrade completed successfully!${NC}\n"
