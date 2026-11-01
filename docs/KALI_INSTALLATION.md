# CipherFlux Labs — Kali Linux Installation Guide

This guide walks you through installing, configuring, and verifying **CipherFlux** on **Kali Linux** or any modern Debian-based distribution.

---

## 1. Prerequisites

CipherFlux requires **Python 3.10** or higher. Kali Linux 2023.x / 2024.x ships with Python 3.11+ by default.

Verify your Python runtime:
```bash
python3 --version
```

Install standard Kali Linux development prerequisites if not already present:
```bash
sudo apt update
sudo apt install -y git python3-pip python3-venv pipx libssl-dev libffi-dev
```

---

## 2. Quick One-Line Installation

Clone the repository and run the automated Kali Linux installation script:

```bash
git clone https://github.com/cipherflux-labs/cipherflux.git
cd cipherflux
chmod +x install.sh uninstall.sh update.sh
./install.sh
```

### What `install.sh` Does:
1. **Verifies Operating System**: Checks `/etc/os-release` for Kali Linux / Debian compatibility.
2. **Checks Python Compatibility**: Confirms Python 3.10+ runtime.
3. **Creates Isolated Virtual Environment**: Installs CipherFlux cleanly into `~/.local/share/cipherflux/venv` using `pipx` or a dedicated virtual environment, strictly adhering to Debian/Kali's PEP 668 non-destructive packaging guidelines.
4. **Registers CLI Executable**: Links `cipherflux` into `~/.local/bin/cipherflux` and verifies your `PATH`.
5. **Installs Desktop Icons**: Copies high-resolution PNG icon variants (16px to 512px) and the master SVG logo to `~/.local/share/icons/hicolor/`.
6. **Creates Desktop Menu Launcher**: Installs `cipherflux.desktop` into `~/.local/share/applications/` so that CipherFlux appears in the **Kali Application Menu** under:
   `Applications -> 02 - Vulnerability Analysis -> CipherFlux`
7. **Executes Diagnostic Audit**: Automatically runs `cipherflux doctor` to verify complete installation integrity.

---

## 3. Launching CipherFlux

### Interactive Terminal Mode (Metasploit-Inspired Experience)
Simply run:
```bash
cipherflux
```

### Launching from the Kali Desktop
Open the Kali Whisker application menu:
- Navigate to **02 - Vulnerability Analysis**
- Click **CipherFlux**
- A terminal window will open with the ASCII banner and interactive main menu.

### Direct Command-Line Execution
CipherFlux functions seamlessly as a standalone Kali Linux command:
```bash
# Verify system integrity
cipherflux doctor

# List authorized scan targets
cipherflux targets list

# Execute quick security audit
cipherflux scan https://target.lab --profile quick

# Audit web application security headers & injection canaries
cipherflux web https://target.lab

# Execute authorized service port scan
cipherflux network 192.168.1.10

# Audit SSL/TLS certificates and cipher suites
cipherflux ssl target.lab --port 443

# Search verified CVE intelligence database
cipherflux cve --query lodash

# Perform SAST audit on local source code
cipherflux sast /path/to/project

# Audit project dependencies (SCA)
cipherflux sca /path/to/package.json

# Export official audit report in PDF format
cipherflux report --format pdf
```

---

## 4. Upgrading CipherFlux

To upgrade your installation to the latest release:
```bash
cd cipherflux
./update.sh
```

---

## 5. Uninstallation

To safely remove CipherFlux from your Kali Linux machine:
```bash
cd cipherflux
./uninstall.sh
```
*Note: The uninstaller prompts whether to preserve or purge your previous audit reports and target databases stored in `~/.cipherflux/`.*
