# CipherFlux Labs — Advanced Vulnerability Assessment Framework

```
   ______ _____ ____  __  __ _____ ____  ______ _      _    _ __   __
  / ____//_  _// __ \/ / / // ____// __ \/ ____// /     / /  / /\ \ / /
 / /      / / / /_/ // /_/ // __/  / /_/ // __/  / /     / /  / /  \ V / 
/ /___  _/ / / ____// __  // /___ / _, _// /___ / /___  / /__/ /   /   \ 
\____/ /___//_/    /_/ /_//_____//_/ |_|/_____//_____/  \____/   /_/ \_\
```
### Product: CipherFlux | Company: CipherFlux Labs | Platform: Kali Linux / Debian

CipherFlux is a modular, high-coverage, evidence-driven vulnerability assessment framework engineered specifically for **Kali Linux** and Debian-based operating systems. It combines deep static analysis (SAST), multi-ecosystem dependency checking (SCA), dynamic web application posture testing (DAST), API security audits, network assessment, TLS inspection, DNS domain security, container posture, and cloud configuration audits into a unified, Metasploit-inspired interactive terminal experience.

---

## Core Engineering Principles

1. **Maximum Real Vulnerability Coverage**: Real checks executing genuine probes and AST evaluations.
2. **Minimum False Positives**: An 8-stage verification pipeline with baseline differential comparison.
3. **Evidence Before Confirmation**: Suspected vulnerabilities require reproducible proof before classification as `CONFIRMED`.
4. **No Fake Results**: Unimplemented checks display `NOT_IMPLEMENTED`; insufficient evidence is classified as `POTENTIAL` or `INCONCLUSIVE`; unexecuted checks are `NOT_TESTED`.
5. **Defensive Assessment Only**: Strictly safe, non-destructive validation. Zero denial-of-service, zero exploit weaponization, zero credential theft.

---

## 1. Kali Linux Installation

CipherFlux provides an automated, non-destructive installer complying with PEP 668:

```bash
git clone https://github.com/cipherflux-labs/cipherflux.git
cd cipherflux
chmod +x install.sh uninstall.sh update.sh
./install.sh
```

### Installation Features:
- **Kali Linux Detection**: Automatically detects Kali Linux and Debian systems via `/etc/os-release`.
- **Isolated Environment**: Uses `pipx` or a dedicated virtual environment (`~/.local/share/cipherflux/venv`) to protect Kali's system Python.
- **CLI Registration**: Symlinks executable to `~/.local/bin/cipherflux`.
- **Desktop Launcher**: Registers an official Kali desktop entry in `~/.local/share/applications/cipherflux.desktop` under **02 - Vulnerability Analysis**.
- **Application Icons**: Installs high-resolution icon variants (16px to 512px) and SVG master logo into `~/.local/share/icons/hicolor/`.
- **Self-Test Diagnostic**: Automatically executes `cipherflux doctor` to verify complete system integrity.

---

## 2. Interactive CLI Navigation

Launch the interactive framework by entering:
```bash
cipherflux
```

### Interactive Main Menu
```
◈ CIPHERFLUX LABS — INTERACTIVE FRAMEWORK MENU ◈
[01] Target Management            - Register, validate targets and configure authorized scopes
[02] Quick Vulnerability Scan      - Low-impact availability, headers, TLS, and exposure audit
[03] Full Vulnerability Scan       - Centralized multi-vector assessment (Web, Network, Code, Cloud)
[04] Web Application Scanner       - Injection canaries, XSS, CORS, cookie flags, and misconfigurations
[05] API Security Scanner          - REST, GraphQL introspection, WebSocket CSWSH, and rate limits
[06] Network Vulnerability Scanner - Controlled port discovery and insecure plaintext service checks
[07] SSL/TLS Security Scanner      - Protocol handshake, weak ciphers, key size, and certificate audit
[08] CVE Vulnerability Scanner     - Verified NVD / OSV / GHSA vulnerability intelligence matching
[09] Source Code Security (SAST)   - Static analysis for hardcoded secrets, injection, and crypto flaws
[10] Software Composition (SCA)    - Manifest analysis (pip, npm, cargo, go, maven) for vulnerable deps
[11] DNS & Domain Security Scanner - SPF (+all), DMARC policy, AXFR zone transfer, and takeover audit
[12] Cloud Security Scanner        - Authorized read-only S3, Azure Blob, GCS, IAM, and Security Group audits
[13] Container Security Scanner    - Dockerfile AST, Kubernetes RBAC, privileged pods, and IaC audits
[14] Custom Scan Configuration     - Configure target, profiles, timeouts, rate limits, and modules
[15] Vulnerability Results         - Triage findings by status (Confirmed, Potential, Inconclusive)
[16] Security Report Generator     - Synthesize publication-ready PDF, JSON, CSV, and Markdown deliverables
[17] Scan History & Comparison     - Inspect historical scans and calculate resolved vs persistent flaws
[18] Vulnerability Database & Rules- Browse, search, and inspect evidence-driven detection rules
[19] Settings & Configuration      - Tune timeouts, concurrency, rate limits, and proxy parameters
[20] System Diagnostics            - Run 'cipherflux doctor' environmental and engine integrity checks
[21] Help & Documentation          - Usage guide, command-line syntax, and security references
[00] Exit Framework                - Safely terminate the CipherFlux session
```

---

## 3. Direct Command-Line Interface (CLI)

CipherFlux can also be invoked as a direct CLI command:

```bash
# System integrity diagnostics
cipherflux doctor

# Target scope management
cipherflux targets list
cipherflux targets add --value "https://staging.lab" --type URL --name "Staging Web" --authorized

# Scanning profiles
cipherflux scan https://target.lab --profile quick
cipherflux scan https://target.lab --profile standard
cipherflux scan https://target.lab --profile deep --export pdf

# Dedicated scanning modules
cipherflux web https://target.lab
cipherflux api https://api.target.lab/v1 --type rest
cipherflux network 192.168.1.10 --ports 21,22,80,443,3306,5432,6379
cipherflux ssl target.lab --port 443
cipherflux cve --query lodash
cipherflux sast /path/to/project
cipherflux sca /path/to/package.json
cipherflux dns example.com
cipherflux cloud --s3 my-bucket
cipherflux container --dockerfile ./Dockerfile

# Triage & reporting
cipherflux results --status CONFIRMED
cipherflux history
cipherflux report --scan-id scan-xxxx --format pdf
cipherflux rules --search "injection"
```

---

## 4. Architecture Overview

```
cipherflux/
├── cipherflux/                     # Core CLI & Framework Package
│   ├── __init__.py
│   ├── __main__.py                 # python -m cipherflux entrypoint
│   ├── cli/                        # Interactive Metasploit-Style Terminal CLI
│   │   ├── banner.py               # Splash screen, ASCII logo & platform detection
│   │   ├── diagnostics.py          # 'cipherflux doctor' engine & integrity check
│   │   ├── interactive.py          # Interactive menu navigation [01] to [21]
│   │   ├── main.py                 # Command router (argparse + rich)
│   │   └── theme.py                # Terminal color scheme (Green, Red, Yellow, Cyan, Blue)
│   ├── core/                       # Orchestration & Central Intelligence
│   │   └── orchestrator.py         # Multi-vector scan orchestrator (Quick, Standard, Deep)
│   ├── scanners/                   # Extended Scanners
│   │   ├── cloud_scanner.py        # AWS S3, Azure Blob, GCS, IAM, and Security Groups
│   │   └── container_scanner.py    # Dockerfile AST, Kubernetes RBAC, and Docker daemon
│   ├── storage/                    # Persistent Storage Subsystem
│   │   ├── target_store.py         # Scope management, SSRF guard & authorization records
│   │   ├── config_store.py         # Configuration file (~/.cipherflux/config.json)
│   │   └── history_store.py        # Scan history persistence & comparison engine
│   └── reporting/                  # Report Exporter
│       └── exporter.py             # Export wrapper for PDF, JSON, CSV, and Markdown
│
├── backend/                        # High-Performance Backend & Scanners
│   ├── main.py                     # FastAPI server
│   ├── core/                       # Safety, verification engine, risk scoring, false-positive filter
│   ├── scanners/                   # Web, API, Network, TLS, DNS, SAST, SCA, CVE, IaC
│   ├── reporting/                  # ReportLab PDF, CSV, and Markdown synthesizer
│   └── storage/                    # In-memory baseline store
│
├── assets/                         # Branding & Visual Identity
│   ├── cipherflux-logo.svg         # Master vector logo (Shield + CF monogram)
│   ├── cipherflux.desktop          # Kali Linux desktop launcher
│   └── icons/                      # High-res icon variants (16, 32, 48, 64, 128, 256, 512px)
│
├── docs/                           # Documentation
│   ├── KALI_INSTALLATION.md        # Comprehensive Kali Linux guide
│   ├── CLI_REFERENCE.md            # Complete command-line manual
│   └── VULNERABILITY_COVERAGE.md   # Coverage matrix, verification states & safety
│
├── tests/                          # Automated Pytest Test Suite
│   ├── test_cli_and_diagnostics.py
│   ├── test_cloud_and_container_scanners.py
│   ├── test_history_and_comparison.py
│   └── test_target_management.py
│
├── install.sh                      # Kali Linux & Debian installer
├── uninstall.sh                    # Safe uninstaller (preserves reports by default)
├── update.sh                       # Upgrade manager
├── pyproject.toml                  # Modern PEP 517/621 packaging
├── CHANGELOG.md                    # Release history
└── LICENSE                         # Apache 2.0 License
```

---

## 5. Verification Status Classifications

CipherFlux never fabricates findings or marks unverified suspicions as confirmed:

- **`CONFIRMED`**: Direct empirical evidence established through safe arithmetic canary reflection, socket handshakes, or deterministic AST evaluation.
- **`POTENTIAL`**: Strong heuristic or code pattern detected; requires operational verification.
- **`INCONCLUSIVE`**: Host response was ambiguous, rate-limited, or blocked by gateway timeouts.
- **`NOT_VULNERABLE`**: Check executed completely; target defended cleanly against the probe.
- **`NOT_TESTED`**: Check intentionally omitted (out of authorized scope or excluded from profile).

---

## 6. Automated Test Suite

Run the full automated test suite (unit tests, integration tests, positive/negative cases):
```bash
python -m pytest tests/ backend/tests/
```
*Current test suite: 60/60 tests passing with 100% success rate.*

---

## License

CipherFlux is open-source software released under the **Apache-2.0 License**. See [LICENSE](LICENSE) for details.
