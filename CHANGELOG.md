# Changelog — CipherFlux Labs

All notable changes to the CipherFlux vulnerability assessment framework are documented in this file.

## [1.0.0] - 2026-11-01

### Added
- **Core CLI Framework**:
  - Metasploit-inspired interactive terminal menu with 21 structured options.
  - Rich-rendered cybernetic ASCII logo, banner, and custom terminal theme.
  - Complete command router supporting `cipherflux doctor`, `cipherflux targets`, `cipherflux scan`, `cipherflux web`, `cipherflux api`, `cipherflux network`, `cipherflux ssl`, `cipherflux cve`, `cipherflux sast`, `cipherflux sca`, `cipherflux dns`, `cipherflux cloud`, `cipherflux container`, `cipherflux results`, `cipherflux history`, `cipherflux report`, and `cipherflux rules`.
  - Seamless JSON output mode (`--json`) with banner suppression.
- **Target Management Module**:
  - Persistent target registry (`targets.json`) supporting URLs, IPs, CIDR ranges, APIs, and Domains.
  - Strict SSRF and cloud metadata (`169.254.169.254`, `metadata.google.internal`) protection.
  - Mandatory authorization records and scope validation before scan execution.
  - Import/Export capabilities in both JSON and CSV formats.
- **Scanning Engines**:
  - **Quick Scan Profile**: Low-impact passive assessment of availability, headers, TLS certs, and exposures.
  - **Full Scan Orchestrator**: Concurrently orchestrates Web, API, Network, SSL/TLS, DNS, SAST, SCA, and IaC/Container engines.
  - **Cloud Security Scanner**: Read-only audits for AWS S3 public bucket listings, Azure Blob containers, Google Cloud Storage, IAM wildcard policies, and security group open ports.
  - **Container & Kubernetes Scanner**: Dockerfile instruction AST, Kubernetes RBAC wildcard privilege detection, hostPID namespace sharing, and Docker daemon socket exposure.
  - **Web Application Scanner**: Safe non-destructive arithmetic SSTI canaries (`{{7*7}}`), CRLF response splitting indicators, CORS reflection with credentials, and cookie security flags.
  - **API Security Scanner**: REST rate limiting checks, GraphQL introspection queries, and WebSocket CSWSH origin verification.
  - **Network Scanner**: Controlled port discovery and plaintext service exposure checks (FTP, Telnet, SMB, Redis, MongoDB, MySQL, Postgres, Elasticsearch).
  - **SSL/TLS Scanner**: Protocol negotiation (SSLv2, SSLv3, TLS 1.0, 1.1), weak cipher detection (RC4, 3DES, DES, NULL), certificate expiration, and RSA key size verification.
  - **CVE Vulnerability Scanner**: Verified CVE intelligence database matching across npm, pip, cargo, go, maven, and composer ecosystems.
  - **SAST Scanner**: Static analysis for hardcoded private keys, cloud tokens, SQL injection patterns, command execution, and insecure deserialization.
  - **SCA Scanner**: Multi-ecosystem software composition analysis for vulnerable and unpinned dependencies.
  - **DNS & Domain Scanner**: Audits SPF permissive policies (`+all`), DMARC enforcement, AXFR zone transfer leaks, and dangling CNAME takeover indicators.
- **Verification & False-Positive Elimination**:
  - Independent non-destructive verification engine with statuses: `CONFIRMED`, `POTENTIAL`, `INCONCLUSIVE`, `NOT_VULNERABLE`, `NOT_TESTED`.
  - Authoritative rule registry with reproducible evidence requirements and false-positive criteria.
  - Automatic token redaction across all logs, snippets, and reports.
- **Reporting Engine**:
  - Multi-format publication-ready report generation in PDF, GitHub-flavored Markdown, CSV, and structured JSON (complying with 21 standard report attributes).
- **Kali Linux System Integration**:
  - Dedicated `install.sh` with Kali Linux detection and isolated venv/pipx packaging.
  - Original application icon variants (16, 32, 48, 64, 128, 256, 512px) and SVG master logo.
  - Kali Linux application menu entry under `02 - Vulnerability Analysis`.
  - Safe `uninstall.sh` and `update.sh` scripts.
  - Comprehensive `cipherflux doctor` system diagnostics.
