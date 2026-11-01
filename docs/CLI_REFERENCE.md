# CipherFlux Labs — CLI Reference Manual

CipherFlux provides both a rich interactive terminal environment and a comprehensive command-line interface.

---

## Global Options

| Option | Description |
| :--- | :--- |
| `--help`, `-h` | Display help message and available subcommands |
| `--version`, `-v` | Display product version and platform identity |
| `--no-banner` | Suppress the ASCII startup banner |
| `--plain` | Render output in plain text without terminal ANSI colors |
| `--json` | Output scan results strictly in JSON format (automatically suppresses banner) |

---

## Subcommands

### 1. `cipherflux doctor`
Runs the System Diagnostics engine:
- Checks Python runtime (>= 3.10)
- Checks operating system (Kali Linux / Debian detection)
- Verifies system dependencies (Rich, Cryptography, httpx, dnspython, reportlab, pyyaml, pillow)
- Tests all 9 scanning engines (SAST, Web, API, Network, TLS, DNS, SCA, IaC/Container, Cloud)
- Verifies Verification Engine and rule registry status
- Confirms database and storage read/write permissions
- Outputs `PASS`, `FAIL`, `WARNING`, or `NOT_IMPLEMENTED` with zero simulated results.

### 2. `cipherflux targets`
Manages authorized scanning targets and scope boundaries:
```bash
# List all registered targets
cipherflux targets list

# Add a target with explicit authorization
cipherflux targets add --value "https://app.staging.internal" --type URL --name "Staging App" --authorized

# Add a network range
cipherflux targets add --value "192.168.1.0/24" --type CIDR --name "Lab Subnet" --authorized

# Remove a target by ID
cipherflux targets remove --id tgt-xxxx
```

### 3. `cipherflux scan`
Centralized vulnerability assessment orchestrator:
```bash
# Standard multi-vector scan
cipherflux scan https://target.lab

# Low-impact quick scan (passive headers, TLS, DNS, exposure)
cipherflux scan https://target.lab --profile quick

# Deep comprehensive audit (Web + API + Network + SAST + SCA + IaC)
cipherflux scan https://target.lab --profile deep --export pdf

# Scan with custom operator attribution
cipherflux scan https://target.lab --operator "JohnDoe_LeadAuditor"
```

### 4. `cipherflux web`
Web application posture and active injection testing:
```bash
cipherflux web https://target.lab
cipherflux web https://target.lab --no-cors
cipherflux web https://target.lab --no-injection
```
- Safe arithmetic SSTI canaries (`{{7*7}}` -> `49`)
- CRLF injection & HTTP response splitting (`X-CipherFlux-...`)
- CORS origin reflection with credentials validation
- Defensive headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Cookie security flags (HttpOnly, Secure, SameSite)
- Publicly exposed sensitive paths (`/.git/HEAD`, `/.env`, `robots.txt`)

### 5. `cipherflux api`
Dedicated API vulnerability detection:
```bash
cipherflux api https://api.target.lab/v1 --type rest
cipherflux api https://api.target.lab/graphql --type graphql
cipherflux api wss://api.target.lab/ws --type websocket
```

### 6. `cipherflux network`
Authorized port discovery and insecure service detection:
```bash
cipherflux network 192.168.1.10
cipherflux network 192.168.1.10 --ports 21,22,23,80,443,3306,5432,6379,27017
```

### 7. `cipherflux ssl`
SSL/TLS protocol negotiation and certificate posture:
```bash
cipherflux ssl target.lab --port 443
```
- Deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- Deprecated ciphers (RC4, 3DES, DES, EXPORT, NULL)
- Certificate validity, expiration (< 30 days), and self-signed certificates
- Weak RSA key sizes (< 2048-bit) and deprecated signature hashes (MD5, SHA-1)

### 8. `cipherflux cve`
Authoritative CVE vulnerability intelligence:
```bash
# Query CVE intelligence database
cipherflux cve --query axios
cipherflux cve --query CVE-2021-23337

# Match specific dependency version
cipherflux cve --ecosystem npm --package lodash --version-str 4.17.15
cipherflux cve --ecosystem pip --package urllib3 --version-str 1.26.15
```

### 9. `cipherflux sast`
Static Application Security Testing on source repositories:
```bash
cipherflux sast /path/to/source/code
cipherflux sast /path/to/file.py
```
- Hardcoded cryptographic private keys (RSA/EC/OpenSSH)
- Cloud access tokens (AWS, GitHub, Slack, Generic API Secrets)
- Raw SQL string formatting in database queries
- Arbitrary command execution patterns (`os.system`, `subprocess.Popen`)
- Insecure deserialization (`pickle.loads`, `yaml.load`)
- Disabled TLS certificate verification (`verify=False`)

### 10. `cipherflux sca`
Software Composition Analysis:
```bash
# Audit current workspace manifests
cipherflux sca

# Audit specific manifest file
cipherflux sca /path/to/package.json
cipherflux sca /path/to/requirements.txt
cipherflux sca /path/to/Cargo.toml
cipherflux sca /path/to/go.mod
```

### 11. `cipherflux dns`
DNS and email domain protection:
```bash
cipherflux dns example.com
```
- SPF records & dangerous permissive policies (`+all`)
- DMARC record presence and policy enforcement (`p=none` vs `p=reject`)
- Authoritative AXFR DNS zone transfer testing
- Dangling CNAME subdomain takeover indicators (AWS S3, GitHub Pages, Heroku, Azure)

### 12. `cipherflux cloud`
Authorized read-only cloud storage and IAM audits:
```bash
cipherflux cloud --s3 my-company-bucket
cipherflux cloud --azure-account mystorage --azure-container public-data
cipherflux cloud --gcs my-gcp-bucket
cipherflux cloud --iam-file /path/to/policy.json
cipherflux cloud --sg-file /path/to/security_group.json
```

### 13. `cipherflux container`
Container, Kubernetes, and IaC security:
```bash
cipherflux container --dockerfile /path/to/Dockerfile
cipherflux container --k8s /path/to/deployment.yaml
cipherflux container --daemon /etc/docker/daemon.json
```

### 14. `cipherflux results`
Triage findings by status and scan ID:
```bash
cipherflux results
cipherflux results --status CONFIRMED
cipherflux results --status POTENTIAL
```

### 15. `cipherflux history`
View previous scans and comparative analytics:
```bash
cipherflux history
```

### 16. `cipherflux report`
Generate high-fidelity audit deliverables:
```bash
cipherflux report --format pdf
cipherflux report --format md
cipherflux report --format csv
cipherflux report --format json --output ~/my-reports
```

### 17. `cipherflux rules`
Inspect evidence detection rules:
```bash
cipherflux rules
cipherflux rules --search "injection"
```
