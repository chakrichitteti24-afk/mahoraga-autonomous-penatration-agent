import pytest
from backend.scanners.sast_scanner import SASTScanner
from backend.scanners.sca_scanner import SCAScanner
from backend.scanners.iac_scanner import IaCScanner
from backend.scanners.tls_scanner import TLSScanner
from backend.scanners.dns_scanner import DNSDomainScanner
from backend.scanners.api_scanner import APISecurityScanner
from backend.scanners.cve_engine import cve_engine
from backend.models.schemas import SeverityLevel, VerificationStatus

# --- SAST TESTS: POSITIVE AND NEGATIVE ---

def test_sast_positive_sql_injection():
    scanner = SASTScanner()
    code = "cursor.execute(f'SELECT * FROM accounts WHERE user_id = {uid}')"
    findings = scanner.scan_code_snippet(code, language="python")
    assert any(f.cweId == "CWE-89" for f in findings)
    assert any(f.severity == SeverityLevel.CRITICAL for f in findings)

def test_sast_negative_parameterized_sql():
    scanner = SASTScanner()
    code = "cursor.execute('SELECT * FROM accounts WHERE user_id = %s', (uid,))"
    findings = scanner.scan_code_snippet(code, language="python")
    assert not any(f.cweId == "CWE-89" for f in findings), "Parameterized query should not trigger SQLi finding"

def test_sast_positive_command_injection():
    scanner = SASTScanner()
    code = "subprocess.run('rm -rf ' + user_folder, shell=True)"
    findings = scanner.scan_code_snippet(code, language="python")
    assert any(f.cweId == "CWE-78" for f in findings)

def test_sast_negative_safe_command_execution():
    scanner = SASTScanner()
    code = "subprocess.run(['ls', '-la', safe_path], shell=False, check=True)"
    findings = scanner.scan_code_snippet(code, language="python")
    assert not any(f.cweId == "CWE-78" for f in findings)

def test_sast_positive_ssti():
    scanner = SASTScanner()
    code = "return render_template_string('Hello ' + request.args.get('name'))"
    findings = scanner.scan_code_snippet(code, language="python")
    assert any(f.cweId == "CWE-1336" for f in findings)

def test_sast_positive_insecure_deserialization():
    scanner = SASTScanner()
    code = "user_obj = pickle.loads(raw_user_bytes)"
    findings = scanner.scan_code_snippet(code, language="python")
    assert any(f.cweId == "CWE-502" for f in findings)

def test_sast_negative_safe_yaml():
    scanner = SASTScanner()
    code = "data = yaml.safe_load(config_str)"
    findings = scanner.scan_code_snippet(code, language="python")
    assert not any(f.cweId == "CWE-502" for f in findings)

def test_sast_positive_disabled_tls():
    scanner = SASTScanner()
    code = "resp = requests.get('https://internal.service', verify=False)"
    findings = scanner.scan_code_snippet(code, language="python")
    assert any(f.cweId == "CWE-295" for f in findings)

def test_sast_positive_github_token():
    scanner = SASTScanner()
    code = "TOKEN = 'ghp_111122223333444455556666777788889999'"
    findings = scanner.scan_code_snippet(code, language="python")
    assert any(f.cweId == "CWE-798" for f in findings)

# --- SCA TESTS ACROSS ECOSYSTEMS ---

def test_sca_npm_positive_and_negative():
    scanner = SCAScanner()
    # Vulnerable lodash
    vuln_manifest = '{"dependencies": {"lodash": "4.17.15"}}'
    vuln_findings = scanner.scan_npm_manifest(vuln_manifest)
    assert any(f.cveId == "CVE-2021-23337" for f in vuln_findings)

    # Patched lodash
    patched_manifest = '{"dependencies": {"lodash": "4.17.21"}}'
    patched_findings = scanner.scan_npm_manifest(patched_manifest)
    assert not any(f.cveId == "CVE-2021-23337" for f in patched_findings)

def test_sca_pip_positive_and_negative():
    scanner = SCAScanner()
    # Vulnerable urllib3
    vuln_req = "urllib3==2.0.5\nrequests==2.31.0"
    vuln_findings = scanner.scan_pip_manifest(vuln_req)
    assert any(f.cveId == "CVE-2023-45803" for f in vuln_findings)

    # Patched urllib3
    patched_req = "urllib3==2.0.7\nrequests==2.31.0"
    patched_findings = scanner.scan_pip_manifest(patched_req)
    assert not any(f.cveId == "CVE-2023-45803" for f in patched_findings)

def test_sca_cargo_positive():
    scanner = SCAScanner()
    cargo_toml = """
    [dependencies]
    openssl = "0.10.55"
    """
    findings = scanner.scan_cargo_manifest(cargo_toml)
    assert any(f.cveId == "CVE-2023-38197" for f in findings)

def test_sca_go_positive():
    scanner = SCAScanner()
    go_mod = """
    module myapp
    go 1.20
    require (
        golang.org/x/net v0.15.0
    )
    """
    findings = scanner.scan_go_manifest(go_mod)
    assert any(f.cveId == "CVE-2023-39325" for f in findings)

def test_sca_maven_positive():
    scanner = SCAScanner()
    pom_xml = """
    <project>
      <dependencies>
        <dependency>
          <groupId>org.apache.logging.log4j</groupId>
          <artifactId>log4j-core</artifactId>
          <version>2.14.1</version>
        </dependency>
      </dependencies>
    </project>
    """
    findings = scanner.scan_maven_manifest(pom_xml)
    assert any(f.cveId == "CVE-2021-44228" for f in findings)

def test_sca_dependency_confusion():
    scanner = SCAScanner()
    manifest = '{"dependencies": {"internal-billing-service": "1.0.0"}}'
    findings = scanner.scan_npm_manifest(manifest)
    assert any("Dependency Confusion" in f.title for f in findings)

# --- IAC & CONTAINER SECURITY TESTS ---

def test_iac_dockerfile_root_user():
    scanner = IaCScanner()
    dockerfile = """
    FROM alpine:3.18
    RUN apk add --no-cache curl
    CMD ["curl", "https://example.com"]
    """
    findings = scanner.scan_dockerfile(dockerfile)
    assert any("Missing Non-Root USER Directive" in f.title for f in findings)

def test_iac_dockerfile_safe_user():
    scanner = IaCScanner()
    dockerfile = """
    FROM alpine:3.18
    RUN adduser -D appuser
    USER appuser
    CMD ["echo", "hello"]
    """
    findings = scanner.scan_dockerfile(dockerfile)
    assert not any("Missing Non-Root USER Directive" in f.title for f in findings)

def test_iac_dockerfile_embedded_secret():
    scanner = IaCScanner()
    dockerfile = """
    FROM python:3.10-slim
    ENV DB_PASSWORD=SuperSecretPass123!
    """
    findings = scanner.scan_dockerfile(dockerfile)
    assert any("Embedded Secret in Dockerfile ENV" in f.title for f in findings)

def test_iac_kubernetes_privileged_pod():
    scanner = IaCScanner()
    k8s_yaml = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: test-pod
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: nginx:1.24
        securityContext:
          privileged: true
    """
    findings = scanner.scan_kubernetes_yaml(k8s_yaml)
    assert any("privileged: true" in f.title for f in findings)
    assert any("hostNetwork: true" in f.title for f in findings)

def test_iac_terraform_public_s3():
    scanner = IaCScanner()
    tf_content = """
    resource "aws_s3_bucket" "b" {
      bucket = "my-public-bucket"
      acl    = "public-read"
    }
    """
    findings = scanner.scan_terraform(tf_content)
    assert any("S3 Bucket Configured with Public Access" in f.title for f in findings)
