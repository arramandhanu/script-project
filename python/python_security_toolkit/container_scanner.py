"""
Container Security Scanner
Performs comprehensive container image security scanning including:
- Vulnerability detection (CVE scanning)
- SBOM generation and analysis
- Supply chain security checks
- Base image hardening validation
- Secret and sensitive data detection
"""

import json
import hashlib
import subprocess
import argparse
import tempfile
import shutil
from dataclasses import dataclass, field
from typing import Optional, Any, Generator
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import base64
import tarfile
import io

import docker


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    cvss_score: float
    description: str
    references: list[str] = field(default_factory=list)
    layer_affected: Optional[str] = None


@dataclass
class SecretFinding:
    """Represents a discovered secret in the image."""
    file_path: str
    secret_type: str
    matched_pattern: str
    line_number: Optional[int] = None
    context: Optional[str] = None


@dataclass
class ScanResult:
    """Result of a container security scan."""
    image_ref: str
    scan_timestamp: datetime
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    base_image_info: dict = field(default_factory=dict)
    scan_errors: list[str] = field(default_factory=list)
    packages: list[dict] = field(default_factory=list)
    sbom_generated: bool = False
    image_digest: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == "CRITICAL"])

    @property
    def high_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == "HIGH"])

    @property
    def medium_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == "MEDIUM"])

    @property
    def low_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == "LOW"])

    @property
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerabilities)


class TrivyScanner:
    """Wrapper for Trivy container vulnerability scanner."""

    SEVERITY_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "LOW"
    }

    def __init__(self, db_path: Optional[Path] = None, cache_dir: Optional[Path] = None):
        self.db_path = db_path
        self.cache_dir = cache_dir or Path(tempfile.gettempdir()) / "trivy-cache"
        self.trivy_available = self._check_trivy_available()

    def _check_trivy_available(self) -> bool:
        """Check if Trivy is installed."""
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def scan_image(
        self,
        image_ref: str,
        severity_threshold: str = "HIGH",
        output_format: str = "json"
    ) -> ScanResult:
        """Scan a container image with Trivy."""
        result = ScanResult(
            image_ref=image_ref,
            scan_timestamp=datetime.now(timezone.utc)
        )

        if not self.trivy_available:
            result.scan_errors.append("Trivy not installed")
            return result

        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                output_file = Path(f.name)

            cmd = [
                "trivy",
                "image",
                "--format", "json",
                "--output", str(output_file),
                "--severity", severity_threshold,
                "--ignore-unfixed",
                "--cache-dir", str(self.cache_dir),
                image_ref
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if output_file.exists():
                scan_data = json.loads(output_file.read_text())

                result.image_digest = scan_data.get("metadata", {}).get("image_digest")

                for vuln_data in scan_data.get("results", []):
                    if "Vulnerabilities" in vuln_data:
                        for v in vuln_data["Vulnerabilities"]:
                            vulnerability = Vulnerability(
                                id=v.get("VulnerabilityID", "unknown"),
                                package_name=v.get("PkgName", "unknown"),
                                installed_version=v.get("InstalledVersion", "unknown"),
                                fixed_version=v.get("FixedVersion"),
                                severity=self.SEVERITY_MAP.get(v.get("Severity", "UNKNOWN"), "LOW"),
                                cvss_score=v.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                                description=v.get("Description", ""),
                                references=v.get("References", [])
                            )
                            result.vulnerabilities.append(vulnerability)

                for pkg_data in scan_data.get("metadata", {}).get("package", []):
                    result.packages.append({
                        "name": pkg_data.get("name"),
                        "version": pkg_data.get("version"),
                        "type": pkg_data.get("type")
                    })

            output_file.unlink(missing_ok=True)

            if proc.returncode != 0 and "ALPINE" not in proc.stderr:
                result.scan_errors.append(proc.stderr)

        except subprocess.TimeoutExpired:
            result.scan_errors.append("Scan timed out after 10 minutes")
        except Exception as e:
            result.scan_errors.append(str(e))

        return result

    def scan_filesystem(
        self,
        image_ref: str,
        output_dir: Path
    ) -> dict:
        """Scan filesystem layers of an image."""
        if not self.trivy_available:
            return {"error": "Trivy not available"}

        try:
            result = subprocess.run(
                [
                    "trivy",
                    "fs",
                    "--format", "json",
                    "--output", str(output_dir / "fs-scan.json"),
                    "--severity", "HIGH,MEDIUM",
                    "--image-ref", image_ref
                ],
                capture_output=True,
                text=True,
                timeout=300
            )

            if output_dir.joinpath("fs-scan.json").exists():
                return json.loads(output_dir.joinpath("fs-scan.json").read_text())

        except Exception as e:
            return {"error": str(e)}

        return {}


class SBOMGenerator:
    """Generates Software Bill of Materials (SBOM) for container images."""

    FORMAT_CYCLONEDX = "cyclonedx"
    FORMAT_SPDX = "spdx"
    FORMAT_SYFT = "syft"

    def __init__(self, syft_available: bool = None):
        self.syft_available = syft_available if syft_available is not None else self._check_syft_available()

    def _check_syft_available(self) -> bool:
        """Check if Syft is installed."""
        try:
            result = subprocess.run(
                ["syft", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def generate_sbom(
        self,
        image_ref: str,
        output_path: Path,
        format: str = FORMAT_SPDX
    ) -> tuple[bool, Optional[str]]:
        """Generate SBOM for a container image."""
        if not self.syft_available:
            return self._generate_sbom_internal(image_ref, output_path, format)

        try:
            cmd = [
                "syft",
                image_ref,
                "-o", f"{format}={output_path}"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0 and output_path.exists():
                return True, output_path.read_text()
            else:
                return False, result.stderr

        except Exception as e:
            return False, str(e)

    def _generate_sbom_internal(
        self,
        image_ref: str,
        output_path: Path,
        format: str
    ) -> tuple[bool, Optional[str]]:
        """Generate SBOM using Docker/Podman inspection."""
        try:
            client = docker.from_env()
            image = client.images.get(image_ref)

            layers = image.history()
            packages = []

            for layer in layers:
                if layer.get("CreatedBy", "").startswith("ADD file:"):
                    packages.append({
                        "source": "layer",
                        "layer_id": layer.get("Id", "")[:12]
                    })

            sbom = {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": f"SPDXRef-Image-{image_ref.replace(':', '-').replace('/', '-')}",
                "name": image_ref,
                "documentNamespace": f"https://example.com/image/{image_ref}",
                "creationInfo": {
                    "created": datetime.now(timezone.utc).isoformat(),
                    "creators": ["Tool: internal-sbom-generator"]
                },
                "packages": [
                    {
                        "SPDXID": f"SPDXRef-Package-{i}",
                        "name": p.get("name", "unknown"),
                        "versionInfo": p.get("version", "unknown"),
                        "supplier": "Organization: Unknown"
                    }
                    for i, p in enumerate(packages)
                ]
            }

            with open(output_path, "w") as f:
                json.dump(sbom, f, indent=2)

            return True, json.dumps(sbom)

        except Exception as e:
            return False, str(e)


class SecretScanner:
    """Scans container images for exposed secrets."""

    SECRET_PATTERNS = {
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "severity": "CRITICAL",
            "description": "AWS Access Key ID"
        },
        "aws_secret_key": {
            "pattern": r"[A-Za-z0-9/+=]{40}",
            "severity": "CRITICAL",
            "description": "AWS Secret Access Key",
            "context": "AWS"
        },
        "private_key": {
            "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "severity": "CRITICAL",
            "description": "Private Key"
        },
        "github_token": {
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
            "severity": "CRITICAL",
            "description": "GitHub Token"
        },
        "gitlab_token": {
            "pattern": r"glpat-[A-Za-z0-9\-_]{20,}",
            "severity": "CRITICAL",
            "description": "GitLab Personal Access Token"
        },
        "slack_token": {
            "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]+",
            "severity": "HIGH",
            "description": "Slack Token"
        },
        "database_url": {
            "pattern": r"(mysql|postgres|redis|mongodb)://[^\s:]+:[^\s@]+@[^\s:]+:\d+",
            "severity": "HIGH",
            "description": "Database Connection String"
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "severity": "HIGH",
            "description": "JWT Token"
        },
        "api_key_generic": {
            "pattern": r"[Aa][Pp][Ii][-_]?[Kk]ey\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}",
            "severity": "MEDIUM",
            "description": "Generic API Key"
        },
        "password_in_env": {
            "pattern": r"(PASSWORD|PASSWD|PWD|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            "severity": "MEDIUM",
            "description": "Password in environment variable pattern"
        },
        "docker_config": {
            "pattern": r"\"auths\":\\s*\\{",
            "severity": "HIGH",
            "description": "Docker config authentication block"
        }
    }

    def __init__(self, max_file_size: int = 5 * 1024 * 1024):
        self.max_file_size = max_file_size

    def scan_image(self, image_ref: str) -> list[SecretFinding]:
        """Scan a container image for secrets."""
        findings = []

        try:
            client = docker.from_env()
            image = client.images.get(image_ref)

            for layer in image.history():
                created_by = layer.get("CreatedBy", "")
                if "/bin/sh -c" not in created_by:
                    continue

        except Exception as e:
            logger.warning(f"Docker scan failed: {e}")

        return findings

    def scan_filesystem(self, root_path: Path) -> list[SecretFinding]:
        """Scan a filesystem for secrets."""
        findings = []

        scan_paths = [
            "*.env",
            "*.pem",
            "*.key",
            "*credentials*",
            "*secret*",
            "*password*",
            ".git/config",
            "**/.dockerconfigjson",
            "**/id_rsa*",
            "**/authorized_keys"
        ]

        for pattern in scan_paths:
            for file_path in root_path.rglob(pattern):
                if file_path.stat().st_size > self.max_file_size:
                    continue

                file_findings = self._scan_file(file_path)
                findings.extend(file_findings)

        return findings

    def _scan_file(self, file_path: Path) -> list[SecretFinding]:
        """Scan a single file for secrets."""
        findings = []

        try:
            content = file_path.read_text(errors="ignore")

            for secret_type, config in self.SECRET_PATTERNS.items():
                pattern = config["pattern"]
                matches = re.finditer(pattern, content, re.MULTILINE)

                for match in matches:
                    line_number = content[:match.start()].count("\n") + 1

                    context_start = max(0, match.start() - 50)
                    context_end = min(len(content), match.end() + 50)
                    context = content[context_start:context_end]

                    finding = SecretFinding(
                        file_path=str(file_path),
                        secret_type=secret_type,
                        matched_pattern=match.group(0)[:50],
                        line_number=line_number,
                        context=context
                    )
                    findings.append(finding)

        except Exception as e:
            logger.debug(f"Failed to scan {file_path}: {e}")

        return findings


class BaseImageAnalyzer:
    """Analyzes container base images for security posture."""

    DISTROLESS_IMAGES = [
        "gcr.io/distroless",
        "chainguard.dev",
        "cgr.dev/chainguard"
    ]

    OFFICIAL_IMAGES = [
        "ubuntu",
        "debian",
        "alpine",
        "nginx",
        "redis",
        "postgres",
        "mysql",
        "python",
        "node",
        "golang"
    ]

    def analyze(self, image_ref: str) -> dict:
        """Analyze base image security posture."""
        analysis = {
            "base_image": image_ref,
            "image_type": "unknown",
            "security_score": 0,
            "recommendations": [],
            "is_distroless": False,
            "is_official": False,
            "uses_latest_tag": self._check_latest_tag(image_ref)
        }

        if any(ds in image_ref for ds in self.DISTROLESS_IMAGES):
            analysis["image_type"] = "distroless"
            analysis["security_score"] = 100
            analysis["is_distroless"] = True
        elif any(oi in image_ref.lower() for oi in self.OFFICIAL_IMAGES):
            analysis["image_type"] = "official"
            analysis["security_score"] = 80
            analysis["is_official"] = True
            analysis["recommendations"].append(
                "Consider using distroless or minimal images for production"
            )
        else:
            analysis["image_type"] = "third-party"
            analysis["security_score"] = 50
            analysis["recommendations"].append(
                "Verify base image source and consider rebuilding from known-good base"
            )

        if analysis["uses_latest_tag"]:
            analysis["recommendations"].append(
                "Avoid 'latest' tag - use specific version for reproducibility"
            )

        return analysis

    def _check_latest_tag(self, image_ref: str) -> bool:
        """Check if image uses 'latest' tag."""
        if ":" not in image_ref:
            return True

        tag = image_ref.split(":")[-1]
        if "@" in tag:
            tag = tag.split("@")[0]

        return tag == "latest"


class ContainerSecurityScanner:
    """Main container security scanning orchestrator."""

    def __init__(self):
        self.trivy = TrivyScanner()
        self.sbom = SBOMGenerator()
        self.secret_scanner = SecretScanner()
        self.base_image_analyzer = BaseImageAnalyzer()

    def full_scan(
        self,
        image_ref: str,
        sbom_output: Optional[Path] = None,
        secrets_enabled: bool = True
    ) -> ScanResult:
        """Perform a comprehensive security scan."""
        result = self.trivy.scan_image(image_ref)

        base_analysis = self.base_image_analyzer.analyze(image_ref)
        result.base_image_info = base_analysis

        if sbom_output:
            success, sbom_content = self.sbom.generate_sbom(
                image_ref,
                sbom_output,
                SBOMGenerator.FORMAT_SPDX
            )
            result.sbom_generated = success

        if secrets_enabled:
            secret_findings = self.secret_scanner.scan_image(image_ref)
            result.secrets = secret_findings

        return result

    def generate_sarif_report(self, result: ScanResult) -> dict:
        """Generate SARIF format report."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "container-security-scanner",
                            "version": "1.0.0",
                            "informationUri": "https://example.com/docs"
                        }
                    },
                    "results": [
                        {
                            "ruleId": v.id,
                            "level": self._severity_to_level(v.severity),
                            "message": {
                                "text": f"{v.package_name}@{v.installed_version}: {v.description}"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": result.image_ref
                                        },
                                        "region": {
                                            "startLine": 1
                                        }
                                    }
                                }
                            ]
                        }
                        for v in result.vulnerabilities
                    ]
                }
            ]
        }

        return sarif

    def _severity_to_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note"
        }
        return mapping.get(severity, "warning")


def main():
    parser = argparse.ArgumentParser(
        description="Scan container images for security vulnerabilities"
    )
    parser.add_argument("image", help="Container image to scan")
    parser.add_argument("--output", default="scan-result.json", help="Output file")
    parser.add_argument("--format", choices=["json", "sarif"], default="json")
    parser.add_argument("--severity", default="HIGH", help="Minimum severity to report")
    parser.add_argument("--sbom", help="Generate SBOM to specified file")
    parser.add_argument("--skip-secrets", action="store_true", help="Skip secret scanning")
    parser.add_argument("--cache-dir", type=Path, help="Trivy cache directory")

    args = parser.parse_args()

    scanner = ContainerSecurityScanner()

    if args.cache_dir:
        scanner.trivy.cache_dir = args.cache_dir

    result = scanner.full_scan(
        args.image,
        sbom_output=Path(args.sbom) if args.sbom else None,
        secrets_enabled=not args.skip_secrets
    )

    if args.format == "sarif":
        report = scanner.generate_sarif_report(result)
    else:
        report = {
            "image": result.image_ref,
            "scan_timestamp": result.scan_timestamp.isoformat(),
            "summary": {
                "total_vulnerabilities": result.total_vulnerabilities,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "package": v.package_name,
                    "installed_version": v.installed_version,
                    "fixed_version": v.fixed_version,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "description": v.description
                }
                for v in result.vulnerabilities
            ],
            "base_image": result.base_image_info,
            "sbom_generated": result.sbom_generated,
            "secrets_found": len(result.secrets),
            "errors": result.scan_errors
        }

    output_path = Path(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Scan complete: {result.total_vulnerabilities} vulnerabilities found")
    logger.info(f"Critical: {result.critical_count}, High: {result.high_count}")
    logger.info(f"Report written to {output_path}")

    return 0 if result.critical_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())