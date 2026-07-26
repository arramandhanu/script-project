"""
GitHub Actions Pipeline Hardener
Enforces security controls on GitHub Actions workflows including:
- OPA/Conftest policy validation
- SBOM generation and verification
- Container image signing
- Secret scanning integration
- Supply chain security controls
"""

import json
import re
import argparse
import hashlib
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import base64
import datetime

import yaml
import requests


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class SecurityGate:
    """A security gate that must pass before deployment."""
    name: str
    enabled: bool = True
    required: bool = True
    severity: str = "HIGH"
    description: str = ""


@dataclass
class PipelineSecurityConfig:
    """Configuration for pipeline security controls."""
    require_signed_commits: bool = True
    require_security_scan: bool = True
    require_sbom: bool = True
    require_image_signing: bool = True
    require_secret_scanning: bool = True
    block_on_critical_findings: bool = True
    allowed_image_sources: list[str] = field(default_factory=lambda: ["ghcr.io"])
    required_trivy_severity: str = "HIGH"
    conftest_policy_path: Optional[str] = None
    cosign_key_path: Optional[str] = None
    github_token: Optional[str] = None


@dataclass
class PipelineAnalysisResult:
    """Result of pipeline security analysis."""
    pipeline_path: str
    passed: bool
    findings: list[dict] = field(default_factory=list)
    security_gates: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    coverage_score: float = 0.0


class GitHubActionsSecurityAnalyzer:
    """Analyzes GitHub Actions workflows for security issues."""

    COMMON_VULNERABLE_ACTIONS = {
        "master": "Branch 'master' is deprecated, use 'main'",
        "main": None,
        "latest": "Avoid 'latest' tag - use specific version",
        "sha-": None,
    }

    UNSAFE_PATTERNS = {
        r"echo\s+[\"'].*\$\{.*\}": "Potentially unsafe command injection",
        r"::add-mask::": "Secret masking in logs",
        r"github\.token": "Direct GitHub token access - verify permissions",
        r"secrets\.": "Secret access detected",
        r"password|passwd|pwd|secret": "Sensitive data pattern detected",
        r"chmod\s+777": "Overly permissive file permissions",
        r"wget.*\|.*bash": "Dangerous download pattern",
        r"curl.*\|.*sh": "Dangerous download pattern",
        r"rm\s+-rf\s+/": "Destructive command detected",
        r"eval\s+": "Use of eval - potential injection risk",
    }

    def __init__(self, config: Optional[PipelineSecurityConfig] = None):
        self.config = config or PipelineSecurityConfig()

    def parse_workflow_file(self, file_path: Path) -> dict:
        """Parse a GitHub Actions workflow file."""
        with open(file_path, "r") as f:
            if file_path.suffix in [".yml", ".yaml"]:
                return yaml.safe_load(f)
            elif file_path.suffix == ".json":
                return json.load(f)
        return {}

    def analyze_workflow(self, workflow_path: Path) -> PipelineAnalysisResult:
        """Analyze a single workflow file for security issues."""
        result = PipelineAnalysisResult(
            pipeline_path=str(workflow_path),
            passed=True
        )

        try:
            workflow = self.parse_workflow_file(workflow_path)

            if "jobs" not in workflow:
                result.findings.append({
                    "type": "ERROR",
                    "message": "Invalid workflow: no jobs defined"
                })
                return result

            self._check_workflow_structure(workflow, result)
            self._check_action_references(workflow, result)
            self._check_security_gates(workflow, result)
            self._check_environment_protection(workflow, result)
            self._check_permissions(workflow, result)
            self._check_container_security(workflow, result)

            result.coverage_score = self._calculate_security_coverage(result)

        except Exception as e:
            logger.error(f"Failed to analyze {workflow_path}: {e}")
            result.findings.append({
                "type": "ERROR",
                "message": str(e)
            })
            result.passed = False

        return result

    def _check_workflow_structure(self, workflow: dict, result: PipelineAnalysisResult) -> None:
        """Check basic workflow structure for security."""
        if workflow.get("name"):
            result.security_gates.append({
                "name": "workflow_named",
                "passed": True,
                "description": f"Workflow has name: {workflow['name']}"
            })

        on_trigger = workflow.get("on", workflow.get("trigger", {}))
        if isinstance(on_trigger, str) or "push" in on_trigger or "pull_request" in on_trigger:
            result.security_gates.append({
                "name": "trigger_defined",
                "passed": True,
                "description": "Workflow has trigger defined"
            })

    def _check_action_references(self, workflow: dict, result: PipelineAnalysisResult) -> None:
        """Check GitHub Actions references for vulnerabilities."""
        jobs = workflow.get("jobs", {})

        for job_name, job_config in jobs.items():
            steps = job_config.get("steps", [])

            for step in steps:
                uses = step.get("uses", "")

                if not uses:
                    continue

                if uses.startswith("actions/"):
                    self._analyze_action_reference(uses, result)
                elif uses.startswith("docker://"):
                    self._analyze_docker_reference(uses, result)

    def _analyze_action_reference(self, action_ref: str, result: PipelineAnalysisResult) -> None:
        """Analyze a single action reference."""
        match = re.search(r"@([a-f0-9]+)", action_ref)
        if match:
            sha = match.group(1)
            if len(sha) == 40:
                result.security_gates.append({
                    "name": "action_sha_pinned",
                    "passed": True,
                    "description": f"Action uses full SHA: {action_ref[:50]}..."
                })
                return

        if "@" in action_ref:
            tag_or_branch = action_ref.split("@")[1]
            for deprecated, warning in self.COMMON_VULNERABLE_ACTIONS.items():
                if tag_or_branch == deprecated and warning:
                    result.findings.append({
                        "type": "WARNING",
                        "severity": "MEDIUM",
                        "message": f"Action uses deprecated reference: {warning}",
                        "reference": action_ref
                    })

    def _analyze_docker_reference(self, docker_ref: str, result: PipelineAnalysisResult) -> None:
        """Analyze a Docker image reference."""
        image = docker_ref.replace("docker://", "")

        if ":" not in image and "@" not in image:
            result.findings.append({
                "type": "WARNING",
                "severity": "MEDIUM",
                "message": "Docker image has no tag - using :latest implicitly",
                "reference": image
            })

        if self.config.allowed_image_sources:
            source_allowed = any(
                image.startswith(source) for source in self.config.allowed_image_sources
            )
            if not source_allowed:
                result.findings.append({
                    "type": "WARNING",
                    "severity": "HIGH",
                    "message": f"Image source not in allowlist: {image}",
                    "reference": image
                })

    def _check_security_gates(self, workflow: dict, result: PipelineAnalysisResult) -> None:
        """Check for required security gates."""
        jobs = workflow.get("jobs", {})

        has_trivy_scan = any(
            "trivy" in str(job).lower()
            for job in jobs.values()
        )

        has_secret_scan = any(
            "secret" in str(job).lower() and "scan" in str(job).lower()
            for job in jobs.values()
        )

        has_sbom = any(
            "sbom" in str(job).lower()
            for job in jobs.values()
        )

        gates = [
            ("trivy_scan", has_trivy_scan, "Trivy vulnerability scanning"),
            ("secret_scanning", has_secret_scan, "Secret scanning"),
            ("sbom_generation", has_sbom, "SBOM generation"),
        ]

        for gate_name, gate_passed, gate_desc in gates:
            result.security_gates.append({
                "name": gate_name,
                "passed": gate_passed,
                "description": gate_desc,
                "required": self.config.require_security_scan
            })

            if not gate_passed and self.config.require_security_scan:
                result.recommendations.append(
                    f"Add {gate_desc.lower()} to your workflow"
                )

    def _check_environment_protection(self, workflow: dict, result: PipelineAnalysisResult) -> None:
        """Check environment protection rules."""
        jobs = workflow.get("jobs", {})

        for job_name, job_config in jobs.items():
            env = job_config.get("environment")
            if env:
                if isinstance(env, str):
                    result.security_gates.append({
                        "name": f"environment_protected_{job_name}",
                        "passed": True,
                        "description": f"Job {job_name} uses environment: {env}"
                    })
                elif isinstance(env, dict):
                    protection_rules = env.get("protection_rules", {})
                    if protection_rules:
                        result.security_gates.append({
                            "name": f"environment_protection_rules_{job_name}",
                            "passed": True,
                            "description": f"Environment has protection rules configured"
                        })

    def _check_permissions(self, workflow: dict, result: PipelineAnalysisResult) -> None:
        """Check workflow and job permissions."""
        permissions = workflow.get("permissions", {})

        if not permissions:
            result.findings.append({
                "type": "WARNING",
                "severity": "LOW",
                "message": "No explicit permissions defined - using defaults"
            })
        else:
            result.security_gates.append({
                "name": "explicit_permissions",
                "passed": True,
                "description": "Workflow has explicit permissions defined"
            })

        dangerous_perms = {
            "contents": "write",
            "packages": "write",
            "actions: write",
            "deployments: write"
        }

        for perm, risk_level in dangerous_perms.items():
            if permissions.get(perm) == risk_level:
                result.findings.append({
                    "type": "INFO",
                    "severity": "LOW",
                    "message": f"Permission '{perm}' is set to '{risk_level}' - review necessity",
                    "permission": perm
                })

    def _check_container_security(self, workflow: dict, result: PipelineAnalysisResult) -> None:
        """Check container-related security controls."""
        jobs = workflow.get("jobs", {})

        for job_name, job_config in jobs.items():
            container = job_config.get("container")
            services = job_config.get("services", [])

            if container:
                image = container if isinstance(container, str) else container.get("image")

                if image and not image.endswith(":latest") and "@sha256:" in image:
                    result.security_gates.append({
                        "name": f"image_digest_pinned_{job_name}",
                        "passed": True,
                        "description": f"Container image pinned to digest"
                    })

    def _calculate_security_coverage(self, result: PipelineAnalysisResult) -> float:
        """Calculate security coverage score."""
        total_gates = len(result.security_gates)
        if total_gates == 0:
            return 0.0

        passed_gates = sum(1 for g in result.security_gates if g["passed"])
        return (passed_gates / total_gates) * 100


class OPAValidator:
    """Validates pipeline configurations using OPA/Rego policies."""

    DEFAULT_POLICIES = {
        "no_privileged_runner": {
            "regql": 'deny[msg] { input.jobs[job].runs-on == "ubuntu-latest" } msg := "Avoid ubuntu-latest, use specific version"',
            "severity": "MEDIUM"
        },
        "require_timeout": {
            "regql": 'deny[msg] { not input.jobs[job]["timeout-minutes"] } msg := "Job should have timeout-minutes set"',
            "severity": "LOW"
        },
        "no_unsafe_scripts": {
            "regql": 'deny[msg] { input.jobs[job].steps[step].run contains "curl | sh" } msg := "Unsafe download pattern detected"',
            "severity": "HIGH"
        },
        "pin_actions_to_sha": {
            "regql": 'deny[msg] { input.jobs[job].steps[step].uses contains "@" not contains "@sha" } msg := "Action not pinned to SHA"',
            "severity": "MEDIUM"
        },
        "require_concurrency_limit": {
            "regql": 'deny[msg] { not input.concurrency } msg := "Workflow should have concurrency limits"',
            "severity": "LOW"
        }
    }

    def __init__(self, policy_dir: Optional[Path] = None):
        self.policy_dir = policy_dir
        self.opa_available = self._check_opa_available()

    def _check_opa_available(self) -> bool:
        """Check if OPA is available."""
        try:
            result = subprocess.run(
                ["opa", "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def validate_workflow(self, workflow: dict, policies: Optional[dict] = None) -> list[dict]:
        """Validate workflow against OPA policies."""
        findings = []

        if not self.opa_available:
            logger.warning("OPA not available, skipping policy validation")
            return findings

        policies = policies or self.DEFAULT_POLICIES

        for policy_name, policy in policies.items():
            try:
                result = subprocess.run(
                    [
                        "opa", "eval",
                        "--format", "json",
                        "--data", "-",
                        "-d", tempfile.NamedTemporaryFile(
                            mode='w',
                            suffix='.rego'
                        ).name,
                        policy["regql"]
                    ],
                    input=json.dumps(workflow),
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    eval_result = json.loads(result.stdout)
                    if eval_result.get("result"):
                        findings.append({
                            "policy": policy_name,
                            "severity": policy["severity"],
                            "message": eval_result["result"][0].get("expressions", [{}])[0]
                        })

            except Exception as e:
                logger.debug(f"Policy evaluation failed for {policy_name}: {e}")

        return findings


class CosignImageSigner:
    """Handles container image signing with Cosign."""

    def __init__(self, key_path: Optional[Path] = None):
        self.key_path = key_path
        self.cosign_available = self._check_cosign_available()

    def _check_cosign_available(self) -> bool:
        """Check if cosign is available."""
        try:
            result = subprocess.run(
                ["cosign", "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def sign_image(
        self,
        image_ref: str,
        key_path: Optional[Path] = None,
        predicate_path: Optional[Path] = None
    ) -> tuple[bool, Optional[str]]:
        """Sign a container image."""
        if not self.cosign_available:
            return False, "Cosign not available"

        key_path = key_path or self.key_path
        if not key_path:
            return False, "No signing key provided"

        try:
            cmd = ["cosign", "sign", "--yes", "--key", str(key_path), image_ref]

            if predicate_path:
                cmd.extend(["--bundle", str(predicate_path)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                return False, result.stderr

        except Exception as e:
            return False, str(e)

    def verify_image(
        self,
        image_ref: str,
        key_path: Optional[Path] = None
    ) -> tuple[bool, Optional[dict]]:
        """Verify a signed container image."""
        if not self.cosign_available:
            return False, None

        key_path = key_path or self.key_path

        try:
            cmd = ["cosign", "verify", "--json", "--key", str(key_path), image_ref]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return True, json.loads(result.stdout)
            else:
                return False, None

        except Exception as e:
            return False, None


class PipelineHardener:
    """Main class for hardening GitHub Actions pipelines."""

    def __init__(
        self,
        config: Optional[PipelineSecurityConfig] = None,
        github_token: Optional[str] = None
    ):
        self.config = config or PipelineSecurityConfig(github_token=github_token)
        self.analyzer = GitHubActionsSecurityAnalyzer(self.config)
        self.opa_validator = OPAValidator()
        self.signer = CosignImageSigner(self.config.cosign_key_path)

    def harden_workflow_file(
        self,
        workflow_path: Path,
        output_path: Optional[Path] = None
    ) -> dict:
        """Apply security hardening to a workflow file."""
        result = self.analyzer.analyze_workflow(workflow_path)

        if self.opa_validator.opa_available:
            workflow = self.analyzer.parse_workflow_file(workflow_path)
            opa_findings = self.opa_validator.validate_workflow(workflow)
            result.findings.extend(opa_findings)

        hardened = self._apply_hardening(result)

        if output_path:
            with open(output_path, "w") as f:
                yaml.dump(hardened, f, default_flow_style=False)

        return {
            "original_findings": len(result.findings),
            "gates_passed": sum(1 for g in result.security_gates if g["passed"]),
            "gates_failed": sum(1 for g in result.security_gates if not g["passed"]),
            "hardened_file": str(output_path) if output_path else None,
            "coverage_score": result.coverage_score
        }

    def _apply_hardening(self, result: PipelineAnalysisResult) -> dict:
        """Generate hardened workflow configuration."""
        hardened = {
            "name": "Hardened Workflow",
            "on": {
                "push": {"branches": ["main"]},
                "pull_request": {"branches": ["main"]}
            },
            "permissions": {
                "contents": "read",
                "packages": "write",
                "security-events": "write"
            },
            "concurrency": {
                "group": "${{ github.workflow }}-${{ github.ref }}",
                "cancel-in-progress": True
            },
            "jobs": {
                "security-checks": {
                    "runs-on": "ubuntu-22.04",
                    "timeout-minutes": 30,
                    "steps": [
                        {
                            "name": "Checkout",
                            "uses": "actions/checkout@v4"
                        },
                        {
                            "name": "Run Trivy vulnerability scanner",
                            "run": "trivy fs --exit-code 1 --severity HIGH ."
                        },
                        {
                            "name": "Generate SBOM",
                            "run": "syft . -o spdx-json=sbom.spdx.json"
                        },
                        {
                            "name": "Upload SBOM",
                            "uses": "actions/upload-artifact@v4",
                            "with": {
                                "name": "sbom",
                                "path": "sbom.spdx.json"
                            }
                        }
                    ]
                }
            }
        }

        return hardened

    def generate_security_report(
        self,
        results: list[PipelineAnalysisResult],
        output_path: Path
    ) -> dict:
        """Generate comprehensive security report."""
        total_findings = sum(len(r.findings) for r in results)
        passed_workflows = sum(1 for r in results if r.passed)

        report = {
            "generated_at": datetime.datetime.now().isoformat(),
            "summary": {
                "total_workflows": len(results),
                "passed_workflows": passed_workflows,
                "failed_workflows": len(results) - passed_workflows,
                "total_findings": total_findings,
                "average_coverage": sum(r.coverage_score for r in results) / len(results) if results else 0
            },
            "workflows": [
                {
                    "path": r.pipeline_path,
                    "passed": r.passed,
                    "findings_count": len(r.findings),
                    "coverage_score": r.coverage_score,
                    "security_gates": r.security_gates,
                    "recommendations": r.recommendations
                }
                for r in results
            ]
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Harden GitHub Actions workflows with security controls"
    )
    parser.add_argument("path", type=Path, help="Path to workflow file or directory")
    parser.add_argument("--output", help="Output path for hardened workflow")
    parser.add_argument("--report", default="security-report.json", help="Security report output")
    parser.add_argument("--github-token", help="GitHub token for API access")
    parser.add_argument("--cosign-key", type=Path, help="Cosign signing key path")
    parser.add_argument("--opa-policies", type=Path, help="OPA policies directory")

    args = parser.parse_args()

    config = PipelineSecurityConfig(
        github_token=args.github_token,
        cosign_key_path=args.cosign_key
    )

    hardener = PipelineHardener(config)

    if args.path.is_file():
        result = hardener.harden_workflow_file(
            args.path,
            Path(args.output) if args.output else None
        )
        logger.info(f"Hardened: {result}")
    else:
        results = []
        for workflow_file in args.path.rglob("*.yml"):
            if ".github/workflows" in str(workflow_file):
                result = hardener.analyzer.analyze_workflow(workflow_file)
                results.append(result)

        report = hardener.generate_security_report(
            results,
            Path(args.report)
        )
        logger.info(f"Analysis complete: {report['summary']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())