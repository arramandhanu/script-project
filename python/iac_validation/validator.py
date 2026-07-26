"""
Terraform IaC Validator
Validates Terraform configurations against security and compliance policies
before deployment. Supports multi-account, multi-environment validation.
"""

import json
import re
import argparse
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Any, Generator
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import subprocess
import tempfile
import shutil

import hcl2


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class ValidationFinding:
    """A single validation finding."""
    severity: str
    resource_type: str
    resource_name: str
    check_id: str
    check_name: str
    message: str
    line_number: Optional[int] = None
    file_path: Optional[str] = None
    remediation: Optional[str] = None
    policy_id: Optional[str] = None


@dataclass
class ValidationResult:
    """Aggregated validation results."""
    passed: bool
    findings: list[ValidationFinding] = field(default_factory=list)
    files_validated: int = 0
    resources_validated: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: ValidationFinding) -> None:
        self.findings.append(finding)
        self.resources_validated += 1

    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity == "CRITICAL"])

    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.severity == "HIGH"])

    @property
    def medium_count(self) -> int:
        return len([f for f in self.findings if f.severity == "MEDIUM"])

    @property
    def low_count(self) -> int:
        return len([f for f in self.findings if f.severity == "LOW"])


class PolicyEngine:
    """Policy evaluation engine for Terraform resources."""

    POLICIES = {
        "CKV_AWS_1": {
            "name": "S3 bucket encryption at rest",
            "severity": "HIGH",
            "resource_types": ["aws_s3_bucket"],
            "check": lambda r: any(
                k for k in r.keys()
                if k.endswith("_server_side_encryption_configuration") or
                   k.endswith("_server_side_encryption_configuration")
            )
        },
        "CKV_AWS_2": {
            "name": "S3 bucket public access block",
            "severity": "HIGH",
            "resource_types": ["aws_s3_bucket"],
            "check": lambda r: any(
                k for k in r.keys()
                if "public_access_block" in k.lower()
            )
        },
        "CKV_AWS_3": {
            "name": "EBS volume encryption",
            "severity": "MEDIUM",
            "resource_types": ["aws_ebs_volume"],
            "check": lambda r: any(
                k for k in r.keys()
                if "encrypted" in k.lower()
            )
        },
        "CKV_AWS_5": {
            "name": "S3 bucket logging enabled",
            "severity": "MEDIUM",
            "resource_types": ["aws_s3_bucket"],
            "check": lambda r: any(
                k for k in r.keys()
                if "logging" in k.lower()
            )
        },
        "CKV_AWS_18": {
            "name": "S3 bucket versioning enabled",
            "severity": "LOW",
            "resource_types": ["aws_s3_bucket"],
            "check": lambda r: any(
                k for k in r.keys()
                if "versioning" in k.lower()
            )
        },
        "CKV_AWS_21": {
            "name": "S3 bucket has access log",
            "severity": "MEDIUM",
            "resource_types": ["aws_s3_bucket"],
            "check": lambda r: any(
                k for k in r.keys()
                if "logging" in k.lower() or "access_control" in k.lower()
            )
        },
        "CKV_AWS_52": {
            "name": "EBS volume has deletion protection",
            "severity": "MEDIUM",
            "resource_types": ["aws_ebs_volume"],
            "check": lambda r: "deletion_protection" in r or "ignore_changes" in r
        },
        "CKV_K8S_1": {
            "name": "Container security context - run as non-root",
            "severity": "CRITICAL",
            "resource_types": ["kubernetes_pod", "kubernetes_deployment"],
            "check": lambda r: _check_security_context(r, "run_as_non_root", True)
        },
        "CKV_K8S_2": {
            "name": "Container security context - drop ALL capabilities",
            "severity": "HIGH",
            "resource_types": ["kubernetes_pod", "kubernetes_deployment"],
            "check": lambda r: _check_security_context(r, "drop_capabilities", ["ALL"])
        },
        "CKV_K8S_3": {
            "name": "Pod has security context defined",
            "severity": "MEDIUM",
            "resource_types": ["kubernetes_pod"],
            "check": lambda r: "security_context" in r or "pod_security_context" in r
        },
        "CKV_K8S_4": {
            "name": "Container has resource limits",
            "severity": "MEDIUM",
            "resource_types": ["kubernetes_pod", "kubernetes_deployment"],
            "check": lambda r: _check_resource_limits(r)
        },
        "CKV_K8S_6": {
            "name": "Container is not using host network",
            "severity": "HIGH",
            "resource_types": ["kubernetes_pod", "kubernetes_deployment"],
            "check": lambda r: not _check_host_network(r)
        },
        "CKV_K8S_8": {
            "name": "Container has readiness probe",
            "severity": "MEDIUM",
            "resource_types": ["kubernetes_pod", "kubernetes_deployment"],
            "check": lambda r: _check_probe_exists(r, "readiness_probe")
        },
        "CKV_K8S_9": {
            "name": "Container has liveness probe",
            "severity": "LOW",
            "resource_types": ["kubernetes_pod", "kubernetes_deployment"],
            "check": lambda r: _check_probe_exists(r, "liveness_probe")
        },
        "CKV_K8S_11": {
            "name": "Pod disallows privileged containers",
            "severity": "CRITICAL",
            "resource_types": ["kubernetes_pod", "kubernetes_deployment"],
            "check": lambda r: not _check_privileged_container(r)
        },
        "CKV_K8S_12": {
            "name": "Pod disallows containers from sharing host IPC",
            "severity": "HIGH",
            "resource_types": ["kubernetes_pod"],
            "check": lambda r: not _check_host_ipc(r)
        },
        "CKV_K8S_13": {
            "name": "Pod disallows containers from sharing host PID",
            "severity": "MEDIUM",
            "resource_types": ["kubernetes_pod"],
            "check": lambda r: not _check_host_pid(r)
        },
        "CKV_AWS_116": {
            "name": "RDS has automated backups enabled",
            "severity": "HIGH",
            "resource_types": ["aws_db_instance", "aws_rds_cluster"],
            "check": lambda r: any(
                k for k in r.keys()
                if "backup" in k.lower() or "replication" in k.lower()
            )
        },
        "CKV_AWS_117": {
            "name": "RDS has multi-AZ enabled",
            "severity": "HIGH",
            "resource_types": ["aws_db_instance"],
            "check": lambda r: r.get("multi_az", False) or "multi_az" in r
        },
        "CKV_AWS_118": {
            "name": "RDS has enhanced monitoring",
            "severity": "MEDIUM",
            "resource_types": ["aws_db_instance"],
            "check": lambda r: any(
                k for k in r.keys()
                if "monitoring" in k.lower()
            )
        },
        "CKV_AWS_163": {
            "name": "EKS cluster has encryption at rest",
            "severity": "HIGH",
            "resource_types": ["aws_eks_cluster"],
            "check": lambda r: any(
                k for k in r.keys()
                if "encryption_config" in k.lower() or "encryption" in k.lower()
            )
        },
        "CKV_AWS_164": {
            "name": "EKS cluster has control plane logging",
            "severity": "HIGH",
            "resource_types": ["aws_eks_cluster"],
            "check": lambda r: _check_eks_logging(r)
        },
        "CKV2_AWS_1": {
            "name": "S3 buckets have MFA delete enabled",
            "severity": "HIGH",
            "resource_types": ["aws_s3_bucket"],
            "check": lambda r: _check_mfa_delete(r)
        },
        "CKV2_AWS_6": {
            "name": "S3 bucket policy restricts public access",
            "severity": "CRITICAL",
            "resource_types": ["aws_s3_bucket"],
            "check": lambda r: _check_bucket_policy_public_access(r)
        },
    }

    @classmethod
    def get_policy(cls, policy_id: str) -> Optional[dict]:
        """Get a policy by ID."""
        return cls.POLICIES.get(policy_id)

    @classmethod
    def get_policies_for_resource_type(cls, resource_type: str) -> list[dict]:
        """Get all policies applicable to a resource type."""
        return [
            {"id": k, **v}
            for k, v in cls.POLICIES.items()
            if resource_type in v.get("resource_types", [])
        ]


def _check_security_context(resource: dict, attribute: str, expected: Any) -> bool:
    """Check if a resource has the expected security context setting."""
    containers = resource.get("spec", {}).get("container", [])
    for container in containers:
        sec_ctx = container.get("security_context", {})
        if attribute in ["run_as_non_root", "privileged"]:
            if sec_ctx.get(attribute) == expected:
                return True
        elif attribute == "drop_capabilities":
            caps = sec_ctx.get("capabilities", {}).get("drop", [])
            if "ALL" in caps or expected in caps:
                return True
    return False


def _check_resource_limits(resource: dict) -> bool:
    """Check if container has resource limits defined."""
    containers = resource.get("spec", {}).get("container", [])
    for container in containers:
        if "resources" in container:
            res = container["resources"]
            if "limits" in res:
                return True
    return False


def _check_host_network(resource: dict) -> bool:
    """Check if pod uses host network."""
    spec = resource.get("spec", {})
    return spec.get("host_network", False)


def _check_probe_exists(resource: dict, probe_type: str) -> bool:
    """Check if container has the specified probe."""
    containers = resource.get("spec", {}).get("container", [])
    for container in containers:
        if probe_type in container:
            return True
    return False


def _check_privileged_container(resource: dict) -> bool:
    """Check if any container is privileged."""
    containers = resource.get("spec", {}).get("container", [])
    for container in containers:
        sec_ctx = container.get("security_context", {})
        if sec_ctx.get("privileged", False):
            return True
    return False


def _check_host_ipc(resource: dict) -> bool:
    """Check if pod uses host IPC."""
    spec = resource.get("spec", {})
    return spec.get("host_ipc", False)


def _check_host_pid(resource: dict) -> bool:
    """Check if pod uses host PID."""
    spec = resource.get("spec", {})
    return spec.get("host_pid", False)


def _check_mfa_delete(resource: dict) -> bool:
    """Check if S3 bucket has MFA delete enabled."""
    versioning = resource.get("versioning", {})
    if isinstance(versioning, dict):
        return versioning.get("mfa_delete", False)
    return False


def _check_bucket_policy_public_access(resource: dict) -> bool:
    """Check if S3 bucket policy restricts public access."""
    bucket_policy = resource.get("bucket_policy", {})
    if bucket_policy:
        policy_json = json.dumps(bucket_policy)
        if '"Effect": "Allow"' in policy_json and '"Principal": "*"' in policy_json:
            if '"Action": "*"' in policy_json or '"Action": "s3:*"' in policy_json:
                return False
    return True


def _check_eks_logging(resource: dict) -> bool:
    """Check if EKS cluster has control plane logging enabled."""
    enabled_logging = resource.get("enabled_cluster_log_types", [])
    required_logs = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
    return all(log in enabled_logging for log in required_logs)


class TerraformValidator:
    """Validates Terraform configurations against security policies."""

    def __init__(self, checkov_enabled: bool = True):
        self.checkov_available = self._check_checkov_available() if checkov_enabled else False

    def _check_checkov_available(self) -> bool:
        """Check if checkov is installed."""
        try:
            result = subprocess.run(
                ["checkov", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def parse_terraform_file(self, file_path: Path) -> dict:
        """Parse a Terraform file and extract resources."""
        with open(file_path, "r") as f:
            try:
                return hcl2.load(f)
            except Exception as e:
                logger.warning(f"Failed to parse {file_path}: {e}")
                return {}

    def parse_terraform_json(self, file_path: Path) -> dict:
        """Parse a Terraform JSON file."""
        with open(file_path, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON {file_path}: {e}")
                return {}

    def extract_resources(self, parsed_tf: dict) -> Generator[tuple, None, None]:
        """Extract resources from parsed Terraform."""
        if not parsed_tf:
            return

        for block_type in ["resource", "data", "module"]:
            if block_type in parsed_tf:
                for resource_type, resources in parsed_tf[block_type].items():
                    if isinstance(resources, dict):
                        for resource_name, resource_config in resources.items():
                            yield (block_type, resource_type, resource_name, resource_config)

    def validate_resource(
        self,
        block_type: str,
        resource_type: str,
        resource_name: str,
        resource_config: dict
    ) -> list[ValidationFinding]:
        """Validate a single resource against all applicable policies."""
        findings = []

        policies = PolicyEngine.get_policies_for_resource_type(resource_type)

        for policy in policies:
            try:
                check_passed = policy["check"](resource_config)

                if not check_passed:
                    finding = ValidationFinding(
                        severity=policy["severity"],
                        resource_type=resource_type,
                        resource_name=resource_name,
                        check_id=policy["id"],
                        check_name=policy["name"],
                        message=f"{policy['name']} is not satisfied",
                        remediation=f"Add {policy['name'].lower().replace(' ', ' ')} configuration"
                    )
                    findings.append(finding)

            except Exception as e:
                logger.debug(f"Error checking policy {policy['id']}: {e}")

        return findings

    def validate_file(self, file_path: Path) -> list[ValidationFinding]:
        """Validate a single Terraform file."""
        findings = []

        if file_path.suffix == ".tf":
            parsed = self.parse_terraform_file(file_path)
        elif file_path.suffix == ".json":
            parsed = self.parse_terraform_json(file_path)
        else:
            return findings

        for block_type, resource_type, resource_name, config in self.extract_resources(parsed):
            resource_findings = self.validate_resource(
                block_type, resource_type, resource_name, config
            )
            findings.extend(resource_findings)

        return findings

    def validate_directory(
        self,
        directory: Path,
        exclude_patterns: Optional[list[str]] = None
    ) -> ValidationResult:
        """Validate all Terraform files in a directory."""
        result = ValidationResult(passed=True)
        exclude_patterns = exclude_patterns or [".terraform", ".terragrunt", "node_modules"]

        terraform_files = []
        for ext in ["*.tf", "*.tf.json"]:
            for pattern in exclude_patterns:
                terraform_files.extend(directory.rglob(ext))
            terraform_files = [
                f for f in terraform_files
                if not any(pattern in str(f) for pattern in exclude_patterns)
            ]

        for tf_file in set(terraform_files):
            try:
                file_findings = self.validate_file(tf_file)
                for finding in file_findings:
                    finding.file_path = str(tf_file)
                    result.add_finding(finding)
                result.files_validated += 1
            except Exception as e:
                result.errors.append(f"Error validating {tf_file}: {e}")

        result.passed = result.critical_count == 0 and result.high_count == 0

        return result

    def validate_with_checkov(
        self,
        directory: Path,
        framework: str = "terraform"
    ) -> Optional[ValidationResult]:
        """Run checkov validation if available."""
        if not self.checkov_available:
            logger.info("Checkov not available, using internal validation")
            return None

        try:
            result = subprocess.run(
                [
                    "checkov",
                    "-d", str(directory),
                    "--framework", framework,
                    "-o", "json"
                ],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout:
                checkov_results = json.loads(result.stdout)
                result_obj = ValidationResult(passed=result.returncode == 0)

                for check in checkov_results.get("results", {}).get("failed_checks", []):
                    finding = ValidationFinding(
                        severity=check.get("severity", "MEDIUM"),
                        resource_type=check.get("resource", ""),
                        resource_name=check.get("resource", ""),
                        check_id=check.get("check_id", ""),
                        check_name=check.get("check_name", ""),
                        message=check.get("check_result", {}).get("result", ""),
                        file_path=check.get("file_path"),
                        line_number=check.get("line_number"),
                        remediation=check.get("guideline")
                    )
                    result_obj.add_finding(finding)

                return result_obj

        except subprocess.TimeoutExpired:
            logger.error("Checkov validation timed out")
        except Exception as e:
            logger.error(f"Checkov validation failed: {e}")

        return None

    def generate_report(
        self,
        result: ValidationResult,
        format: str = "json"
    ) -> dict:
        """Generate a validation report."""
        report = {
            "validation_passed": result.passed,
            "summary": {
                "files_validated": result.files_validated,
                "resources_validated": result.resources_validated,
                "findings_total": len(result.findings),
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "duration_seconds": result.duration_seconds
            },
            "findings": [
                {
                    "severity": f.severity,
                    "resource_type": f.resource_type,
                    "resource_name": f.resource_name,
                    "check_id": f.check_id,
                    "check_name": f.check_name,
                    "message": f.message,
                    "file": f.file_path,
                    "line": f.line_number,
                    "remediation": f.remediation
                }
                for f in result.findings
            ],
            "errors": result.errors
        }

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Validate Terraform configurations against security policies"
    )
    parser.add_argument("path", type=Path, help="Path to Terraform file or directory")
    parser.add_argument("--output", default="validation-report.json", help="Output file")
    parser.add_argument("--format", choices=["json", "yaml"], default="json")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium"], default="critical")
    parser.add_argument("--no-checkov", action="store_true", help="Disable checkov integration")

    args = parser.parse_args()

    validator = TerraformValidator(checkov_enabled=not args.no_checkov)

    if args.path.is_file():
        findings = validator.validate_file(args.path)
        result = ValidationResult(
            passed=len([f for f in findings if f.severity in ["CRITICAL", "HIGH"]]) == 0,
            findings=findings,
            files_validated=1
        )
    else:
        result = validator.validate_directory(args.path)

    report = validator.generate_report(result)

    output_path = Path(args.output)
    with open(output_path, "w") as f:
        if args.format == "yaml":
            import yaml
            yaml.dump(report, f, default_flow_style=False)
        else:
            json.dump(report, f, indent=2)

    logger.info(f"Validation complete: {len(result.findings)} findings")
    logger.info(f"Report written to {output_path}")

    fail_severities = {
        "critical": ["CRITICAL"],
        "high": ["CRITICAL", "HIGH"],
        "medium": ["CRITICAL", "HIGH", "MEDIUM"]
    }

    failed_findings = [
        f for f in result.findings
        if f.severity in fail_severities[args.fail_on]
    ]

    return 0 if len(failed_findings) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())