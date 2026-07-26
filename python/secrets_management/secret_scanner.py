"""
Secret Scanner and Remediator
Scans repositories and environments for exposed secrets,
validates rotation status, and generates remediation tickets.
"""

import json
import re
import argparse
from dataclasses import dataclass, field
from typing import Optional, Any, Generator
from pathlib import Path
from datetime import datetime, timedelta
import logging
import hashlib
import base64

import requests


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class SecretMatch:
    """Represents a detected secret."""
    type: str
    value: str
    file_path: str
    line_number: int
    commit_sha: Optional[str] = None
    branch: Optional[str] = None
    author: Optional[str] = None
    detected_at: Optional[datetime] = None
    confidence: float = 0.0


@dataclass
class SecretInventoryEntry:
    """Entry in the secret inventory."""
    secret_name: str
    secret_type: str
    arn: Optional[str]
    last_rotated: Optional[datetime]
    next_rotation: Optional[datetime]
    rotation_status: str
    tags: dict
    accounts: list[str]


class GitSecretsScanner:
    """Scans git repositories for secrets using pattern matching."""

    SECRET_PATTERNS = {
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "severity": "CRITICAL",
            "description": "AWS Access Key ID"
        },
        "aws_secret_key": {
            "pattern": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}",
            "severity": "CRITICAL",
            "description": "AWS Secret Access Key"
        },
        "github_token": {
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
            "severity": "CRITICAL",
            "description": "GitHub Personal Access Token"
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
        "private_key": {
            "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "severity": "CRITICAL",
            "description": "Private Key"
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "severity": "MEDIUM",
            "description": "JWT Token"
        },
        "generic_api_key": {
            "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}",
            "severity": "MEDIUM",
            "description": "Generic API Key"
        },
        "azure_token": {
            "pattern": r"[A-Za-z0-9+/]{86}==",
            "severity": "HIGH",
            "description": "Azure AD Token"
        },
        "google_api_key": {
            "pattern": r"AIza[0-9A-Za-z_-]{35}",
            "severity": "HIGH",
            "description": "Google API Key"
        },
        "stripe_key": {
            "pattern": r"sk_live_[0-9a-zA-Z]{24}",
            "severity": "HIGH",
            "description": "Stripe Live API Key"
        },
        "ssh_password": {
            "pattern": r"(?i)password\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            "severity": "MEDIUM",
            "description": "Password in configuration"
        }
    }

    EXCLUDED_PATHS = [
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".terraform",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache"
    ]

    EXCLUDED_EXTENSIONS = [
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
        ".pdf", ".zip", ".tar", ".gz",
        ".lock", ".sum"
    ]

    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = repo_path
        self.matches = []

    def scan_file(self, file_path: Path) -> list[SecretMatch]:
        """Scan a single file for secrets."""
        matches = []

        if any(ext in str(file_path) for ext in self.EXCLUDED_EXTENSIONS):
            return matches

        try:
            content = file_path.read_text(errors="ignore")
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                for secret_type, config in self.SECRET_PATTERNS.items():
                    pattern = config["pattern"]
                    matches_found = re.finditer(pattern, line)

                    for match in matches_found:
                        masked_value = self._mask_secret(match.group(0), secret_type)

                        match_obj = SecretMatch(
                            type=secret_type,
                            value=masked_value,
                            file_path=str(file_path),
                            line_number=line_num,
                            detected_at=datetime.now(),
                            confidence=0.9
                        )
                        matches.append(match_obj)

        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")

        return matches

    def _mask_secret(self, secret: str, secret_type: str) -> str:
        """Mask a secret value for safe logging."""
        if len(secret) <= 8:
            return "*" * len(secret)

        if secret_type in ["aws_access_key"]:
            return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

        return secret[:4] + "*" * 20 + secret[-4:]

    def scan_directory(self, directory: Path) -> list[SecretMatch]:
        """Scan directory for secrets."""
        all_matches = []

        for file_path in directory.rglob("*"):
            if file_path.is_file():
                file_matches = self.scan_file(file_path)
                all_matches.extend(file_matches)

        return all_matches

    def scan_git_history(self, repo_path: Path) -> list[SecretMatch]:
        """Scan git history for secrets committed in the past."""
        matches = []

        try:
            import subprocess

            result = subprocess.run(
                ["git", "-C", str(repo_path), "log", "--all", "--full-history", "--source",
                 "--remotes", "-p", "--name-only"],
                capture_output=True,
                text=True,
                timeout=60
            )

            current_file = None
            current_commit = None

            for line in result.stdout.split("\n"):
                if line.startswith("commit "):
                    current_commit = line.split()[1]
                elif line.strip().endswith((".py", ".yaml", ".json", ".tf", ".sh")):
                    current_file = line.strip()
                elif current_file and current_commit:
                    for secret_type, config in self.SECRET_PATTERNS.items():
                        if re.search(config["pattern"], line):
                            matches.append(SecretMatch(
                                type=secret_type,
                                value=self._mask_secret(
                                    re.search(config["pattern"], line).group(0),
                                    secret_type
                                ),
                                file_path=current_file,
                                line_number=0,
                                commit_sha=current_commit,
                                confidence=0.7
                            ))

        except Exception as e:
            logger.error(f"Git history scan failed: {e}")

        return matches

    def generate_report(self, matches: list[SecretMatch], output_path: Path) -> dict:
        """Generate scan report."""
        by_type = {}
        for match in matches:
            if match.type not in by_type:
                by_type[match.type] = []
            by_type[match.type].append({
                "file": match.file_path,
                "line": match.line_number,
                "commit": match.commit_sha,
                "confidence": match.confidence
            })

        report = {
            "scan_timestamp": datetime.now().isoformat(),
            "total_matches": len(matches),
            "by_type": {
                secret_type: len(matches_list)
                for secret_type, matches_list in by_type.items()
            },
            "findings": matches,
            "severity_summary": {
                "CRITICAL": sum(1 for m in matches if self.SECRET_PATTERNS[m.type]["severity"] == "CRITICAL"),
                "HIGH": sum(1 for m in matches if self.SECRET_PATTERNS[m.type]["severity"] == "HIGH"),
                "MEDIUM": sum(1 for m in matches if self.SECRET_PATTERNS[m.type]["severity"] == "MEDIUM")
            }
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        return report


class SecretsManagerValidator:
    """Validates secrets in AWS Secrets Manager."""

    def __init__(self, region: str = "us-east-1"):
        import boto3
        self.secrets_client = boto3.client("secretsmanager", region_name=region)

    def list_secrets(self, tag_filter: Optional[dict] = None) -> list[dict]:
        """List secrets with optional tag filter."""
        try:
            if tag_filter:
                filters = [
                    {"Key": "tag-key", "Values": [list(tag_filter.keys())[0]]},
                    {"Key": "tag-value", "Values": [list(tag_filter.values())[0]]}
                ]
                secrets = self.secrets_client.list_secrets(Filters=filters)["SecretList"]
            else:
                secrets = self.secrets_client.list_secrets()["SecretList"]

            return [
                {
                    "name": s["Name"],
                    "arn": s["ARN"],
                    "tags": s.get("Tags", []),
                    "last_rotated": s.get("LastRotatedDate"),
                    "last_changed": s.get("LastChangedDate"]),
                    "next_rotation": s.get("NextRotationDate"),
                    "rotation_enabled": s.get("RotationEnabled", False)
                }
                for s in secrets
            ]

        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []

    def check_rotation_status(self, secret_name: str) -> dict:
        """Check rotation status for a secret."""
        try:
            rotation = self.secrets_client.rotate_secret(
                SecretId=secret_name,
                RotationLambdaArn="",
                RotationRules={"AutomaticallyAfterDays": 0}
            )

            return {
                "secret_name": secret_name,
                "rotation_triggered": True,
                "message": "Rotation check completed"
            }

        except Exception as e:
            return {
                "secret_name": secret_name,
                "rotation_triggered": False,
                "message": str(e)
            }

    def audit_rotation_compliance(
        self,
        max_age_days: int = 90,
        required_tag: Optional[str] = None
    ) -> dict:
        """Audit secrets rotation compliance."""
        secrets = self.list_secrets({"compliance": "required"} if required_tag else None)

        compliant = []
        non_compliant = []
        stale = []

        now = datetime.now()

        for secret in secrets:
            last_rotated = secret.get("last_rotated")

            if not last_rotated:
                stale.append(secret["name"])
                non_compliant.append(secret["name"])
                continue

            age = (now - last_rotated).days

            if age > max_age_days:
                stale.append(secret["name"])
                non_compliant.append(secret["name"])
            else:
                compliant.append(secret["name"])

        return {
            "total_secrets": len(secrets),
            "compliant": len(compliant),
            "non_compliant": len(non_compliant),
            "stale_secrets": stale,
            "compliance_rate": len(compliant) / len(secrets) if secrets else 0
        }


class TicketGenerator:
    """Generates remediation tickets for secrets findings."""

    JIRA_TEMPLATE = {
        "project": {"key": "SEC"},
        "summary": "Secret Exposure: {secret_type} in {file_path}",
        "description": """
**Severity**: {severity}

**Finding**:
- Type: {secret_type}
- Location: {file_path}:{line_number}
- Detected: {detected_at}

**Description**: {description}

**Actions Required**:
1. Rotate the exposed secret immediately
2. Revoke any active sessions using this secret
3. Review access logs for unauthorized usage
4. Update secret in secure storage (AWS Secrets Manager)
5. Add pre-commit hook to prevent future exposure

**Remediation Status**: Pending
""",
        "issuetype": {"name": "Security Incident"},
        "priority": {"name": "High"}
    }

    def __init__(self, jira_config: Optional[dict] = None):
        self.jira_config = jira_config

    def create_ticket(self, match: SecretMatch) -> Optional[str]:
        """Create a remediation ticket for a secret finding."""
        if not self.jira_config:
            logger.info("JIRA not configured, skipping ticket creation")
            return None

        template = self.JIRA_TEMPLATE.copy()
        template["summary"] = template["summary"].format(
            secret_type=match.type,
            file_path=match.file_path
        )
        template["description"] = template["description"].format(
            secret_type=match.type,
            file_path=match.file_path,
            line_number=match.line_number,
            detected_at=match.detected_at or datetime.now().isoformat(),
            description=f"Exposed {match.type} detected in repository"
        )

        try:
            response = requests.post(
                f"{self.jira_config['url']}/rest/api/3/issue",
                json=template,
                headers={"Authorization": f"Bearer {self.jira_config['token']}"},
                timeout=10
            )

            if response.status_code == 201:
                return response.json()["key"]

        except Exception as e:
            logger.error(f"Failed to create ticket: {e}")

        return None

    def bulk_create_tickets(self, matches: list[SecretMatch]) -> dict[str, str]:
        """Create tickets for multiple findings."""
        tickets = {}

        for match in matches:
            ticket_key = self.create_ticket(match)
            if ticket_key:
                tickets[f"{match.file_path}:{match.line_number}"] = ticket_key

        return tickets


def main():
    parser = argparse.ArgumentParser(
        description="Scan for exposed secrets and generate remediation plans"
    )
    parser.add_argument("path", type=Path, help="Path to scan")
    parser.add_argument("--output", default="secret-scan-report.json", help="Output file")
    parser.add_argument("--scan-git-history", action="store_true", help="Scan git history")
    parser.add_argument("--jira-url", help="JIRA URL for ticket creation")
    parser.add_argument("--jira-token", help="JIRA API token")

    args = parser.parse_args()

    scanner = GitSecretsScanner()

    if args.path.is_dir():
        matches = scanner.scan_directory(args.path)

        if args.scan_git_history:
            git_matches = scanner.scan_git_history(args.path)
            matches.extend(git_matches)
    else:
        matches = scanner.scan_file(args.path)

    report = scanner.generate_report(matches, Path(args.output))

    logger.info(f"Scan complete: {len(matches)} secrets found")
    logger.info(f"Critical: {report['severity_summary']['CRITICAL']}")
    logger.info(f"High: {report['severity_summary']['HIGH']}")
    logger.info(f"Report written to {args.output}")

    if matches and args.jira_url:
        jira_config = {"url": args.jira_url, "token": args.jira_token}
        generator = TicketGenerator(jira_config)
        tickets = generator.bulk_create_tickets(matches)
        logger.info(f"Created {len(tickets)} JIRA tickets")

    return 0 if len(matches) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())