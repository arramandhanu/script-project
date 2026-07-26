"""
IAM Policy Analyzer
Analyzes IAM policies across AWS accounts for least-privilege violations
and generates remediation recommendations.
"""

import json
import argparse
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

import boto3
from botocore.exceptions import ClientError, BotoCoreError


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class PolicyFinding:
    """Represents a policy finding with severity and remediation."""
    account_id: str
    policy_name: str
    resource: str
    finding_type: str
    severity: str
    description: str
    current_statement: dict
    recommendation: str
    cvss_score: Optional[float] = None


@dataclass
class IAMAnalysisResult:
    """Aggregated results from IAM policy analysis."""
    account_id: str
    findings: list[PolicyFinding] = field(default_factory=list)
    policies_analyzed: int = 0
    resources_scanned: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

    def add_finding(self, finding: PolicyFinding) -> None:
        self.findings.append(finding)
        self.policies_analyzed += 1
        if finding.severity == "CRITICAL":
            self.critical_findings += 1
        elif finding.severity == "HIGH":
            self.high_findings += 1
        elif finding.severity == "MEDIUM":
            self.medium_findings += 1
        else:
            self.low_findings += 1


class IAMPolicyAnalyzer:
    """Analyzes IAM policies for security and compliance violations."""

    PRIVILEGED_ACTION_PATTERNS = {
        "iam:PassRole": {
            "severity": "HIGH",
            "description": "Allows iam:PassRole which can be used for privilege escalation",
            "recommendation": "Restrict to specific service roles that require this permission"
        },
        "iam:AttachManagedPolicy": {
            "severity": "CRITICAL",
            "description": "Allows attaching managed policies to modify permissions",
            "recommendation": "Remove this permission and use role-based access control"
        },
        "iam:CreateUser": {
            "severity": "HIGH",
            "description": "Allows creation of new IAM users",
            "recommendation": "Restrict to break-glass scenarios only"
        },
        "iam:CreateAccessKey": {
            "severity": "CRITICAL",
            "description": "Allows creation of access keys - potential for persistence",
            "recommendation": "Use temporary credentials via STS instead"
        },
        "s3:*": {
            "severity": "CRITICAL",
            "description": "Wildcard on S3 provides full access to all buckets",
            "recommendation": "Restrict to specific actions and resources"
        },
        "*": {
            "severity": "CRITICAL",
            "description": "Full wildcard permissions - extreme risk",
            "recommendation": "Never use wildcard permissions in production"
        }
    }

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.iam_client = None

    def _get_iam_client(self, role_arn: Optional[str] = None):
        """Get IAM client, optionally assuming a cross-account role."""
        if role_arn:
            sts = boto3.client("sts")
            try:
                credentials = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="iam-analyzer-session"
                )["Credentials"]
                return boto3.client(
                    "iam",
                    region_name=self.region,
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"]
                )
            except ClientError as e:
                logger.warning(f"Failed to assume role {role_arn}: {e}")
                return None
        return boto3.client("iam", region_name=self.region)

    def analyze_inline_policies(self, iam_client) -> list[PolicyFinding]:
        """Analyze inline policies for violations."""
        findings = []
        try:
            roles = iam_client.list_roles(MaxResults=100)
            for role in roles["Roles"]:
                try:
                    role_name = role["RoleName"]
                    policies = iam_client.list_role_policies(RoleName=role_name)

                    for policy_name in policies["PolicyNames"]:
                        policy_doc = iam_client.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name
                        )["PolicyDocument"]

                        for statement in policy_doc.get("Statement", []):
                            if statement.get("Effect") == "Allow":
                                for action in self._expand_actions(statement.get("Action", [])):
                                    if action in self.PRIVILEGED_ACTION_PATTERNS:
                                        pattern = self.PRIVILEGED_ACTION_PATTERNS[action]
                                        finding = PolicyFinding(
                                            account_id=iam_client._client_config.region_name,
                                            policy_name=f"{role_name}/{policy_name}",
                                            resource=statement.get("Resource", "*"),
                                            finding_type="PRIVILEGED_ACTION",
                                            severity=pattern["severity"],
                                            description=pattern["description"],
                                            current_statement=statement,
                                            recommendation=pattern["recommendation"]
                                        )
                                        findings.append(finding)

                except ClientError as e:
                    logger.debug(f"Error analyzing role {role_name}: {e}")
                    continue

        except ClientError as e:
            logger.error(f"Failed to list roles: {e}")

        return findings

    def _expand_actions(self, actions) -> list[str]:
        """Expand wildcard actions to their components."""
        expanded = []
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            if "*" in action:
                expanded.append(action)
            else:
                expanded.append(action)

        return expanded

    def analyze_managed_policies(self, iam_client) -> list[PolicyFinding]:
        """Analyze attached managed policies."""
        findings = []
        try:
            policies = iam_client.list_policies(Scope="Local", MaxItems=100)

            for policy in policies["Policies"]:
                try:
                    versions = iam_client.list_policy_versions(
                        PolicyArn=policy["Arn"]
                    )

                    for version in versions["Versions"]:
                        if not version["IsDefaultVersion"]:
                            continue

                        doc = iam_client.get_policy_version(
                            PolicyArn=policy["Arn"],
                            PolicyVersionIdentifier=version["VersionId"]
                        )["PolicyVersion"]["Document"]

                        for statement in doc.get("Statement", []):
                            if statement.get("Effect") == "Allow":
                                for action in self._expand_actions(statement.get("Action", [])):
                                    if action in self.PRIVILEGED_ACTION_PATTERNS:
                                        pattern = self.PRIVILEGED_ACTION_PATTERNS[action]
                                        finding = PolicyFinding(
                                            account_id=iam_client._client_config.region_name,
                                            policy_name=policy["PolicyName"],
                                            resource=statement.get("Resource", "*"),
                                            finding_type="MANAGED_POLICY_VIOLATION",
                                            severity=pattern["severity"],
                                            description=pattern["description"],
                                            current_statement=statement,
                                            recommendation=pattern["recommendation"]
                                        )
                                        findings.append(finding)

                except ClientError as e:
                    logger.debug(f"Error analyzing policy {policy['PolicyName']}: {e}")
                    continue

        except ClientError as e:
            logger.error(f"Failed to list policies: {e}")

        return findings

    def run_analysis(self, account_id: str, role_arn: Optional[str] = None) -> IAMAnalysisResult:
        """Run full IAM analysis on an account."""
        result = IAMAnalysisResult(account_id=account_id)
        iam_client = self._get_iam_client(role_arn)

        if not iam_client:
            logger.error(f"Could not initialize IAM client for account {account_id}")
            return result

        inline_findings = self.analyze_inline_policies(iam_client)
        managed_findings = self.analyze_managed_policies(iam_client)

        for finding in inline_findings + managed_findings:
            result.add_finding(finding)

        result.resources_scanned = len(result.findings)
        return result

    def generate_remediation_plan(self, result: IAMAnalysisResult) -> dict:
        """Generate a structured remediation plan from analysis results."""
        plan = {
            "account_id": result.account_id,
            "generated_at": str(Path(__file__).stat().st_mtime),
            "summary": {
                "total_findings": len(result.findings),
                "critical": result.critical_findings,
                "high": result.high_findings,
                "medium": result.medium_findings,
                "low": result.low_findings
            },
            "remediation_steps": []
        }

        for finding in result.findings:
            plan["remediation_steps"].append({
                "priority": finding.severity,
                "target": finding.policy_name,
                "action": "MODIFY_POLICY",
                "description": finding.recommendation,
                "current_state": json.dumps(finding.current_statement, indent=2),
                "finding_type": finding.finding_type
            })

        plan["remediation_steps"].sort(
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[x["priority"]]
        )

        return plan


def main():
    parser = argparse.ArgumentParser(
        description="Analyze IAM policies for least-privilege violations"
    )
    parser.add_argument("--account-id", help="AWS Account ID to analyze")
    parser.add_argument("--role-arn", help="Cross-account role ARN to assume")
    parser.add_argument("--output", default="iam-findings.json", help="Output file path")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--format", choices=["json", "yaml"], default="json", help="Output format")

    args = parser.parse_args()

    analyzer = IAMPolicyAnalyzer(region=args.region)

    if args.account_id:
        result = analyzer.run_analysis(args.account_id, args.role_arn)
    else:
        sts = boto3.client("sts")
        result = analyzer.run_analysis(sts.meta.service_model.region_name)

    plan = analyzer.generate_remediation_plan(result)

    output_path = Path(args.output)
    with open(output_path, "w") as f:
        if args.format == "yaml":
            import yaml
            yaml.dump(plan, f, default_flow_style=False)
        else:
            json.dump(plan, f, indent=2)

    logger.info(f"Analysis complete. Found {len(result.findings)} findings.")
    logger.info(f"Results written to {output_path}")

    return 0 if result.critical_findings == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())