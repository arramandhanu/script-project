"""
Kubernetes RBAC Auditor
Audits RBAC configurations for least-privilege violations,
generates risk assessments, and suggests remediation plans.
"""

import json
import argparse
from dataclasses import dataclass, field
from typing import Optional, Any, Generator
from pathlib import Path
from datetime import datetime
import logging
import re
import hashlib

import yaml
from kubernetes import client, config
from kubernetes.client import ApiClient


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class RBACRiskAssessment:
    """Risk assessment for RBAC configuration."""
    subject_type: str
    subject_name: str
    subject_namespace: Optional[str]
    risk_score: float
    risk_factors: list[str] = field(default_factory=list)
    permissions: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    last_used: Optional[datetime] = None


@dataclass
class PermissionRule:
    """Represents an RBAC permission rule."""
    api_groups: list[str]
    resources: list[str]
    verbs: list[str]
    resource_names: Optional[list[str]] = None
    non_resource_urls: Optional[list[str]] = None


@dataclass
class RBACAuditResult:
    """Aggregated RBAC audit results."""
    cluster_name: str
    audit_timestamp: datetime
    assessments: list[RBACRiskAssessment] = field(default_factory=list)
    total_subjects: int = 0
    high_risk_subjects: int = 0
    medium_risk_subjects: int = 0
    low_risk_subjects: int = 0
    overprivileged_subjects: list[str] = field(default_factory=list)
    cluster_admin_bindings: list[str] = field(default_factory=list)
    anonymous_bindings: list[str] = field(default_factory=list)


class RBACAuditor:
    """Audits Kubernetes RBAC configurations."""

    DANGEROUS_PERMISSIONS = {
        "*/create": 90,
        "*/delete": 85,
        "*/update": 80,
        "*/patch": 80,
        "*/escalate": 100,
        "*/bind": 100,
        "*/impersonate": 100,
        "secrets/create": 70,
        "secrets/update": 70,
        "secrets/delete": 75,
        "*/verb": 95,
        "*/*": 100,
        "*/": 100,
        "nodes/proxy": 95,
        "podsecuritypolicies/*": 95,
        "priorityclasses/*": 80,
    }

    PROTECTED_RESOURCES = {
        "clusterroles": "Critical cluster configuration",
        "clusterrolebindings": "Critical cluster configuration",
        "roles": "Namespace-level configuration",
        "rolebindings": "Namespace-level configuration",
        "serviceaccounts": "Workload identity",
        "secrets": "Sensitive data storage",
        "configmaps": "Application configuration",
        "certificatesigningrequests": "PKI operations",
        "tokens": "Authentication tokens",
    }

    CLUSTER_ADMIN_CLUSTERS = [
        "cluster-admin",
        "admin",
        "kubernetes-admin",
    ]

    def __init__(self, cluster_name: str = "default"):
        self.cluster_name = cluster_name
        self.rbac_api = None
        self.core_api = None
        self._initialize_clients()

    def _initialize_clients(self) -> None:
        """Initialize Kubernetes API clients."""
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except config.ConfigException:
                logger.warning("Could not load kubeconfig, using mock mode")
                self.rbac_api = None
                self.core_api = None
                return

        self.rbac_api = client.RbacAuthorizationV1Api()
        self.core_api = client.CoreV1Api()

    def _risk_score_for_permission(self, rule: PermissionRule) -> float:
        """Calculate risk score for a permission rule."""
        max_score = 0.0

        for api_group in rule.api_groups:
            for resource in rule.resources:
                for verb in rule.verbs:
                    key = f"{api_group}/{resource}/{verb}"
                    wildcard_key = f"{api_group}/*"
                    resource_wildcard = f"*/{resource}"
                    any_verb = f"*/{verb}"

                    score = self.DANGEROUS_PERMISSIONS.get(key)
                    if not score:
                        score = self.DANGEROUS_PERMISSIONS.get(wildcard_key)
                    if not score:
                        score = self.DANGEROUS_PERMISSIONS.get(resource_wildcard)
                    if not score:
                        score = self.DANGEROUS_PERMISSIONS.get(any_verb)

                    if score and score > max_score:
                        max_score = score

        if not max_score:
            if "*" in rule.verbs or "*" in rule.resources:
                max_score = 50.0

        return max_score

    def _parse_rule(self, rule_dict: dict) -> PermissionRule:
        """Parse a rule dictionary into a PermissionRule."""
        return PermissionRule(
            api_groups=rule_dict.get("apiGroups", [""]),
            resources=rule_dict.get("resources", []),
            verbs=rule_dict.get("verbs", []),
            resource_names=rule_dict.get("resourceNames"),
            non_resource_urls=rule_dict.get("nonResourceURLs")
        )

    def audit_cluster_roles(self) -> list[RBACRiskAssessment]:
        """Audit all ClusterRoles in the cluster."""
        assessments = []

        try:
            cluster_roles = self.rbac_api.list_cluster_role().items

            for cr in cluster_roles:
                assessment = self._assess_role_permissions(
                    subject_type="ClusterRole",
                    subject_name=cr.metadata.name,
                    subject_namespace=None,
                    rules=cr.rules or []
                )
                assessments.append(assessment)

        except Exception as e:
            logger.error(f"Failed to audit cluster roles: {e}")

        return assessments

    def audit_roles(self, namespace: Optional[str] = None) -> list[RBACRiskAssessment]:
        """Audit all Roles in specified namespace or all namespaces."""
        assessments = []

        try:
            if namespace:
                roles = self.rbac_api.list_namespaced_role(namespace).items
            else:
                all_roles = []
                namespaces = self.core_api.list_namespace().items

                for ns in namespaces:
                    roles = self.rbac_api.list_namespaced_role(ns.metadata.name).items
                    all_roles.extend(roles)

                roles = all_roles

            for role in roles:
                assessment = self._assess_role_permissions(
                    subject_type="Role",
                    subject_name=role.metadata.name,
                    subject_namespace=role.metadata.namespace,
                    rules=role.rules or []
                )
                assessments.append(assessment)

        except Exception as e:
            logger.error(f"Failed to audit roles: {e}")

        return assessments

    def _assess_role_permissions(
        self,
        subject_type: str,
        subject_name: str,
        subject_namespace: Optional[str],
        rules: list[dict]
    ) -> RBACRiskAssessment:
        """Assess permissions for a role."""
        risk_factors = []
        permissions = []
        total_risk = 0.0

        for rule_dict in rules:
            rule = self._parse_rule(rule_dict)
            rule_risk = self._risk_score_for_permission(rule)
            total_risk += rule_risk

            perm_info = {
                "api_groups": rule.api_groups,
                "resources": rule.resources,
                "verbs": rule.verbs,
                "risk_score": rule_risk
            }
            permissions.append(perm_info)

            for resource in rule.resources:
                if resource in self.PROTECTED_RESOURCES:
                    risk_factors.append(
                        f"Access to protected resource: {resource}"
                    )

            if "*" in rule.verbs:
                risk_factors.append(f"Wildcard verbs on {rule.resources}")

            if "*" in rule.resources:
                risk_factors.append(f"Wildcard resources in {rule.api_groups}")

            if rule.resource_names and "*" in rule.resource_names:
                risk_factors.append(f"Wildcard resource names on {rule.resources}")

        if total_risk >= 80:
            risk_level = "HIGH"
        elif total_risk >= 50:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        recommendations = self._generate_recommendations(
            subject_name, permissions, risk_level
        )

        return RBACRiskAssessment(
            subject_type=subject_type,
            subject_name=subject_name,
            subject_namespace=subject_namespace,
            risk_score=total_risk,
            risk_factors=risk_factors,
            permissions=permissions,
            recommendations=recommendations
        )

    def _generate_recommendations(
        self,
        role_name: str,
        permissions: list[dict],
        risk_level: str
    ) -> list[str]:
        """Generate remediation recommendations."""
        recommendations = []

        if risk_level == "HIGH":
            recommendations.append(
                f"Review {role_name} - high risk score indicates overprivileged role"
            )

        wildcard_perms = [
            p for p in permissions
            if "*" in p["verbs"] or "*" in p["resources"]
        ]

        if wildcard_perms:
            recommendations.append(
                f"Replace {len(wildcard_perms)} wildcard permissions with specific resources/verbs"
            )

        dangerous_perms = [
            "escalate", "bind", "impersonate"
        ]

        for perm in permissions:
            if any(d in perm["verbs"] for d in dangerous_perms):
                recommendations.append(
                    f"Review {', '.join(dangerous_perms)} permissions - these can lead to privilege escalation"
                )

        recommendations.append(
            f"Implement least-privilege: use specific resources and verbs"
        )

        return recommendations[:5]

    def audit_cluster_role_bindings(self) -> list[RBACRiskAssessment]:
        """Audit ClusterRoleBindings for risky assignments."""
        assessments = []

        try:
            bindings = self.rbac_api.list_cluster_role_binding().items

            for binding in bindings:
                assessment = self._assess_binding(
                    binding_type="ClusterRoleBinding",
                    binding_name=binding.metadata.name,
                    subjects=binding.subjects or [],
                    role_ref=binding.role_ref
                )
                assessments.append(assessment)

        except Exception as e:
            logger.error(f"Failed to audit cluster role bindings: {e}")

        return assessments

    def audit_role_bindings(self, namespace: Optional[str] = None) -> list[RBACRiskAssessment]:
        """Audit RoleBindings for risky assignments."""
        assessments = []

        try:
            if namespace:
                bindings = self.rbac_api.list_namespaced_role_binding(namespace).items
            else:
                all_bindings = []
                namespaces = self.core_api.list_namespace().items

                for ns in namespaces:
                    bindings = self.rbac_api.list_namespaced_role_binding(ns.metadata.name).items
                    all_bindings.extend(bindings)

                bindings = all_bindings

            for binding in bindings:
                assessment = self._assess_binding(
                    binding_type="RoleBinding",
                    binding_name=binding.metadata.name,
                    subjects=binding.subjects or [],
                    role_ref=binding.role,
                    namespace=binding.metadata.namespace
                )
                assessments.append(assessment)

        except Exception as e:
            logger.error(f"Failed to audit role bindings: {e}")

        return assessments

    def _assess_binding(
        self,
        binding_type: str,
        binding_name: str,
        subjects: list,
        role_ref: Any,
        namespace: Optional[str] = None
    ) -> RBACRiskAssessment:
        """Assess a binding for risk factors."""
        risk_factors = []
        is_anonymous = False
        is_cluster_admin = False

        for subject in subjects:
            if subject.kind == "User" and subject.name == "system:anonymous":
                is_anonymous = True
                risk_factors.append("Anonymous user has cluster access")

            if subject.kind == "ServiceAccount":
                risk_factors.append(
                    f"ServiceAccount {subject.namespace}/{subject.name} bound"
                )

        if role_ref and hasattr(role_ref, "name"):
            if role_ref.name in self.CLUSTER_ADMIN_CLUSTERS:
                is_cluster_admin = True
                risk_factors.append(f"Cluster-admin role binding: {role_ref.name}")

        risk_score = 50.0 if is_cluster_admin else 30.0
        risk_score += 20.0 if is_anonymous else 0.0

        return RBACRiskAssessment(
            subject_type=binding_type,
            subject_name=binding_name,
            subject_namespace=namespace,
            risk_score=risk_score,
            risk_factors=risk_factors,
            permissions=[{"role": role_ref.name if role_ref else "unknown"}],
            recommendations=["Review binding necessity and implement least-privilege"]
        )

    def audit_service_accounts(self) -> list[RBACRiskAssessment]:
        """Audit ServiceAccounts for token usage and permissions."""
        assessments = []

        try:
            namespaces = self.core_api.list_namespace().items

            for ns in namespaces:
                service_accounts = self.core_api.list_namespaced_service_account(ns.metadata.name).items

                for sa in service_accounts:
                    assessment = self._assess_service_account(sa)
                    assessments.append(assessment)

        except Exception as e:
            logger.error(f"Failed to audit service accounts: {e}")

        return assessments

    def _assess_service_account(self, sa) -> RBACRiskAssessment:
        """Assess a ServiceAccount for risk."""
        risk_factors = []
        risk_score = 10.0

        if sa.automount_service_account_token:
            risk_factors.append("Service account token auto-mounted")
            risk_score += 15.0

        annotations = sa.metadata.annotations or {}
        for key, value in annotations.items():
            if "eks.amazonaws.com" in key or "gke-gke" in key:
                risk_factors.append("Cloud provider workload identity detected")

        recommendations = []
        if risk_score > 20:
            recommendations.append(
                "Disable automount_service_account_token if not needed"
            )
            recommendations.append(
                "Use projected volumes for token mounting with audience and expiration"
            )

        return RBACRiskAssessment(
            subject_type="ServiceAccount",
            subject_name=sa.metadata.name,
            subject_namespace=sa.metadata.namespace,
            risk_score=risk_score,
            risk_factors=risk_factors,
            recommendations=recommendations
        )

    def run_full_audit(self) -> RBACAuditResult:
        """Run a comprehensive RBAC audit."""
        result = RBACAuditResult(
            cluster_name=self.cluster_name,
            audit_timestamp=datetime.now()
        )

        assessments = []
        assessments.extend(self.audit_cluster_roles())
        assessments.extend(self.audit_roles())
        assessments.extend(self.audit_cluster_role_bindings())
        assessments.extend(self.audit_role_bindings())
        assessments.extend(self.audit_service_accounts())

        result.assessments = assessments
        result.total_subjects = len(assessments)
        result.high_risk_subjects = len([a for a in assessments if a.risk_score >= 80])
        result.medium_risk_subjects = len([a for a in assessments if 50 <= a.risk_score < 80])
        result.low_risk_subjects = len([a for a in assessments if a.risk_score < 50])

        for assessment in assessments:
            if assessment.risk_score >= 80:
                result.overprivileged_subjects.append(
                    f"{assessment.subject_type}/{assessment.subject_name}"
                )

            if assessment.subject_type in ["ClusterRoleBinding", "RoleBinding"]:
                if "cluster-admin" in assessment.subject_name.lower():
                    result.cluster_admin_bindings.append(assessment.subject_name)

        return result

    def generate_manifest_report(self, result: RBACAuditResult) -> dict:
        """Generate a Kubernetes-style manifest report."""
        report = {
            "apiVersion": "v1",
            "kind": "RBACAuditReport",
            "metadata": {
                "name": f"rbac-audit-{self.cluster_name}-{datetime.now().strftime('%Y%m%d')}",
                "labels": {
                    "audit-type": "rbac",
                    "cluster": self.cluster_name
                }
            },
            "report": {
                "type": "RBAC Security Audit",
                "timestamp": result.audit_timestamp.isoformat(),
                "summary": {
                    "total_subjects": result.total_subjects,
                    "high_risk": result.high_risk_subjects,
                    "medium_risk": result.medium_risk_subjects,
                    "low_risk": result.low_risk_subjects,
                    "cluster_admin_bindings": len(result.cluster_admin_bindings)
                },
                "findings": [
                    {
                        "subject_type": a.subject_type,
                        "subject_name": a.subject_name,
                        "namespace": a.subject_namespace,
                        "risk_score": a.risk_score,
                        "risk_factors": a.risk_factors,
                        "permissions": a.permissions,
                        "recommendations": a.recommendations
                    }
                    for a in sorted(
                        result.assessments,
                        key=lambda x: x.risk_score,
                        reverse=True
                    )[:50]
                ],
                "remediation_plan": self._generate_remediation_plan(result)
            }
        }

        return report

    def _generate_remediation_plan(self, result: RBACAuditResult) -> dict:
        """Generate a structured remediation plan."""
        plan = {
            "priority_actions": [],
            "medium_priority_actions": [],
            "low_priority_actions": []
        }

        for assessment in result.assessments:
            if assessment.risk_score >= 80:
                plan["priority_actions"].append({
                    "action": f"Review {assessment.subject_type} {assessment.subject_name}",
                    "reason": assessment.risk_factors[:2],
                    "recommendations": assessment.recommendations[:2]
                })
            elif assessment.risk_score >= 50:
                plan["medium_priority_actions"].append({
                    "action": f"Assess {assessment.subject_type} {assessment.subject_name}",
                    "reason": assessment.risk_factors[:1]
                })

        return plan


def main():
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes RBAC configurations"
    )
    parser.add_argument("--cluster-name", default="production", help="Cluster name")
    parser.add_argument("--namespace", help="Specific namespace to audit")
    parser.add_argument("--output", default="rbac-audit-report.json", help="Output file")
    parser.add_argument("--format", choices=["json", "yaml", "manifest"], default="json")
    parser.add_argument("--include-anonymous", action="store_true", help="Include anonymous bindings")

    args = parser.parse_args()

    auditor = RBACAuditor(cluster_name=args.cluster_name)
    result = auditor.run_full_audit()

    if args.format == "manifest":
        report = auditor.generate_manifest_report(result)
    else:
        report = {
            "cluster": result.cluster_name,
            "timestamp": result.audit_timestamp.isoformat(),
            "summary": {
                "total_subjects": result.total_subjects,
                "high_risk": result.high_risk_subjects,
                "medium_risk": result.medium_risk_subjects,
                "low_risk": result.low_risk_subjects
            },
            "assessments": [
                {
                    "type": a.subject_type,
                    "name": a.subject_name,
                    "namespace": a.subject_namespace,
                    "risk_score": a.risk_score,
                    "risk_factors": a.risk_factors,
                    "recommendations": a.recommendations
                }
                for a in sorted(result.assessments, key=lambda x: x.risk_score, reverse=True)
            ],
            "overprivileged": result.overprivileged_subjects,
            "cluster_admin_bindings": result.cluster_admin_bindings
        }

    output_path = Path(args.output)
    with open(output_path, "w") as f:
        if args.format == "yaml":
            yaml.dump(report, f, default_flow_style=False)
        else:
            json.dump(report, f, indent=2)

    logger.info(f"Audit complete: {result.total_subjects} subjects analyzed")
    logger.info(f"High risk: {result.high_risk_subjects}, Medium: {result.medium_risk_subjects}")
    logger.info(f"Report written to {output_path}")

    return 0 if result.high_risk_subjects == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())