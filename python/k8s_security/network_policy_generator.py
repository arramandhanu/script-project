"""
Kubernetes Network Policy Generator
Generates least-privilege network policies based on service mesh
traffic analysis and dependency mapping.
"""

import json
import argparse
from dataclasses import dataclass, field
from typing import Optional, Any, Generator
from pathlib import Path
from datetime import datetime
import logging
import re
from collections import defaultdict

import yaml
from kubernetes import client, config


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class ServiceEndpoint:
    """Represents a service endpoint."""
    name: str
    namespace: str
    pod_selector: dict
    ports: list[dict]
    pod_count: int = 0


@dataclass
class NetworkFlow:
    """Represents an observed network flow."""
    source_namespace: str
    source_pod: str
    source_labels: dict
    dest_namespace: str
    dest_pod: str
    dest_labels: dict
    dest_port: int
    protocol: str
    observed_count: int = 0
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None


@dataclass
class PolicyTemplate:
    """Template for network policy generation."""
    policy_name: str
    namespace: str
    pod_selector: dict
    policy_types: list[str]
    ingress_rules: list[dict]
    egress_rules: list[dict]


class NetworkPolicyGenerator:
    """Generates Kubernetes network policies based on traffic analysis."""

    def __init__(self):
        self.core_api = None
        self.networking_api = None
        self._initialize_clients()

    def _initialize_clients(self) -> None:
        """Initialize Kubernetes API clients."""
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except config.ConfigException:
                logger.warning("Could not load kubeconfig")
                return

        self.core_api = client.CoreV1Api()
        self.networking_api = client.NetworkingV1Api()

    def discover_services(self, namespace: Optional[str] = None) -> list[ServiceEndpoint]:
        """Discover all services in the cluster."""
        services = []

        try:
            if namespace:
                svc_list = self.core_api.list_namespaced_service(namespace).items
            else:
                svc_list = self.core_api.list_service_for_all_namespaces().items

            for svc in svc_list:
                endpoint = ServiceEndpoint(
                    name=svc.metadata.name,
                    namespace=svc.metadata.namespace,
                    pod_selector=svc.spec.selector or {},
                    ports=[
                        {"port": p.port, "protocol": p.protocol}
                        for p in (svc.spec.ports or [])
                    ]
                )

                pod_count = self._count_pods_for_selector(
                    endpoint.namespace,
                    endpoint.pod_selector
                )
                endpoint.pod_count = pod_count

                services.append(endpoint)

        except Exception as e:
            logger.error(f"Failed to discover services: {e}")

        return services

    def _count_pods_for_selector(self, namespace: str, selector: dict) -> int:
        """Count pods matching a selector."""
        try:
            pods = self.core_api.list_namespaced_pod(
                namespace,
                label_selector=self._build_selector_string(selector)
            )
            return len(pods.items)
        except Exception:
            return 0

    def _build_selector_string(self, selector: dict) -> str:
        """Build Kubernetes label selector string."""
        return ",".join(f"{k}={v}" for k, v in selector.items())

    def parse_envoy_access_logs(self, log_path: Path) -> list[NetworkFlow]:
        """Parse Envoy access logs to extract network flows."""
        flows = []

        if not log_path.exists():
            logger.warning(f"Log file not found: {log_path}")
            return flows

        flow_counts = defaultdict(lambda: {
            "count": 0,
            "first": None,
            "last": None
        })

        with open(log_path, "r") as f:
            for line in f:
                try:
                    flow = self._parse_envoy_log_line(line)
                    if flow:
                        key = (
                            flow.source_namespace,
                            flow.source_pod,
                            flow.dest_namespace,
                            flow.dest_pod,
                            flow.dest_port
                        )
                        flow_counts[key]["count"] += 1
                        if not flow_counts[key]["first"]:
                            flow_counts[key]["first"] = flow.first_observed
                        flow_counts[key]["last"] = flow.last_observed

                except Exception as e:
                    logger.debug(f"Failed to parse log line: {e}")

        for key, data in flow_counts.items():
            flows.append(NetworkFlow(
                source_namespace=key[0],
                source_pod=key[1],
                source_labels={},
                dest_namespace=key[2],
                dest_pod=key[3],
                dest_labels={},
                dest_port=key[4],
                protocol="TCP",
                observed_count=data["count"],
                first_observed=data["first"],
                last_observed=data["last"]
            ))

        return flows

    def _parse_envoy_log_line(self, line: str) -> Optional[NetworkFlow]:
        """Parse a single Envoy log line."""
        try:
            log_data = json.loads(line)

            return NetworkFlow(
                source_namespace=log_data.get("metadata", {}).get("namespace", "default"),
                source_pod=log_data.get("metadata", {}).get("pod", "unknown"),
                source_labels=log_data.get("metadata", {}).get("labels", {}),
                dest_namespace=log_data.get("upstream", {}).get("namespace", "default"),
                dest_pod=log_data.get("upstream", {}).get("pod", "unknown"),
                dest_labels=log_data.get("upstream", {}).get("labels", {}),
                dest_port=log_data.get("upstream", {}).get("port", 80),
                protocol="TCP",
                first_observed=datetime.fromisoformat(
                    log_data.get("timestamp", datetime.now().isoformat())
                ),
                last_observed=datetime.fromisoformat(
                    log_data.get("timestamp", datetime.now().isoformat())
                )
            )

        except json.JSONDecodeError:
            pass

        return None

    def generate_policies_from_services(
        self,
        services: list[ServiceEndpoint],
        default_deny: bool = True
    ) -> list[PolicyTemplate]:
        """Generate network policies from service definitions."""
        policies = []

        for svc in services:
            if not svc.pod_selector:
                continue

            ingress_rules = []

            ingress_rules.append({
                "from": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {"name": svc.namespace}
                        }
                    }
                ],
                "ports": [
                    {
                        "port": p["port"],
                        "protocol": p["protocol"]
                    }
                    for p in svc.ports
                ]
            })

            egress_rules = [
                {
                    "to": [
                        {
                            "podSelector": {
                                "matchLabels": svc.pod_selector
                            }
                        }
                    ],
                    "ports": [
                        {
                            "port": p["port"],
                            "protocol": p["protocol"]
                        }
                        for p in svc.ports
                    ]
                }
            ]

            egress_rules.append({
                "to": [{"namespaceSelector": {}}],
                "ports": [
                    {"port": 53, "protocol": "UDP"},
                    {"port": 53, "protocol": "TCP"}
                ]
            })

            policy_types = ["Ingress"]
            if default_deny:
                policy_types.append("Egress")

            policies.append(PolicyTemplate(
                policy_name=f"allow-{svc.name}-traffic",
                namespace=svc.namespace,
                pod_selector=svc.pod_selector,
                policy_types=policy_types,
                ingress_rules=ingress_rules,
                egress_rules=egress_rules
            ))

        return policies

    def generate_policies_from_flows(
        self,
        flows: list[NetworkFlow],
        namespace: Optional[str] = None
    ) -> list[PolicyTemplate]:
        """Generate network policies based on observed flows."""
        namespace_policies = defaultdict(lambda: {
            "selectors": set(),
            "ingress_rules": [],
            "egress_rules": [],
            "policy_types": ["Ingress", "Egress"]
        })

        for flow in flows:
            ns_key = flow.dest_namespace
            if namespace and ns_key != namespace:
                continue

            policy = namespace_policies[ns_key]

            selector_key = json.dumps(flow.dest_labels, sort_keys=True)
            if selector_key not in policy["selectors"]:
                policy["selectors"].add(selector_key)

                if flow.source_namespace == flow.dest_namespace:
                    ingress_from = [{
                        "podSelector": {
                            "matchLabels": flow.source_labels
                        }
                    }]
                else:
                    ingress_from = [{
                        "namespaceSelector": {
                            "matchLabels": {"name": flow.source_namespace}
                        }
                    }]

                policy["ingress_rules"].append({
                    "from": ingress_from,
                    "ports": [{
                        "port": flow.dest_port,
                        "protocol": flow.protocol.upper()
                    }]
                })

                if flow.source_namespace != flow.dest_namespace:
                    policy["egress_rules"].append({
                        "to": [{
                            "namespaceSelector": {
                                "matchLabels": {"name": flow.source_namespace}
                            }
                        }],
                        "ports": [{
                            "port": flow.dest_port,
                            "protocol": flow.protocol.upper()
                        }]
                    })

        policies = []
        for ns, data in namespace_policies.items():
            merged_selector = {}
            for sel_json in data["selectors"]:
                sel = json.loads(sel_json)
                merged_selector.update(sel)

            policies.append(PolicyTemplate(
                policy_name=f"allow-observed-traffic-{ns}",
                namespace=ns,
                pod_selector=merged_selector,
                policy_types=data["policy_types"],
                ingress_rules=data["ingress_rules"],
                egress_rules=data["egress_rules"]
            ))

        return policies

    def generate_default_deny_policy(
        self,
        namespace: str,
        policy_name: str = "default-deny-all"
    ) -> PolicyTemplate:
        """Generate a default deny-all policy for a namespace."""
        return PolicyTemplate(
            policy_name=policy_name,
            namespace=namespace,
            pod_selector={},
            policy_types=["Ingress", "Egress"],
            ingress_rules=[],
            egress_rules=[]
        )

    def render_policy(self, template: PolicyTemplate) -> dict:
        """Render a policy template to Kubernetes manifest."""
        manifest = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": template.policy_name,
                "namespace": template.namespace,
                "labels": {
                    "generated-by": "netpol-generator",
                    "created": datetime.now().strftime("%Y-%m-%d")
                },
                "annotations": {
                    "description": "Auto-generated network policy"
                }
            },
            "spec": {
                "podSelector": template.pod_selector,
                "policyTypes": template.policy_types
            }
        }

        if template.ingress_rules:
            spec["ingress"] = template.ingress_rules

        if template.egress_rules:
            spec["egress"] = template.egress_rules

        return manifest

    def generate_namespace_set(self, namespaces: list[str]) -> list[PolicyTemplate]:
        """Generate allow policies between specific namespaces."""
        policies = []

        for i, ns1 in enumerate(namespaces):
            for ns2 in namespaces[i+1:]:
                for ns in [ns1, ns2]:
                    egress_rules = [{
                        "to": [{
                            "namespaceSelector": {
                                "matchLabels": {"name": ns2 if ns == ns1 else ns1}
                            }
                        }]
                    }]

                    policies.append(PolicyTemplate(
                        policy_name=f"allow-{ns1}-to-{ns2}" if ns == ns1 else f"allow-{ns2}-to-{ns1}",
                        namespace=ns,
                        pod_selector={},
                        policy_types=["Egress"],
                        ingress_rules=[],
                        egress_rules=egress_rules
                    ))

        return policies

    def generate_mesh_policies(
        self,
        services: list[ServiceEndpoint],
        mesh_mode: str = "sidecar"
    ) -> list[PolicyTemplate]:
        """Generate policies for service mesh environments."""
        policies = []

        for svc in services:
            policy_types = ["Ingress", "Egress"]

            ingress_rules = [{
                "from": [{"namespaceSelector": {}}],
                "ports": [
                    {
                        "port": p["port"],
                        "protocol": p["protocol"]
                    }
                    for p in svc.ports
                ]
            }]

            egress_rules = []

            if mesh_mode == "sidecar":
                egress_rules.append({
                    "to": [{"podSelector": {}}],
                    "ports": svc.ports
                })

            egress_rules.append({
                "to": [{"namespaceSelector": {}}],
                "ports": [{"port": 15021, "protocol": "TCP"}]
            })

            policies.append(PolicyTemplate(
                policy_name=f"mesh-{svc.name}",
                namespace=svc.namespace,
                pod_selector=svc.pod_selector,
                policy_types=policy_types,
                ingress_rules=ingress_rules,
                egress_rules=egress_rules
            ))

        return policies

    def write_policies(
        self,
        policies: list[PolicyTemplate],
        output_dir: Path
    ) -> list[Path]:
        """Write policies to YAML files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        written_files = []

        manifest = {
            "apiVersion": "v1",
            "kind": "List",
            "items": []
        }

        for policy in policies:
            spec = {
                "podSelector": policy.pod_selector,
                "policyTypes": policy.policy_types
            }

            if policy.ingress_rules:
                spec["ingress"] = policy.ingress_rules

            if policy.egress_rules:
                spec["egress"] = policy.egress_rules

            item = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": policy.policy_name,
                    "namespace": policy.namespace,
                    "labels": {
                        "generated-by": "netpol-generator"
                    }
                },
                "spec": spec
            }

            manifest["items"].append(item)

        output_file = output_dir / "network-policies.yaml"
        with open(output_file, "w") as f:
            yaml.dump(manifest, f, default_flow_style=False)

        written_files.append(output_file)

        return written_files


def main():
    parser = argparse.ArgumentParser(
        description="Generate Kubernetes network policies"
    )
    parser.add_argument("--namespace", help="Specific namespace to generate policies for")
    parser.add_argument("--output-dir", type=Path, default=Path("./policies"), help="Output directory")
    parser.add_argument("--mode", choices=["service", "flow", "mesh"], default="service")
    parser.add_argument("--envoy-logs", type=Path, help="Path to Envoy access logs")
    parser.add_argument("--default-deny", action="store_true", help="Include default deny policies")
    parser.add_argument("--namespaces", nargs="+", help="Namespace pairs for cross-namespace policies")

    args = parser.parse_args()

    generator = NetworkPolicyGenerator()

    if args.mode == "service":
        services = generator.discover_services(args.namespace)
        policies = generator.generate_policies_from_services(services, args.default_deny)

        if args.default_deny:
            namespaces = set(s.namespace for s in services)
            for ns in namespaces:
                deny_policy = generator.generate_default_deny_policy(ns)
                policies.append(deny_policy)

    elif args.mode == "flow":
        if not args.envoy_logs:
            logger.error("--envoy-logs required for flow mode")
            return 1

        flows = generator.parse_envoy_access_logs(args.envoy_logs)
        policies = generator.generate_policies_from_flows(flows, args.namespace)

    elif args.mode == "mesh":
        services = generator.discover_services(args.namespace)
        policies = generator.generate_mesh_policies(services)

    else:
        logger.error(f"Unknown mode: {args.mode}")
        return 1

    written = generator.write_policies(policies, args.output_dir)

    logger.info(f"Generated {len(policies)} policies")
    logger.info(f"Written to: {[str(f) for f in written]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())