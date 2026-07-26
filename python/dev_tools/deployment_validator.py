"""
Developer Platform CLI Tools
Internal developer tooling for security and compliance automation.
Makes the secure path the default path.
"""

import json
import sys
import subprocess
import argparse
from pathlib import Path
from typing import Optional
import logging

import click


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@click.group()
def cli():
    """Developer Platform CLI - Security automation tools."""
    pass


@cli.command()
@click.argument("image")
@click.option("--fail-on", default="HIGH", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM"]))
def scan_image(image: str, fail_on: str):
    """Scan container image for vulnerabilities."""
    try:
        result = subprocess.run(
            ["python", "-m", "python_security_toolkit.container_scanner", image, "--severity", "HIGH"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            click.echo(f"❌ Scan failed: {result.stderr}", err=True)
            sys.exit(1)

        data = json.loads(Path("scan-result.json").read_text())

        critical = data["summary"]["critical"]
        high = data["summary"]["high"]

        click.echo(f"\n📊 Scan Results for {image}")
        click.echo(f"   Critical: {critical}")
        click.echo(f"   High: {high}")
        click.echo(f"   Medium: {data['summary']['medium']}")
        click.echo(f"   Low: {data['summary']['low']}")

        threshold = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1}[fail_on]

        if fail_on == "CRITICAL" and critical > threshold:
            click.echo(f"\n❌ Deployment blocked - {critical} critical vulnerabilities")
            sys.exit(1)
        elif fail_on == "HIGH" and critical + high > threshold:
            click.echo(f"\n❌ Deployment blocked - {critical + high} critical/high vulnerabilities")
            sys.exit(1)

        click.echo("\n✅ Image passed security scan")

    except FileNotFoundError:
        click.echo("❌ Scanner not found - ensure dependencies are installed", err=True)
        sys.exit(1)


@cli.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--output", default="policy-check.json", help="Output file")
def validate_iac(directory: str, output: str):
    """Validate infrastructure as code."""
    try:
        result = subprocess.run(
            [
                "python", "-m", "iac_validation.validator",
                directory,
                "--output", output,
                "--fail-on", "HIGH"
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            click.echo("❌ IaC validation failed", err=True)
            click.echo(result.stdout)
            sys.exit(1)

        data = json.loads(Path(output).read_text())

        findings = data["summary"]["critical"] + data["summary"]["high"]

        click.echo(f"\n📋 IaC Validation Results")
        click.echo(f"   Files validated: {data['summary']['files_validated']}")
        click.echo(f"   Critical: {data['summary']['critical']}")
        click.echo(f"   High: {data['summary']['high']}")
        click.echo(f"   Medium: {data['summary']['medium']}")

        if findings > 0:
            click.echo(f"\n❌ Found {findings} security issues")
            for finding in data["findings"][:5]:
                click.echo(f"   - {finding['check_id']}: {finding['check_name']}")
            sys.exit(1)

        click.echo("\n✅ IaC passed security validation")

    except FileNotFoundError:
        click.echo("❌ Validator not found", err=True)
        sys.exit(1)


@cli.command()
@click.argument("workflow")
@click.option("--output", default="pipeline-review.json")
def review_pipeline(workflow: str, output: str):
    """Review GitHub Actions pipeline security."""
    try:
        result = subprocess.run(
            [
                "python", "-m", "ci_cd_security.pipeline_hardener",
                workflow,
                "--report", output
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            click.echo("❌ Pipeline review failed", err=True)
            sys.exit(1)

        data = json.loads(Path(output).read_text())

        click.echo(f"\n🔒 Pipeline Security Review")
        click.echo(f"   Workflows analyzed: {data['summary']['total_workflows']}")
        click.echo(f"   Passed: {data['summary']['passed_workflows']}")
        click.echo(f"   Coverage: {data['summary']['average_coverage']:.1f}%")

        failed = data["summary"]["failed_workflows"]
        if failed > 0:
            click.echo(f"\n⚠️  {failed} workflows need attention")
            for wf in data["workflows"]:
                if not wf["passed"]:
                    click.echo(f"   - {wf['path']}")
            sys.exit(1)

        click.echo("\n✅ All pipelines meet security requirements")

    except FileNotFoundError:
        click.echo("❌ Pipeline hardener not found", err=True)
        sys.exit(1)


@cli.command()
@click.option("--namespace", help="Specific namespace to audit")
@click.option("--output", default="rbac-audit.json")
def audit_rbac(namespace: str, output: str):
    """Audit Kubernetes RBAC configuration."""
    cmd = [
        "python", "-m", "k8s_security.rbac_auditor",
        "--output", output
    ]

    if namespace:
        cmd.extend(["--namespace", namespace])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            click.echo("❌ RBAC audit failed", err=True)
            sys.exit(1)

        data = json.loads(Path(output).read_text())

        click.echo(f"\n🔑 RBAC Audit Results")
        click.echo(f"   Subjects analyzed: {data['summary']['total_subjects']}")
        click.echo(f"   High risk: {data['summary']['high_risk']}")
        click.echo(f"   Medium risk: {data['summary']['medium_risk']}")
        click.echo(f"   Cluster admin bindings: {len(data.get('cluster_admin_bindings', []))}")

        if data["summary"]["high_risk"] > 0:
            click.echo("\n⚠️  High-risk RBAC configurations found")
            for subject in data.get("overprivileged", [])[:5]:
                click.echo(f"   - {subject}")
            sys.exit(1)

        click.echo("\n✅ RBAC configuration meets security standards")

    except FileNotFoundError:
        click.echo("❌ RBAC auditor not found", err=True)
        sys.exit(1)


@cli.command()
@click.option("--namespace", help="Generate policies for namespace")
@click.option("--output-dir", default="./policies", type=click.Path())
def generate_network_policies(namespace: str, output_dir: str):
    """Generate Kubernetes network policies."""
    cmd = [
        "python", "-m", "k8s_security.network_policy_generator",
        "--mode", "service",
        "--output-dir", output_dir
    ]

    if namespace:
        cmd.extend(["--namespace", namespace])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            click.echo("❌ Network policy generation failed", err=True)
            sys.exit(1)

        click.echo(f"\n🌐 Network Policies Generated")
        click.echo(f"   Output directory: {output_dir}")
        click.echo("   Run: kubectl apply -f policies/network-policies.yaml")

    except FileNotFoundError:
        click.echo("❌ Network policy generator not found", err=True)
        sys.exit(1)


@cli.command()
def security_checklist():
    """Display security checklist before deployment."""
    checklist = [
        ("Container Image Scanned", "Run `devtool scan-image <image>`"),
        ("IaC Validated", "Run `devtool validate-iac <directory>`"),
        ("Pipeline Reviewed", "Run `devtool review-pipeline <workflow>`"),
        ("RBAC Audited", "Run `devtool audit-rbac`"),
        ("Secrets Not Exposed", "Check no secrets in code"),
        ("Dependencies Updated", "Run `pip audit`"),
        ("Tests Passing", "CI/CD status green"),
    ]

    click.echo("\n🔐 Pre-Deployment Security Checklist\n")
    for i, (check, command) in enumerate(checklist, 1):
        click.echo(f"  {i}. [ ] {check}")
        click.echo(f"     → {command}\n")


@cli.command()
@click.argument("plan_file", type=click.Path(exists=True))
def remediation_plan(plan_file: str):
    """Display vulnerability remediation plan."""
    data = json.loads(Path(plan_file).read_text())

    click.echo(f"\n📋 Remediation Plan")
    click.echo(f"   Created: {data['created_at']}")
    click.echo(f"   Total Vulnerabilities: {data['total_vulnerabilities']}\n")

    click.echo("   Phased Rollout:")
    for phase in data.get("phased_rollout", []):
        click.echo(f"   Phase {phase['phase']}: {phase['name']}")
        click.echo(f"      Actions: {phase['actions']}")
        click.echo(f"      Time: {phase['estimated_time']}\n")


if __name__ == "__main__":
    cli()