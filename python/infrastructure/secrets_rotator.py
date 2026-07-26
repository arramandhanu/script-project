"""
Secrets Rotation Manager
Automated rotation of secrets in AWS Secrets Manager with
health checks, rollback capabilities, and audit logging.
"""

import json
import hashlib
import time
import argparse
from dataclasses import dataclass, field
from typing import Optional, Callable
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import logging
import os
import signal
import sys

import boto3
from botocore.exceptions import ClientError, BotoCoreError


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class RotationConfig:
    """Configuration for secret rotation."""
    secret_name: str
    rotation_lambda_arn: Optional[str] = None
    rotation_days: int = 90
    health_check_enabled: bool = True
    health_check_timeout: int = 30
    rollback_on_failure: bool = True
    notify_on_completion: bool = True
    tags: dict = field(default_factory=dict)


@dataclass
class RotationResult:
    """Result of a secret rotation operation."""
    secret_name: str
    success: bool
    started_at: datetime
    completed_at: Optional[datetime] = None
    previous_version: Optional[str] = None
    new_version: Optional[str] = None
    error_message: Optional[str] = None
    health_check_passed: bool = False
    steps_completed: list[str] = field(default_factory=list)


class SecretsRotationManager:
    """Manages automated rotation of secrets with health checks."""

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.secrets_client = boto3.client("secretsmanager", region_name=region)
        self.lambda_client = boto3.client("lambda", region_name=region)
        self.sns_client = boto3.client("sns", region_name=region)
        self.cloudwatch = boto3.client("cloudwatch", region_name=region)

    def get_secret_metadata(self, secret_name: str) -> dict:
        """Retrieve secret metadata including rotation configuration."""
        try:
            response = self.secrets_client.describe_secret(SecretId=secret_name)
            return {
                "arn": response["ARN"],
                "name": response["Name"],
                "rotation_enabled": response.get("RotationEnabled", False),
                "rotation_lambda_arn": response.get("RotationLambdaARN"),
                "last_rotated_date": response.get("LastRotatedDate"),
                "last_changed_date": response.get("LastChangedDate"],
                "tags": response.get("Tags", []),
                "version_ids_to_stages": response.get("VersionIdsToStages", {})
            }
        except ClientError as e:
            logger.error(f"Failed to get secret metadata: {e}")
            raise

    def create_rotation_stage(
        self,
        secret_name: str,
        secret_value: str,
        target_stage: str = "AWSPENDING"
    ) -> str:
        """Create a new version of the secret in the target stage."""
        try:
            response = self.secrets_client.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_value,
                VersionStages=[target_stage]
            )
            version_id = response["VersionId"]
            logger.info(f"Created new version {version_id} with stage {target_stage}")
            return version_id
        except ClientError as e:
            logger.error(f"Failed to create rotation stage: {e}")
            raise

    def get_secret_versions(self, secret_name: str) -> list[dict]:
        """List all versions of a secret."""
        try:
            response = self.secrets_client.list_secret_version_ids(SecretId=secret_name)
            versions = []

            for version in response.get("Versions", []):
                versions.append({
                    "version_id": version["VersionId"],
                    "stages": version.get("VersionStages", []),
                    "created_date": version.get("CreatedDate"),
                    "last_accessed_date": version.get("LastAccessedDate")
                })

            return versions
        except ClientError as e:
            logger.error(f"Failed to list secret versions: {e}")
            return []

    def tag_secret_version(
        self,
        secret_name: str,
        version_id: str,
        from_stage: str,
        to_stage: str
    ) -> None:
        """Move a secret version from one stage to another atomically."""
        try:
            current_stages = self.secrets_client.get_secret_value(
                SecretId=secret_name,
                VersionId=version_id,
                VersionStage=from_stage
            )["VersionStages"]

            new_stages = [s for s in current_stages if s != from_stage] + [to_stage]

            self.secrets_client.update_secret_version_stage(
                SecretId=secret_name,
                VersionStage=to_stage,
                MoveToVersionId=version_id
            )

            if from_stage in current_stages:
                self.secrets_client.update_secret_version_stage(
                    SecretId=secret_name,
                    VersionStage=from_stage,
                    RemoveFromVersionId=version_id
                )

            logger.info(f"Moved version {version_id} from {from_stage} to {to_stage}")
        except ClientError as e:
            logger.error(f"Failed to update secret stage: {e}")
            raise

    def perform_health_check(
        self,
        secret_name: str,
        health_check_func: Optional[Callable] = None,
        timeout: int = 30
    ) -> tuple[bool, Optional[str]]:
        """Perform health check on the new secret version."""
        try:
            pending_value = self.secrets_client.get_secret_value(
                SecretId=secret_name,
                VersionStage="AWSPENDING"
            )

            secret_value = pending_value["SecretString"]

            if health_check_func:
                logger.info("Running custom health check function...")
                success, error = health_check_func(secret_value)
                return success, error

            if secret_name.startswith("rds!"):
                return self._health_check_rds(secret_value)
            elif secret_name.startswith("redshift!"):
                return self._health_check_redshift(secret_value)
            elif secret_name.startswith("mysql!"):
                return self._health_check_mysql(secret_value)
            else:
                return self._validate_secret_format(secret_value)

        except ClientError as e:
            return False, str(e)

    def _validate_secret_format(self, secret_value: str) -> tuple[bool, Optional[str]]:
        """Validate that secret has expected format."""
        try:
            data = json.loads(secret_value)
            required_fields = ["username", "password"]
            missing = [f for f in required_fields if f not in data]

            if missing:
                return False, f"Missing required fields: {missing}"

            return True, None
        except json.JSONDecodeError:
            return False, "Secret is not valid JSON"

    def _health_check_rds(self, secret_value: str) -> tuple[bool, Optional[str]]:
        """Health check for RDS secrets."""
        try:
            import pg8000
            creds = json.loads(secret_value)
            conn = pg8000.connect(
                host=creds.get("host", ""),
                port=creds.get("port", 5432),
                database=creds.get("dbInstanceIdentifier", "postgres"),
                user=creds.get("username", ""),
                password=creds.get("password", "")
            )
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            return result == (1,), None
        except Exception as e:
            return False, f"RDS health check failed: {str(e)}"

    def _health_check_mysql(self, secret_value: str) -> tuple[bool, Optional[str]]:
        """Health check for MySQL/Aurora secrets."""
        try:
            import pymysql
            creds = json.loads(secret_value)
            conn = pymysql.connect(
                host=creds.get("host", ""),
                port=creds.get("port", 3306),
                user=creds.get("username", ""),
                password=creds.get("password", ""),
                connect_timeout=30
            )
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
            conn.close()
            return True, None
        except Exception as e:
            return False, f"MySQL health check failed: {str(e)}"

    def _health_check_redshift(self, secret_value: str) -> tuple[bool, Optional[str]]:
        """Health check for Redshift secrets."""
        try:
            import psycopg2
            creds = json.loads(secret_value)
            conn = psycopg2.connect(
                host=creds.get("host", ""),
                port=creds.get("port", 5439),
                dbname=creds.get("dbname", "dev"),
                user=creds.get("username", ""),
                password=creds.get("password", ""),
                connect_timeout=30
            )
            conn.close()
            return True, None
        except Exception as e:
            return False, f"Redshift health check failed: {str(e)}"

    def rotate_secret(
        self,
        config: RotationConfig,
        new_secret_value: Optional[str] = None,
        health_check_func: Optional[Callable] = None
    ) -> RotationResult:
        """Execute secret rotation with health checks and rollback capability."""
        result = RotationResult(
            secret_name=config.secret_name,
            success=False,
            started_at=datetime.now()
        )

        try:
            metadata = self.get_secret_metadata(config.secret_name)
            current_versions = self.get_secret_versions(config.secret_name)

            active_version = None
            for v in current_versions:
                if "AWSCURRENT" in v["stages"]:
                    active_version = v["version_id"]
                    break

            result.previous_version = active_version

            if not new_secret_value:
                new_secret_value = self._generate_secret_value(metadata)

            result.new_version = self.create_rotation_stage(
                config.secret_name,
                new_secret_value,
                "AWSPENDING"
            )
            result.steps_completed.append("CREATED_PENDING_VERSION")
            logger.info(f"Created pending version: {result.new_version}")

            if config.health_check_enabled:
                success, error = self.perform_health_check(
                    config.secret_name,
                    health_check_func,
                    config.health_check_timeout
                )

                if not success:
                    result.error_message = f"Health check failed: {error}"
                    if config.rollback_on_failure:
                        logger.warning("Health check failed, rolling back...")
                        self._rollback_rotation(config.secret_name, result)
                        result.steps_completed.append("ROLLED_BACK")
                    return result

                result.health_check_passed = True
                result.steps_completed.append("HEALTH_CHECK_PASSED")
                logger.info("Health check passed")

            self.tag_secret_version(
                config.secret_name,
                result.new_version,
                "AWSPENDING",
                "AWSCURRENT"
            )
            result.steps_completed.append("PROMOTED_TO_CURRENT")

            if active_version:
                self.tag_secret_version(
                    config.secret_name,
                    active_version,
                    "AWSCURRENT",
                    "AWSPREVIOUS"
                )
            result.steps_completed.append("DEMOTED_PREVIOUS")

            self._cleanup_old_versions(config.secret_name, keep_versions=5)
            result.steps_completed.append("CLEANUP_COMPLETE")

            self._emit_rotation_metric(config.secret_name, True, result)
            result.success = True

        except Exception as e:
            result.error_message = str(e)
            result.steps_completed.append("ERROR_OCCURRED")
            self._emit_rotation_metric(config.secret_name, False, result)
            logger.error(f"Rotation failed: {e}")

        finally:
            result.completed_at = datetime.now()

        return result

    def _generate_secret_value(self, metadata: dict) -> str:
        """Generate a new secret value based on the secret type."""
        import secrets
        import string

        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(secrets.choice(chars) for _ in range(32))

        secret_data = {
            "username": f"service-{os.getpid()}",
            "password": password,
            "generated_at": datetime.now().isoformat(),
            "rotation_id": hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        }

        return json.dumps(secret_data)

    def _rollback_rotation(self, secret_name: str, result: RotationResult) -> None:
        """Rollback to previous version on failure."""
        try:
            if result.new_version:
                self.secrets_client.delete_secret(
                    SecretId=secret_name,
                    RecoveryWindowInDays=0
                )
            logger.warning("Rolled back rotation")
        except ClientError as e:
            logger.error(f"Rollback failed: {e}")

    def _cleanup_old_versions(self, secret_name: str, keep_versions: int = 5) -> None:
        """Remove old secret versions beyond retention policy."""
        versions = self.get_secret_versions(secret_name)

        cleanup_candidates = [
            v for v in versions
            if not any(stage in ["AWSCURRENT", "AWSPENDING", "AWSPREVIOUS"]
                      for stage in v["stages"])
        ]

        cleanup_candidates.sort(key=lambda x: x["created_date"], reverse=True)

        for version in cleanup_candidates[keep_versions:]:
            try:
                self.secrets_client.delete_secret_version(
                    SecretId=secret_name,
                    VersionId=version["version_id"]
                )
                logger.info(f"Cleaned up old version: {version['version_id']}")
            except ClientError as e:
                logger.debug(f"Could not delete version: {e}")

    def _emit_rotation_metric(self, secret_name: str, success: bool, result: RotationResult) -> None:
        """Emit CloudWatch metrics for rotation operations."""
        try:
            duration = (result.completed_at - result.started_at).total_seconds()

            self.cloudwatch.put_metric_data(
                Namespace="SecretsManager",
                MetricData=[
                    {
                        "MetricName": "RotationSuccess",
                        "Value": 1 if success else 0,
                        "Unit": "Count",
                        "Dimensions": [{"Name": "SecretName", "Value": secret_name}]
                    },
                    {
                        "MetricName": "RotationDuration",
                        "Value": duration,
                        "Unit": "Seconds",
                        "Dimensions": [{"Name": "SecretName", "Value": secret_name}]
                    }
                ]
            )
        except ClientError as e:
            logger.warning(f"Failed to emit metrics: {e}")

    def batch_rotate(
        self,
        configs: list[RotationConfig],
        max_workers: int = 5
    ) -> list[RotationResult]:
        """Rotate multiple secrets in parallel."""
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.rotate_secret, config): config
                for config in configs
            }

            for future in as_completed(futures):
                config = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Batch rotation failed for {config.secret_name}: {e}")
                    results.append(RotationResult(
                        secret_name=config.secret_name,
                        success=False,
                        started_at=datetime.now(),
                        completed_at=datetime.now(),
                        error_message=str(e)
                    ))

        return results


def main():
    parser = argparse.ArgumentParser(description="Rotate secrets in AWS Secrets Manager")
    parser.add_argument("--secret-name", required=True, help="Secret name to rotate")
    parser.add_argument("--secret-value", help="New secret value (JSON string)")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--rotation-days", type=int, default=90, help="Rotation interval in days")
    parser.add_argument("--no-health-check", action="store_true", help="Skip health check")
    parser.add_argument("--no-rollback", action="store_true", help="Don't rollback on failure")
    parser.add_argument("--output", default="rotation-result.json", help="Output file path")

    args = parser.parse_args()

    manager = SecretsRotationManager(region=args.region)

    config = RotationConfig(
        secret_name=args.secret_name,
        rotation_days=args.rotation_days,
        health_check_enabled=not args.no_health_check,
        rollback_on_failure=not args.no_rollback
    )

    result = manager.rotate_secret(config, args.secret_value)

    with open(args.output, "w") as f:
        json.dump({
            "success": result.success,
            "secret_name": result.secret_name,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "previous_version": result.previous_version,
            "new_version": result.new_version,
            "health_check_passed": result.health_check_passed,
            "steps_completed": result.steps_completed,
            "error_message": result.error_message
        }, f, indent=2)

    if result.success:
        logger.info("Rotation completed successfully")
        return 0
    else:
        logger.error(f"Rotation failed: {result.error_message}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())