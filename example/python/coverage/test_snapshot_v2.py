# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Test snapshot creation and deletion endpoints.

Tests:
- POST /api/ocie/v1/db_snapshots/__validate (validation)
- POST /api/ocie/v1/db_snapshots (create snapshot)
- DELETE /api/ocie/v1/db_snapshots/{id} (delete snapshot)

Creates a snapshot, validates it exists, then deletes it.
"""

import sys
import os
import argparse

# Add parent directory to path to import common
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import (
    _ensure_env,
    _make_request,
    _wait_for_task,
    _get_host_topology,
    exit_with_error,
)


def run(
    host_name: str,
    db_name: str,
    snapshot_prefix: str = "test-",
    consistency_level: str = "crash",
    timeout: int = 300,
):
    """Test snapshot creation and deletion endpoints.

    Args:
        host_name: Host name/ID to create snapshot from
        db_name: Database name to snapshot
        snapshot_prefix: Prefix for snapshot name (default: "test-")
        consistency_level: Consistency level - "crash" or "application" (default: "crash")
        timeout: Task timeout in seconds (default: 300)
    """
    _ensure_env()

    if consistency_level not in ["crash", "application"]:
        exit_with_error("Consistency level must be 'crash' or 'application'.")

    print(f"Testing snapshot creation and deletion endpoints")
    print(f"  Host: {host_name}")
    print(f"  Database: {db_name}")
    print(f"  Consistency level: {consistency_level}")

    # Get topology to find host and database IDs
    host_topology = _get_host_topology(host_name)
    actual_host_id = host_topology["host"]["id"]

    # Find database ID
    database_ids = []
    for db in host_topology["databases"]:
        if db["name"] == db_name:
            database_ids = [db["id"]]
            break

    if not database_ids:
        exit_with_error(f"Database '{db_name}' not found on host.")

    snapshot_id = None

    try:
        # Prepare payload
        payload = {
            "source_host_id": actual_host_id,
            "database_ids": database_ids,
            "name_prefix": snapshot_prefix,
            "consistency_level": consistency_level,
        }

        # Test validation endpoint for creation
        print("\n1. Testing POST /api/ocie/v1/db_snapshots/__validate")
        validate_response = _make_request(
            "POST",
            "/api/ocie/v1/db_snapshots/__validate",
            payload=payload
        )
        print("   ✓ Validation passed")

        # Test create snapshot endpoint
        print("\n2. Testing POST /api/ocie/v1/db_snapshots")
        task = _make_request("POST", "/api/ocie/v1/db_snapshots", payload=payload)
        success, completed_task = _wait_for_task(task, timeout=timeout)

        if not success:
            exit_with_error(f"Snapshot creation failed: {completed_task.get('error', 'Unknown error')}")

        snapshot_id = completed_task["result"]["db_snapshot"]["id"]
        print(f"   ✓ Snapshot created: {snapshot_id}")

        # Test delete snapshot endpoint
        print("\n3. Testing DELETE /api/ocie/v1/db_snapshots/{id}")
        delete_task = _make_request("DELETE", f"/api/ocie/v1/db_snapshots/{snapshot_id}")
        success2, completed_delete_task = _wait_for_task(delete_task, timeout=timeout)

        if not success2:
            exit_with_error(f"Snapshot deletion failed: {completed_delete_task.get('error', 'Unknown error')}")

        print(f"   ✓ Snapshot deleted")

        print("\n✓ Snapshot creation and deletion test passed.")
        return 0

    except Exception as e:
        # Try to cleanup on error
        if snapshot_id:
            try:
                delete_task = _make_request("DELETE", f"/api/ocie/v1/db_snapshots/{snapshot_id}")
                _wait_for_task(delete_task, timeout=timeout)
            except:
                pass
        exit_with_error(f"Snapshot test failed: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test snapshot creation and deletion endpoints")
    parser.add_argument("--host-name", required=True, help="Host name/ID to create snapshot from")
    parser.add_argument("--db-name", required=True, help="Database name to snapshot")
    parser.add_argument("--snapshot-prefix", default="test-", help="Prefix for snapshot name (default: 'test-')")
    parser.add_argument("--consistency-level", default="crash", choices=["crash", "application"], help="Consistency level (default: 'crash')")
    parser.add_argument("--timeout", type=int, default=300, help="Task timeout in seconds (default: 300)")

    args = parser.parse_args()
    sys.exit(run(
        host_name=args.host_name,
        db_name=args.db_name,
        snapshot_prefix=args.snapshot_prefix,
        consistency_level=args.consistency_level,
        timeout=args.timeout,
    ))
