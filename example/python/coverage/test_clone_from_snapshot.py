# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Test clone from snapshot endpoints (direct access APIs).

Tests:
- POST /api/echo/v1/db_snapshots (create snapshot)
- POST /api/echo/v1/db_snapshots/{id}/echo_db/__validate (validation)
- POST /api/echo/v1/db_snapshots/{id}/echo_db (public endpoint)
- DELETE /api/echo/v1/echo_dbs (cleanup)

Creates a snapshot, clones from it, validates, then cleans up.
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
    _wait_validation_pass,
    exit_with_error,
)


def run(
    source_host_name: str,
    dest_host_name: str,
    db_name: str,
    snapshot_prefix: str = "test_clone",
    echo_db_suffix: str = "_clone",
    consistency_level: str = "crash",
    timeout: int = 300,
):
    """Test clone from snapshot endpoints (direct access APIs).

    Args:
        source_host_name: Source host name/ID
        dest_host_name: Destination host name/ID
        db_name: Database name to snapshot and clone
        snapshot_prefix: Prefix for snapshot name (default: "test-clone-v2-")
        echo_db_suffix: Suffix for cloned echo DB name (default: "-clone-v2")
        consistency_level: Consistency level - "crash" or "application" (default: "crash")
        timeout: Task timeout in seconds (default: 300)
    """
    _ensure_env()

    if consistency_level not in ["crash", "application"]:
        exit_with_error("Consistency level must be 'crash' or 'application'.")

    print(f"Testing clone from snapshot endpoints (direct access APIs)")
    print(f"  Source host: {source_host_name}")
    print(f"  Destination host: {dest_host_name}")
    print(f"  Database: {db_name}")

    # Get topology for both hosts
    source_topology = _get_host_topology(source_host_name)
    dest_topology = _get_host_topology(dest_host_name)

    source_host_id = source_topology["host"]["id"]
    dest_host_id = dest_topology["host"]["id"]

    # Find database ID
    db_id = None
    for db in source_topology["databases"]:
        if db["name"] == db_name:
            db_id = db["id"]
            break

    if not db_id:
        exit_with_error(f"Database '{db_name}' not found on source host.")

    snapshot_id = None
    echo_db_name = db_name + echo_db_suffix

    try:
        # Create snapshot first (using direct endpoint)
        print("\n1. Creating snapshot")
        create_snapshot_payload = {
            "source_host_id": source_host_id,
            "database_ids": [db_id],
            "name_prefix": snapshot_prefix,
            "consistency_level": consistency_level,
        }

        create_task = _make_request("POST", "/api/echo/v1/db_snapshots", payload=create_snapshot_payload)
        success, completed_task = _wait_for_task(create_task, timeout=timeout)

        if not success:
            exit_with_error(f"Failed to create snapshot: {completed_task.get('error', 'Unknown error')}")

        snapshot_id = completed_task["result"]["db_snapshot"]["id"]
        print(f"   ✓ Snapshot created: {snapshot_id}")

        # Prepare clone payload
        clone_payload = {
            "destinations": [
                {
                    "host_id": dest_host_id,
                    "db_id": db_id,
                    "db_name": echo_db_name,
                }
            ],
        }

        # Test validation endpoint
        print("\n2. Testing POST /api/echo/v1/db_snapshots/{id}/echo_db/__validate")
        validate_response = _make_request(
            "POST",
            f"/api/echo/v1/db_snapshots/{snapshot_id}/echo_db/__validate",
            payload=clone_payload
        )
        print("   ✓ Validation passed")

        # Test direct endpoint
        print("\n3. Testing POST /api/echo/v1/db_snapshots/{id}/echo_db")
        clone_task = _make_request("POST", f"/api/echo/v1/db_snapshots/{snapshot_id}/echo_db", payload=clone_payload)
        success2, completed_clone_task = _wait_for_task(clone_task, timeout=timeout)

        if not success2:
            exit_with_error(f"Direct endpoint clone failed: {completed_clone_task.get('error', 'Unknown error')}")

        print(f"   ✓ Echo DB created: {echo_db_name}")

        # Cleanup: delete echo DB and snapshot
        print("\n3. Cleaning up")

        # Get database ID from destination host
        dest_topology_after = _get_host_topology(dest_host_name)
        echo_db_id = None

        for db in dest_topology_after["databases"]:
            if db["name"] == echo_db_name:
                echo_db_id = db["id"]
                break

        if echo_db_id:
            try:
                delete_payload = {"host_id": dest_host_id, "database_id": echo_db_id}
                delete_task = _make_request("DELETE", "/api/echo/v1/echo_dbs", payload=delete_payload)
                _wait_for_task(delete_task, timeout=timeout)
                print(f"   ✓ Deleted echo DB: {echo_db_name}")
            except Exception as e:
                print(f"   ✗ Failed to delete echo DB {echo_db_name}: {e}")

        if snapshot_id:
            try:
                _wait_validation_pass("DELETE", f"/api/echo/v1/db_snapshots/{snapshot_id}/__validate", ignore_status_codes=[404])
                delete_snapshot_task = _make_request("DELETE", f"/api/echo/v1/db_snapshots/{snapshot_id}")
                _wait_for_task(delete_snapshot_task, timeout=timeout)
                print(f"   ✓ Deleted snapshot: {snapshot_id}")
            except Exception as e:
                print(f"   ✗ Failed to delete snapshot {snapshot_id}: {e}")

        print("\n✓ Clone from snapshot test passed.")
        return 0

    except Exception as e:
        # Try to cleanup on error
        if snapshot_id:
            try:
                _wait_validation_pass("DELETE", f"/api/echo/v1/db_snapshots/{snapshot_id}/__validate", ignore_status_codes=[404])
                _make_request("DELETE", f"/api/echo/v1/db_snapshots/{snapshot_id}")
            except:
                pass
        exit_with_error(f"Clone from snapshot test failed: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test clone from snapshot endpoints (direct access APIs)")
    parser.add_argument("--source-host-name", required=True, help="Source host name/ID")
    parser.add_argument("--dest-host-name", required=True, help="Destination host name/ID")
    parser.add_argument("--db-name", required=True, help="Database name to snapshot and clone")
    parser.add_argument("--snapshot-prefix", default="test_clone", help="Prefix for snapshot name (default: 'test_clone')")
    parser.add_argument("--echo-db-suffix", default="_clone", help="Suffix for cloned echo DB name (default: '_clone')")
    parser.add_argument("--consistency-level", default="crash", choices=["crash", "application"], help="Consistency level (default: 'crash')")
    parser.add_argument("--timeout", type=int, default=300, help="Task timeout in seconds (default: 300)")

    args = parser.parse_args()
    sys.exit(run(
        source_host_name=args.source_host_name,
        dest_host_name=args.dest_host_name,
        db_name=args.db_name,
        snapshot_prefix=args.snapshot_prefix,
        echo_db_suffix=args.echo_db_suffix,
        consistency_level=args.consistency_level,
        timeout=args.timeout,
    ))
