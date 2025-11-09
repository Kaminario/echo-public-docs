# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Test task listing endpoints (rewritten URLs).

Tests:
- GET /flex/api/v1/ocie/tasks (rewritten endpoint)

Creates a task (via snapshot creation), then lists tasks.
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
    snapshot_prefix: str = "test-list-v2-",
    consistency_level: str = "crash",
    timeout: int = 300,
):
    """Test task listing endpoints (rewritten URLs).

    Args:
        host_name: Host name/ID to create snapshot from (creates task)
        db_name: Database name to snapshot
        snapshot_prefix: Prefix for snapshot name (default: "test-list-v2-")
        consistency_level: Consistency level - "crash" or "application" (default: "crash")
        timeout: Task timeout in seconds (default: 300)
    """
    _ensure_env()

    if consistency_level not in ["crash", "application"]:
        exit_with_error("Consistency level must be 'crash' or 'application'.")

    print(f"Testing task listing endpoints (rewritten URLs)")
    print(f"  Host: {host_name}")
    print(f"  Database: {db_name}")

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
        # Create a snapshot to generate a task (using rewritten endpoint)
        print("\n1. Creating snapshot to generate task")
        create_payload = {
            "source_host_id": actual_host_id,
            "database_ids": database_ids,
            "name_prefix": snapshot_prefix,
            "consistency_level": consistency_level,
        }

        task = _make_request("POST", "/flex/api/v1/db_snapshots", payload=create_payload)
        request_id = task.get("request_id")

        if not request_id:
            exit_with_error("Task missing 'request_id' field.")

        print(f"   ✓ Task created: {request_id}")

        # Test rewritten endpoint
        print("\n2. Testing GET /flex/api/v1/ocie/tasks")
        tasks_list = _make_request("GET", "/flex/api/v1/ocie/tasks")

        if not isinstance(tasks_list, list):
            exit_with_error("Tasks list response is not a list.")

        # Find our task in the list
        found_task = None
        for t in tasks_list:
            if t.get("request_id") == request_id:
                found_task = t
                break

        if not found_task:
            exit_with_error(f"Task {request_id} not found in tasks list.")

        print(f"   ✓ Task found in list ({len(tasks_list)} total tasks)")

        # Wait for task completion and cleanup
        print("\n3. Waiting for task completion and cleaning up")
        success, completed_task = _wait_for_task(task, timeout=timeout)

        if not success:
            exit_with_error(f"Snapshot creation task failed: {completed_task.get('error', 'Unknown error')}")

        snapshot_id = completed_task["result"]["db_snapshot"]["id"]

        # Delete snapshot (using rewritten endpoint)
        delete_task = _make_request("DELETE", f"/flex/api/v1/db_snapshots/{snapshot_id}")
        _wait_for_task(delete_task, timeout=timeout)
        print(f"   ✓ Cleanup completed")

        print("\n✓ Task listing test passed.")
        return 0

    except Exception as e:
        # Try to cleanup on error
        if snapshot_id:
            try:
                _make_request("DELETE", f"/flex/api/v1/db_snapshots/{snapshot_id}")
            except:
                pass
        exit_with_error(f"Task listing test failed: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test task listing endpoints (rewritten URLs)")
    parser.add_argument("--host-name", required=True, help="Host name/ID to create snapshot from (creates task)")
    parser.add_argument("--db-name", required=True, help="Database name to snapshot")
    parser.add_argument("--snapshot-prefix", default="test-list-v2-", help="Prefix for snapshot name (default: 'test-list-v2-')")
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
