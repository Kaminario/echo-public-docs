# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Test echo DB clone endpoints (public API).

Tests:
- POST /flex/api/v1/ocie/clone/__validate (validation)
- POST /flex/api/v1/ocie/clone (public endpoint - creates snapshot + echo DB)
- DELETE /flex/api/v1/ocie/clone (delete echo DB)
- DELETE /flex/api/v1/db_snapshots/{id} (delete snapshot)

Creates an echo DB from source (which also creates a snapshot), validates it exists, then cleans up both.
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
    source_host_name: str,
    dest_host_name: str,
    db_name: str,
    echo_db_suffix: str = "-test-v2",
    consistency_level: str = "crash",
    timeout: int = 300,
):
    """Test echo DB clone endpoints (rewritten URLs).

    Args:
        source_host_name: Source host name/ID
        dest_host_name: Destination host name/ID
        db_name: Database name to clone
        echo_db_suffix: Suffix for cloned echo DB name (default: "-test-v2")
        consistency_level: Consistency level - "crash" or "application" (default: "crash")
        timeout: Task timeout in seconds (default: 300)
    """
    _ensure_env()

    if consistency_level not in ["crash", "application"]:
        exit_with_error("Consistency level must be 'crash' or 'application'.")

    print(f"Testing echo DB clone endpoints (rewritten URLs)")
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

    echo_db_name = db_name + echo_db_suffix

    try:
        # Prepare payload
        payload = {
            "source_host_id": source_host_id,
            "destinations": [
                {
                    "host_id": dest_host_id,
                    "db_id": db_id,
                    "db_name": echo_db_name,
                }
            ],
            "consistency_level": consistency_level,
        }

        # Test validation endpoint
        print("\n1. Testing POST /flex/api/v1/ocie/clone/__validate")
        validate_response = _make_request("POST", "/flex/api/v1/ocie/clone/__validate", payload=payload)
        print("   ✓ Validation passed")

        # Test rewritten endpoint
        print("\n2. Testing POST /flex/api/v1/ocie/clone")
        task = _make_request("POST", "/flex/api/v1/ocie/clone", payload=payload)
        success, completed_task = _wait_for_task(task, timeout=timeout)

        if not success:
            exit_with_error(f"Direct endpoint clone failed: {completed_task.get('error', 'Unknown error')}")

        # Extract snapshot ID created by clone operation
        snapshot_id = completed_task.get("result", {}).get("db_snapshot", {}).get("id")
        print(f"   ✓ Echo DB created: {echo_db_name}")
        if snapshot_id:
            print(f"   ✓ Snapshot created: {snapshot_id}")

        # Cleanup: delete echo DB and snapshot
        print("\n3. Cleaning up created echo DB and snapshot")

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
                delete_task = _make_request("DELETE", "/flex/api/v1/ocie/clone", payload=delete_payload)
                _wait_for_task(delete_task, timeout=timeout)
                print(f"   ✓ Deleted echo DB: {echo_db_name}")
            except Exception as e:
                print(f"   ✗ Failed to delete echo DB {echo_db_name}: {e}")

        # Delete the snapshot created by clone operation
        if snapshot_id:
            try:
                delete_snapshot_task = _make_request("DELETE", f"/flex/api/v1/db_snapshots/{snapshot_id}")
                _wait_for_task(delete_snapshot_task, timeout=timeout)
                print(f"   ✓ Deleted snapshot: {snapshot_id}")
            except Exception as e:
                print(f"   ✗ Failed to delete snapshot {snapshot_id}: {e}")

        print("\n✓ Echo DB clone test passed.")
        return 0

    except Exception as e:
        # Try to cleanup on error
        if snapshot_id:
            try:
                _make_request("DELETE", f"/flex/api/v1/db_snapshots/{snapshot_id}")
            except:
                pass
        exit_with_error(f"Echo DB clone test failed: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test echo DB clone endpoints (rewritten URLs)")
    parser.add_argument("--source-host-name", required=True, help="Source host name/ID")
    parser.add_argument("--dest-host-name", required=True, help="Destination host name/ID")
    parser.add_argument("--db-name", required=True, help="Database name to clone")
    parser.add_argument("--echo-db-suffix", default="-test-v2", help="Suffix for cloned echo DB name (default: '-test-v2')")
    parser.add_argument("--consistency-level", default="crash", choices=["crash", "application"], help="Consistency level (default: 'crash')")
    parser.add_argument("--timeout", type=int, default=300, help="Task timeout in seconds (default: 300)")

    args = parser.parse_args()
    sys.exit(run(
        source_host_name=args.source_host_name,
        dest_host_name=args.dest_host_name,
        db_name=args.db_name,
        echo_db_suffix=args.echo_db_suffix,
        consistency_level=args.consistency_level,
        timeout=args.timeout,
    ))
