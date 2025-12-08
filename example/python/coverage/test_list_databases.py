# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Test database listing endpoints (direct access APIs).

Tests:
- GET /api/v1/hosts/{host_id}/databases (list databases)
- GET /api/v1/hosts/{host_id}/databases/{db_id} (get single database)

Lists databases on a host, then retrieves a specific database by ID.
"""

import sys
import os
import argparse

# Add parent directory to path to import common
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import (
    _ensure_env,
    _make_request,
    exit_with_error,
)


def run(host_name: str):
    """Test database listing endpoints (direct access APIs).

    Args:
        host_name: Host name/ID to list databases from
    """
    _ensure_env()

    print(f"Testing database listing endpoints (direct access APIs)")
    print(f"  Host: {host_name}")

    try:
        # Test list databases endpoint
        print(f"\n1. Testing GET /api/v1/hosts/{host_name}/databases")
        databases = _make_request("GET", f"/api/v1/hosts/{host_name}/databases")

        if not isinstance(databases, list):
            exit_with_error("Databases response is not a list.")

        print(f"   ✓ Listed {len(databases)} databases")

        if len(databases) == 0:
            print("   ⚠ No databases found on host, skipping single database test")
            print("\n✓ Database listing test passed (no databases to test individually).")
            return 0

        # Print database names
        for db in databases:
            print(f"     - {db['name']} (id: {db['id']}, vendor: {db['vendor']})")

        # Test get single database endpoint
        first_db = databases[0]
        db_id = first_db["id"]
        db_name = first_db["name"]

        print(f"\n2. Testing GET /api/v1/hosts/{host_name}/databases/{db_id}")
        single_db = _make_request("GET", f"/api/v1/hosts/{host_name}/databases/{db_id}")

        # Verify response structure
        required_fields = ["id", "host_id", "name", "vendor", "mssql", "mount_points"]
        missing_fields = [f for f in required_fields if f not in single_db]
        if missing_fields:
            exit_with_error(f"Database response missing fields: {missing_fields}")

        if single_db["id"] != db_id:
            exit_with_error(f"Database ID mismatch: expected {db_id}, got {single_db['id']}")

        if single_db["name"] != db_name:
            exit_with_error(f"Database name mismatch: expected {db_name}, got {single_db['name']}")

        print(f"   ✓ Retrieved database: {single_db['name']}")
        print(f"     - ID: {single_db['id']}")
        print(f"     - Vendor: {single_db['vendor']}")
        print(f"     - Status: {single_db.get('status', 'N/A')}")
        print(f"     - Files: {len(single_db['mssql']['files'])}")
        print(f"     - Mount points: {len(single_db['mount_points'])}")

        print("\n✓ Database listing test passed.")
        return 0

    except Exception as e:
        exit_with_error(f"Database listing test failed: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test database listing endpoints (direct access APIs)")
    parser.add_argument("--host-name", required=True, help="Host name/ID to list databases from")

    args = parser.parse_args()
    sys.exit(run(host_name=args.host_name))
