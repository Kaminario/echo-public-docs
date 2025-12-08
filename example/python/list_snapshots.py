# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import time
import random
import sys
from collections import defaultdict
from optparse import OptionParser

import requests

requests.packages.urllib3.disable_warnings()

# Environment Variables
FLEX_TOKEN = os.getenv("FLEX_TOKEN", "")
FLEX_IP = os.getenv("FLEX_IP", "")

############################################
# Helper Functions
############################################


def exit_with_error(msg: str, **kwargs):
    # print to stderr to avoid mixing with stdout
    print(msg, file=sys.stderr, **kwargs)
    sys.exit(1)


def _ensure_env():
    global FLEX_TOKEN, FLEX_IP

    if not FLEX_TOKEN or not FLEX_IP:
        exit_with_error("FLEX_TOKEN and FLEX_IP environment variables must be set.")


def _tracking_id():
    """random string [a-zA-Z0-9]{10}.
    used to identify request at flex
    """
    return "".join(
        random.choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10
        )
    )


def _get_snapshots():
    """Retrieve all snapshots using the dedicated snapshots API."""
    url = f"https://{FLEX_IP}/api/echo/v1/db_snapshots"
    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
    }

    r = requests.get(url, verify=False, headers=headers)

    if r.status_code // 100 != 2:
        exit_with_error(
            f"Failed to get snapshots. tracking_id: {tracking_id} Error: {r.status_code} {r.text}"
        )

    return r.json()


def _get_databases(host_id: str):
    """Retrieve all databases for a host using the dedicated databases API."""
    url = f"https://{FLEX_IP}/api/v1/hosts/{host_id}/databases"
    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
    }

    r = requests.get(url, verify=False, headers=headers)

    if r.status_code // 100 != 2:
        exit_with_error(
            f"Failed to get databases. tracking_id: {tracking_id} Error: {r.status_code} {r.text}"
        )

    return r.json()


############################################
# Main Command
############################################


def filter_snapshots(
    snapshots: list[dict], host_id: str, db_ids: set[str]
) -> list[dict]:
    """Filter snapshots by host and database IDs.

    GET /api/echo/v1/db_snapshots response example:
    [
        {
            "id": "primary__5__1735025906",
            "host_id": "primary",
            "host_name": "primary",
            "sdp_id": "sdp-001",
            "vg_snapshot_ids": [101, 102],
            "databases": [
                {"db_id": "5", "db_name": "analytics"},
                {"db_id": "6", "db_name": "reporting"}
            ],
            "timestamp": 1735025906,
            "consistency_level": "application",
            "db_engine_version": "16.0.1000.6",
            "is_vss_based": true
        }
    ]
    """
    filtered = []

    for snap in snapshots:
        if snap["host_id"] != host_id:
            continue

        snap_db_ids = {db["db_id"] for db in snap["databases"]}
        if db_ids.issubset(snap_db_ids):
            filtered.append(snap)

    return sorted(filtered, key=lambda x: -x["timestamp"])


def run(host_name: str, db_names: list[str]):
    """This script lists snapshots from a host that include the requested DB names.

    Output format: <Snapshot ID> <Timestamp> <Consistency Level> <DateTime>

    primary__5__1735025906 1735025907 crash 2024-12-24T10:51:46

    Usage example:

    Set the following environment variables:
       - `FLEX_TOKEN`: Bearer token for Flex API authentication.
       - `FLEX_IP`: Flex server IP address.

    python list_snapshots.py --host-name <host-name> --db-names <db-name-1,db-name-2>

    Args:
        host_name (str): Host name to list snapshots from
        db_names (list[str]): List of database names to filter snapshots
    """
    _ensure_env()

    # Get databases for the host to map names to IDs
    databases = _get_databases(host_name)
    db_name_to_id = {db["name"]: db["id"] for db in databases}

    # Validate all requested db_names exist
    missing_dbs = [name for name in db_names if name not in db_name_to_id]
    if missing_dbs:
        exit_with_error(f"Databases not found on host '{host_name}': {missing_dbs}")

    required_db_ids = {db_name_to_id[name] for name in db_names}

    # Get all snapshots and filter by host and databases
    all_snapshots = _get_snapshots()
    filtered_snapshots = filter_snapshots(all_snapshots, host_name, required_db_ids)

    if not filtered_snapshots:
        print(f"No snapshots found for databases {db_names} on host '{host_name}'")
        return

    # Calculate column widths for formatting
    sizes = defaultdict(int)
    for snap in filtered_snapshots:
        sizes["id"] = max(sizes["id"], len(snap["id"]))
        sizes["timestamp"] = max(sizes["timestamp"], len(str(snap["timestamp"])))
        sizes["consistency_level"] = max(
            sizes["consistency_level"], len(snap["consistency_level"])
        )

    for snap in filtered_snapshots:
        tm = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(snap["timestamp"]))
        print(
            f"{snap['id'].ljust(sizes['id'])} "
            f"{str(snap['timestamp']).ljust(sizes['timestamp'])} "
            f"{snap['consistency_level'].ljust(sizes['consistency_level'])} "
            f"{tm}"
        )


def parse_arguments():
    parser = OptionParser(
        usage="usage: %prog [options]",
        description="This script list snapshots for the given DB names on the given host.",
    )
    parser.add_option(
        "--host-name",
        dest="host_name",
        help="Look for databases on this host",
        metavar="HOST_NAME",
    )
    parser.add_option(
        "--db-names",
        dest="db_names",
        help="Comma-separated list of database names to be contained in the snapshot",
        type="string",
        metavar="DB_NAMES",
    )
    (options, _) = parser.parse_args()

    if not options.host_name or not options.db_names:
        parser.print_help()
        sys.exit(1)

    return {
        "host_name": options.host_name,
        "db_names": options.db_names.split(","),
    }


if __name__ == "__main__":
    args = parse_arguments()
    run(**args)
