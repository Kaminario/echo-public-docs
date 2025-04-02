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


def log(msg: str, **kwargs):
    # print to stderr to avoid mixing with stdout
    print(msg, file=sys.stderr, **kwargs)


def _ensure_env():
    global FLEX_TOKEN, FLEX_IP

    if not FLEX_TOKEN or not FLEX_IP:
        log("FLEX_TOKEN and FLEX_IP environment variables must be set.")
        sys.exit(1)


def _tracking_id():
    """random string [a-zA-Z0-9]{10}.
    used to identify request at flex
    """
    return "".join(
        random.choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10
        )
    )


def _host_topology(host_name):
    topo = _get_topology()
    return [t for t in topo if t["host"]["name"] == host_name][0]


def _get_topology():
    url = f"https://{FLEX_IP}/api/ocie/v1/topology"
    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
    }
    log(f"Fetching topology with tracking ID: {tracking_id}")

    r = requests.get(url, verify=False, headers=headers)

    if r.status_code // 100 != 2:
        log(f"Failed to get database topology. Error: {r.status_code} {r.text}")
        sys.exit(1)
    topology = r.json()

    return topology


############################################
# Main Command
############################################


def filter_snapshots(databases: list[dict], db_ids: set[str]) -> list[dict]:
    """
    topology API response example:
    [{'db_snapshot_allowed': True,
    'db_snapshot_disallowed_reason': '',
    'db_snapshots': [{'consistency_level': 'crash',
                        'db_ids': ['5', '6', '7'],
                        'deletable': True,
                        'id': 'daily_1743347917',
                        'timestamp': 1743347917}],
    'id': '5',
    'name': 'NeuroStack',
    'parent': None,
    'vendor': 'mssql'},
    {'db_snapshot_allowed': True,
    'db_snapshot_disallowed_reason': '',
    'db_snapshots': [{'consistency_level': 'crash',
                        'db_ids': ['5', '6', '7'],
                        'deletable': True,
                        'id': 'daily_1743347917',
                        'timestamp': 1743347917}],
    'id': '6',
    'name': 'AIVault',
    'parent': None,
    'vendor': 'mssql'},
    {'db_snapshot_allowed': True,
    'db_snapshot_disallowed_reason': '',
    'db_snapshots': [{'consistency_level': 'crash',
                        'db_ids': ['5', '6', '7'],
                        'deletable': True,
                        'id': 'daily_1743347917',
                        'timestamp': 1743347917},
                        {'consistency_level': 'application',
                        'db_ids': ['7'],
                        'deletable': True,
                        'id': 'primary__7__1743342150',
                        'timestamp': 1743342150}],
    'id': '7',
    'name': 'analytics',
    'parent': None,
    'vendor': 'mssql'}]
    """

    filtered_snapshots = {}  # snapshot_id -> snapshot

    for db in databases:
        if db["id"] not in db_ids:
            continue

        for snap in db["db_snapshots"]:
            if set(snap["db_ids"]) & db_ids == db_ids:
                filtered_snapshots[snap["id"]] = snap

    # return sorted snapshots by timestamp in descending order
    return sorted(filtered_snapshots.values(), key=lambda x: -x["timestamp"])


def run(host_name: str, db_names: str):
    """This script list snapshots from host that includes requested DB names.

    in table format: <Snapshot ID> <Created At> <Consistency Level>

    primary__5__1735025906 1735025907 crash
    primary__5__1735025907 1735025900 application

    Usage example:

    Set the following environment variables:
       - `FLEX_TOKEN`: Bearer token for Flex API authentication.
       - `FLEX_IP`: Flex server IP address.

    python list_snapshots.py --host-name <host-name> --db-names <db-name-1,db-name-2>

    Args:
        host_name (str): Host name to take snapshot from
        db_names (list[str]): List of database names to filter snapshots
    """

    _ensure_env()

    # get_database_ids by host_id by vg
    topology = _host_topology(host_name)

    db_names_to_db_ids = {db["name"]: db["id"] for db in topology["databases"]}
    required_db_ids = {db_names_to_db_ids[db_name] for db_name in db_names}

    filtered_snapshots = filter_snapshots(topology["databases"], required_db_ids)

    # make ljust to a max length of each column
    sizes = defaultdict(int)
    for snap in filtered_snapshots:
        sizes["id"] = max(sizes["id"], len(snap["id"]))
        sizes["timestamp"] = max(sizes["timestamp"], len(str(snap["timestamp"])))
        sizes["consistency_level"] = max(
            sizes["consistency_level"], len(snap["consistency_level"])
        )

    for snap in filtered_snapshots:
        # timestamp in format "%Y-%m-%dT%H:%M:%S"
        tm = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(snap["timestamp"]))
        print(
            f"{snap['id'].ljust(sizes['id'])} {str(snap['timestamp']).ljust(sizes['timestamp'])} {snap['consistency_level'].ljust(sizes['consistency_level'])} {tm}"
        )


def parse_arguments():
    parser = OptionParser(
        usage="usage: %prog [options]",
        description="This script creates a snapshot of all databases on the source host.",
    )
    parser.add_option(
        "--host-name",
        dest="host_name",
        help="Host name to take snapshot from",
        metavar="HOST_NAME",
    )
    parser.add_option(
        "--db-names",
        dest="db_names",
        help="Comaseparated list of database names to be contained in the snapshot",
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
