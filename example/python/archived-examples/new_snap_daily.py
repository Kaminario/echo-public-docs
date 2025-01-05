import os
import requests
import sys
import time

FLEX_TOKEN = os.environ["FLEX_TOKEN"]
FLEX_IP = os.environ["FLEX_IP"]
SOURCE_HOST_ID = os.environ["SOURCE_HOST_ID"]
# DATABASE_ID = os.environ["DATABASE_ID"]


def main():
    print(
        "Creating DB snapshot, Flex IP: ", FLEX_IP, " Source host ID: ", SOURCE_HOST_ID
    )
    requests.packages.urllib3.disable_warnings()
    url = f"https://{FLEX_IP}/api/ocie/v1/db_snapshots"
    headers = {"Authorization": f"Bearer {FLEX_TOKEN}"}
    body = {"source_host_id": SOURCE_HOST_ID, "database_ids": [5, 6]}
    r = requests.post(url, json=body, verify=False, headers=headers, timeout=10)
    if r.status_code // 100 != 2:
        print(f"Failed to create snapshot: {r.status_code} {r.text}")
        sys.exit(1)

    task = r.json()
    while task["state"] == "running":
        print(task)
        print("Task create DB snapshot is running")
        time.sleep(5)
        r = requests.get(
            f"https://{FLEX_IP}{task['location']}", verify=False, headers=headers
        )
        if r.status_code // 100 == 2:
            task = r.json()

    if task["state"] == "completed":
        print("Task completed successfully")
        sys.exit(0)

    print(f"Task {task['state']}: ", task["error"])
    sys.exit(1)


main()
