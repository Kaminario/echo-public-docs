import os
import requests
import sys
import time

FLEX_TOKEN = os.environ['FLEX_TOKEN']
FLEX_IP = os.environ['FLEX_IP']
SOURCE_HOST_ID = os.environ['SOURCE_HOST_ID']
DESTINATION_HOST_ID = os.environ['DESTINATION_HOST_ID']
DATABASE_ID = os.environ['DATABASE_ID']
DATABASE_NAME = os.environ['DATABASE_NAME']


def main():
    requests.packages.urllib3.disable_warnings() 
    url = f"https://{FLEX_IP}/flex/api/v1/ocie/clone"
    headers = {'Authorization': f'Bearer {FLEX_TOKEN}'}
    body = {
        "source_host_id": SOURCE_HOST_ID,
        "database_ids": [DATABASE_ID],
        "destinations": [{
            "host_id": DESTINATION_HOST_ID,
            "db_id": DATABASE_ID,
            "db_name": DATABASE_NAME + "_" + time.strftime("%Y%m%d"),
        }]
    }
    r = requests.post(url, json=body, verify=False, headers=headers)
    if r.status_code // 100 != 2:
        sys.exit(1)

    task = r.json()
    while task['state'] == 'running':
        time.sleep(5)
        r = requests.get(f"https://{FLEX_IP}{task['location']}", verify=False, headers=headers)
        if r.status_code // 100 == 2:
            task = r.json()


    if task['state'] == 'completed':
        print("Task completed successfully")
        sys.exit(0)

    print(f"Task {task['state']}: ", task['error'])
    sys.exit(1)

main()