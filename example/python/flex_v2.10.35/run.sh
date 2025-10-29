#! /bin/bash

#1. Snapshot daily at 4:00 all host
#2. Refresh Staging at 6:00
#3. Create Echo from Snapshot (taken at 1)
#4. Delete Echo at 20:00

export FLEX_TOKEN=""
export FLEX_IP=""

# check if the virtual environment is already activated

if [ -z "$VIRTUAL_ENV" ]; then
    echo "Activating virtual environment"
    source ../.venv/bin/activate
fi

# make snapshot of the primary host
python3 make_snapshot.py --host-id primary --name-prefix daily-app --consistency-level application

# retrieve the last snapshot of the host primary in the databases analytics, AIVault, and NeuroStack
last_snap=$(python3 list_snapshots.py --host-name primary --db-names "analytics,AIVault,NeuroStack"  | head -n 1 | awk '{print $1}')
echo "Last snapshot: $last_snap"

# refresh database NeuroStack_clone in the host staging with from last snapshot
python3 refresh.py --host-id staging --db-names "NeuroStack_clone" --snapshot-id "$last_snap"

# create echo databases analytics_clone1, AIVault_clone1, and NeuroStack_clone1
# in the host developing from the last snapshot
python3 make_echo_db.py --host-ids  developing --db-names "analytics,AIVault,NeuroStack" --snapshot-id "$last_snap" --name-suffix "clone1"

# delete echo databases analytics_clone1, AIVault_clone1, and NeuroStack_clone1
python3 delete_echo_db.py --host-id developing --db-names "analytics_clone1,AIVault_clone1,NeuroStack_clone1"
