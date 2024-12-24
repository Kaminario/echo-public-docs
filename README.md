# Silk Echo

Silk Echo provides the ability to take an Application Consistent snapshot of a Database on one Host and use it to create a copy database on another Host, in human friendly manner or automated routine.

## Prerequisites

Installed Flex
Host Windows server runs MSSQL with original DB.
Host Windows server runs MSSQL.
Hosts are capable to communicate with the Flex server.
Silk VSS installed and configured on both hosts.

The required setup actions:

1. Register the "source" host server in Flex. (The server that hold original MSSQL DB)
2. Install Silk Agent on "source".
3. Register the "destination" host server in Flex. (The server where Flex will restore DB)
4. Install Silk Agent on "target".

After Hosts are prepared, we can clone a DB from the source host to some target host.

1. (Optionally) Use Echo API to discover the registered Hosts and their existing Databases
2. Call Flex to clone a DB from a "source" host to a "destination" host.

The Most of the actions are long operation and can be monitored by "tasks" API calls.

# Authentication

Flex uses Bearer Token Authentication.

Example

```bash
curl -XGET "http://{flex}/{path}" -H "Authorization: Bearer {token}"
```

The authentication token obtained by using Flex UI and relies on operator that
is an authenticated user in Flex.

- Browse to Flex.
- Click Cog at right upper corner of the web page
- Click "App Tokens"

The pop up dialog helps to mange existing Application Tokens and create new ones.

# Operation Tracking

A unique header parameter can be set, causing all Flex logs generated
by that API call to include that value for ease of flow tracking interfnaly.

Header:

- `hs-ref-id` (string): Keep it small, 6-8 characters. Format [a-zA-Z0-9]

Example

```bash
curl -XGET "http://{flex}/{path}" -H "hs-ref-id: Hy6f50Ki"
```

# APIS

**Topology API**
|method|path|description|
|-|-|-|
|GET|/api/ocie/v1/topology|Retrieve full "host > db > snapshot" topology|

**Hosts APIs**
|method|path|description|
|-|-|-|
|PUT|/flex/api/v1/hosts/{host_id}|Register host|
|DELETE|/flex/api/v1/hosts/{host_id}|Unregister Host|
|GET|/flex/api/v1/hosts/{host_id}|Retrieve Host Info|
|GET|/flex/api/v1/hosts|Get All Registered Hosts Info|

**Clone APIs**
|method|path|description|
|-|-|-|
|POST|/flex/api/v1/ocie/clone|Create Snapshot and clone it to a desdtination host|
|DELETE|/flex/api/v1/ocie/clone|Delete clone|


**Snapshot APIs**
|method|path|description|
|-|-|-|
|POST|/flex/api/v1/db_snapshots|Create a snapshot|
|DELETE|/flex/api/v1/db_snapshots/{db_snapshot_id}|Delete a snapshot|
|POST|/flex/api/v1/db_snapshots/{db_snapshot_id}/clone|Clone a DB from an existing snapshot to a host|


**Tasks APIs**
|method|path|description|
|-|-|-|
|GET|/flex/api/v1/ocie/tasks/{request_id}|Retrieve Task Info|
|GET|/flex/api/v1/ocie/tasks|Get All Registered Task Info|

The "Task" returned by Clone/Snapshot API contains "location" field that can differ from Tasks API
but it both of them will work the same way.

## Host APIs

### Register Host

#### Endpoint

`PUT /flex/api/v1/hosts/{host_id}`

#### Request Body

```json
{
  "db_vendor": "mssql"
}
```

#### Parameters

- `host_id` (string):
    The unique identifier for the host `host_id`, regulary it is the same as host name

    It should be compliant to following:

    The ID of the host. Must start with letter, end with letter or number.
    Only letters, numbers, underscore and hyphen are allowed.
    Min length 3, max length 32

  - min_length=3,
  - max_length=32,
  - pattern="^[a-zA-Z][a-zA-Z0-9_-]+[a-zA-Z0-9]$",

- `db_vendor` (string enum):
    The database vendor of the host. Currently only `mssql` is supported.

#### Example

```bash
curl -XPUT "http://{flex}/flex/api/v1/hosts/{host_id}" -d'{"db_vendor": "mssql"}' -H "Authorization: Bearer {token}"
```

#### Responses

- 201 Created

    ```json
    {
        "host_id": "host_id",
        "db_vendor": "mssql",
        "token": "vd8iofbhsdohodxhgdx"
    }
    ```

    - `host_id` (string): The unique identifier for the host.
    - `db_vendor` (string enum): The database vendor of the host.
    - `token` (string): unique token for the host is used to authenticate the agent with the Flex. URL-safe String of max 128 characters.

- 409 Conflict

    Host already exists

### Unregister Host

Removes the host from the Flex.

#### Endpoint

`DELETE /flex/api/v1/hosts/{host_id}`

#### Request Body

No

#### Parameters

- `host_id` (string): The unique identifier for the host.

#### Responses

- 204 No Content

    The 204 returned even there is no such host exists.

#### Example

```bash
curl -XDELETE "http://{flex}/flex/api/v1/hosts/{host_id}" -H "Authorization: Bearer {token}"
```

### Get Host

Get the single Host information stored in Flex.

#### Endpoint

`GET /flex/api/v1/hosts/{host_id}`

#### Request Body

No

#### Parameters

- `host_id` (string): The unique identifier for the host.

#### Responses

- 200 Ok

    ```json
    {
        "host_id": "host01",
        "db_vendor": "mssql",
        "last_seen_ts": 1722841284,
        "host_name": "host_wfGIWX4",
        "host_iqn": "iqn.2009-01.com.kaminario:initiator.host_wfGIWX4",
        "host_os": "Windows",
        "host_os_version": "Windows 10",
        "agent_version": "0.1.0",
        "cloud_vendor": "AZURE"
    }
    ```

    - `host_id` (string): The unique identifier for the host.
    - `db_vendor` (string): The vendor of DB on the host
    - `last_seen_ts` (int): The Timestamp in seconds of last received heartbeat from the Host Agent
    - `cloud_vendor` (string)
    - `host_name` (string)
    - `host_iqn` (string)
    - `host_os` (string)
    - `host_os_version` (string)
    - `agent_version` (string): In format '1.2.3'

- 404 Not Found

#### Example

```bash
curl -XGET "http://{flex}/flex/api/v1/hosts/{host_id}" -H "Authorization: Bearer {token}"
```

### List Host

Get the Hosts information stored in Flex.

#### Endpoint

`GET /flex/api/v1/hosts`

#### Request Body

No

#### Responses

- 200 Ok

    ```json
    [
        {
            "host_id": "host01",
            "db_vendor": "mssql",
            "last_seen_ts": 1722841284,
            "host_name": "host_wfGIWX4",
            "host_iqn": "iqn.2009-01.com.kaminario:initiator.host_wfGIWX4",
            "host_os": "Windows",
            "host_os_version": "Windows 10",
            "agent_version": "0.1.0",
            "cloud_vendor": "AZURE"
        }
    ]
    ```
    Object fields are Identical to API `Get Host`

- 204 No Content

    If no host is registered, the response is an empty array:

    ```json
    []
    ```

#### Example

```bash
curl -XGET "http://{flex}/flex/api/v1/hosts" -H "Authorization: Bearer {token}"
```

## Clone APIs

### Clone DB

Takes a snapshot of a database located on host A and creates a copy on one or more hosts.

#### Endpoint

`POST /flex/api/v1/ocie/clone`

#### Request Body

```json
{
  "source_host_id": "host02",
  "database_ids": [
    "5"
  ],
  "destinations": [
    {
      "host_id": "host03",
      "db_id": "5",
      "db_name": "employes_copy_05"
    },
    {
      "host_id": "host06",
      "db_id": "5",
      "db_name": "employes_copy_06"
    }
  ]
}
```

#### Parameters

- `source_host_id` (string): The unique identifier for the source host.
- `database_ids` (array of strings): The unique identifiers of the databases to clone.
- `destinations` (array of objects): A list of objects detailing the destination databases:
    - `host_id` (string): The unique identifier for the destination host.
    - `db_id`  (string): The unique identifier of database to clone under new_name
    - `db_name` (string): The name of the destination database.

#### Responses

- 200 Ok

    ```json
    {
        "state": "completed",
        "create_ts": 1735025889,
        "update_ts": 1735025908,
        "request_id": "Fj3U7QTsDDWL45ikk0bvk2tsanfC3HBJH2zVyJvfRLc",
        "owner": "ocie-0",
        "command_type": "CreateCloneCommand",
        "ref_id": "ADD62kMoLB",
        "error": "",
        "result": {"db_snapshot": {"id": "primary__5__1735025906"}, "cloned_dbs": [{
            "id": "7",
            "name": "dev_bd_copu_01",
            "host_id": "host02",
            "source_host_id": "host01",
            "source_db_id": 5,
            "source_db_name": "dev_db",
        }]},
        "location": "/api/ocie/v1/tasks/Fj3U7QTsDDWL45ikk0bvk2tsanfC3HBJH2zVyJvfRLc",
    }
    ```
    - `state` (string): Task state. Optional are: running, completed, failed, aborted.
    - `create_ts` (integer): Timestamp task was committed
    - `update_ts` (integer): Last time Task state was updated
    - `request_id` (string): The Original request_id
    - `owner` (string): Flex owner of the task.
    - `command_type` (CommandKind): Type of the task
    - `ref_id` (string): ref_id to track the operation
    - `error` (string): Error message.
    - `result` (object): The Object hosts an information about created clones
    - `location` (string): URL location to be queried for Task state

#### Example

```bash
curl -XPOST "http://{flex}/flex/api/v1/ocie/clone" -d'{"source_host_id": "host01","database_ids":["5"],"destinations":[{"host_id":"host02","db_id":"5","db_name":"employes_copy_05"}]}' -H 'Content-Type: application/json' -H "Authorization: Bearer {token}"
```

## Snapshot APIs

### Create DB Snapshot

Creates a snapshot of a database located on a host.

#### Endpoint

`POST /flex/api/v1/db_snapshots`

#### Request Body

```json
{
  "source_host_id": "host01",
  "database_ids": [
    "5", "6"
  ],
}
```

#### Parameters

- `source_host_id` (string): The unique identifier for the source host.
- `database_ids` (list of string): The unique identifiers for the databases to snapshot.

#### Responses

- 200 Ok

    ```json
    {
        "state": "completed",
        "create_ts": 1735025889,
        "update_ts": 1735025908,
        "request_id": "Fj3U7QTsDDWL45ikk0bvk2tsanfC3HBJH2zVyJvfRLc",
        "owner": "ocie-0",
        "command_type": "CreateDBSnapshotCommand",
        "ref_id": "ADD62kMoLB",
        "error": "",
        "result": {"db_snapshot": {"id": "primary__5__1735025906"}},
        "location": "/api/ocie/v1/tasks/Fj3U7QTsDDWL45ikk0bvk2tsanfC3HBJH2zVyJvfRLc",
    }
    ```

#### Example

```bash
curl -XPOST "http://{flex}/flex/api/v1/db_snapshots" -d'{"source_host_id":"host01","database_ids":["5","6"]}' -H 'Content-Type: application/json' -H "Authorization: Bearer {token}"
```

### Clone DB Snapshot

Clone a DB from an existing snapshot to a host

#### Endpoint

`GET /flex/api/v1/db_snapshots/{db_snapshot_id}/clone`

#### Payload

```json
{
    "destinations": [
        {
            "host_id": "host02",
            "db_id": "5",
            "db_name": "db_name"
        }
    ],
}
```

- `db_snapshot_id` (string): The unique identifier for the database.
- `destinations` (array of objects): A list of objects detailing the destination databases:
    - `host_id` (string): The unique identifier for the destination host.
    - `db_id` (string):  The unique identifier for database to name.
    - `db_name` (string): The name of the destination database.

#### Responses

- 200 Ok

    ```json
    {
        "state": "running",
        "create_ts": 1735049892,
        "update_ts": 1735049892,
        "request_id": "YUiQ_S3SstXXtBQhCuyYUzDws-fAYnEsnlX84wsERvs",
        "owner": "ocie-0",
        "command_type": "ImportDBSnapshotCommand",
        "ref_id": "asdasda",
        "error": "",
        "result": null,
        "location": "/api/ocie/v1/tasks/YUiQ_S3SstXXtBQhCuyYUzDws-fAYnEsnlX84wsERvs"
    }
    ```

    ```json
    {
        "state": "completed",
        "create_ts": 1735049892,
        "update_ts": 1735049907,
        "request_id": "YUiQ_S3SstXXtBQhCuyYUzDws-fAYnEsnlX84wsERvs",
        "owner": "ocie-0",
        "command_type": "ImportDBSnapshotCommand",
        "ref_id": "asdasda",
        "error": "",
        "result": {
            "cloned_dbs": [
            {
                "source_db_name": "analytics_4",
                "source_host_id": "primary",
                "name": "alala",
                "id": "5",
                "host_id": "dev-2",
                "source_db_id": 10
            }
            ]
        },
        "location": "/api/ocie/v1/tasks/YUiQ_S3SstXXtBQhCuyYUzDws-fAYnEsnlX84wsERvs"
    }
    ```

    For explanation see `Create Clone` API

#### Example


```bash
curl -XPOST "http://{flex}/flex/api/v1/db_snapshots/primary__10__1735028786/clone" -d'{"destinations":[{"host_ids":"dev-2","db_name":"alala"}]}' -H 'Content-Type: application/json'
```


## Task State APIs

### Get

Retrieve current Task state by ID

#### Endpoint

`GET /flex/api/v1/ocie/tasks/{request_id}`

#### Payload

- `request_id` (string)

#### Responses

- 200 Ok

    ```json
        {
            "state": "running",
            "create_ts": 1723108781,
            "update_ts": 1723108781,
            "request_id": "_gfSro_KscTYPMYiMUjCjJleHLauR0y_kSTzlIi8was",
            "owner": "ocie",
            "command_type": "DeployCommand",
            "ref_id": "bjGP9ygRMew",
            "error": "",
            "result": null
            "location": "/flex/api/v1/ocie/tasks/_gfSro_KscTYPMYiMUjCjJleHLauR0y_kSTzlIi8was"
        }
    ```

- 404 Not Found

#### Example

```bash
curl -XGET "http://{flex}/flex/api/v1/ocie/tasks/_gfSro_KscTYPMYiMUjCjJleHLauR0y_kSTzlIi8was"
```

### List

Retrieve All Tasks

#### Endpoint

`GET /flex/api/v1/ocie/tasks`

#### Payload

No

#### Responses

- 200 Ok

    ```json
    [
        {
            "state": "completed",
            "create_ts": 1723108781,
            "update_ts": 1723108981,
            "request_id": "_gfSro_KscTYPMYiMUjCjJleHLauR0y_kSTzlIi8was",
            "owner": "ocie",
            "command_type": "DeployCommand",
            "ref_id": "bjGP9ygRMew",
            "error": "",
            "result": {
                "cloned_dbs": [
                    {
                        "source_db_name": "analytics_4",
                        "source_host_id": "primary",
                        "name": "alala",
                        "id": "5",
                        "host_id": "dev-2",
                        "source_db_id": 10
                    }
                ]
        },
            "location": "/flex/api/v1/ocie/tasks/_gfSro_KscTYPMYiMUjCjJleHLauR0y_kSTzlIi8was"
        }
    ]
    ```

#### Example

```bash
curl -XGET "http://{flex}/flex/api/v1/ocie/tasks"
```
