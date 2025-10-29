# Silk Echo

Silk Echo offers a powerful solution for creating application-consistent or crash-consistent snapshots of databases.

With silk, you can capture application-consistent state of a database on one host with precision and reliability. These snapshots can then be used to create an identical copy of the database on a different host. The process is flexible, allowing you to perform it manually for specific needs or integrate it into automated workflows to streamline operations. This ensures consistent, efficient, and error-free database replication.

For rapid data capture, crash-consistent snapshots offer a fast and reliable way to preserve system state instantly. These snapshots enable quick recovery from failures or disaster scenarios. However, since they do not ensure application-level consistency, databases and transactional applications may require log replay or application-consistent snapshots for full data integrity.

## Prerequisites

- Installed Flex.
- Source host running Windows Server with MSSQL and the original database.
- Destination host running Windows Server with MSSQL.
- Hosts must be capable of communicating with the Flex server and the SDP rest API.
- You'l need Silk VSS installed (on both sides) if you're doing app-consistent operations on MSSQL2019 .

### Required Setup Actions:

1. Register the "source" host server in Flex (the server that holds the original MSSQL database).
2. Install Silk Agent on the "source" host.
3. Register the "destination" host server in Flex (the server where Flex will restore the database).
4. Install Silk Agent on the "destination" host.

### Cloning a Database

After preparing the hosts, you can clone a database from the source host to the destination host:

1. (Optional) Use the Echo API to discover registered hosts and their existing databases.
2. Call Flex to clone a database from the "source" host to the "destination" host.

Most of these actions are long-running operations and can be monitored via the "tasks" API calls.

## Authentication

Flex uses Bearer Token Authentication.

### Example:

```bash
curl -XGET "http://{flex}/{path}" -H "Authorization: Bearer {token}"
```

The authentication token is obtained while registering host in Flex.

## Operation Tracking

A unique header parameter can be set, this will make it easier to track operations.

### Header:

- `hs-ref-id` (string): Keep it short, 6-8 characters. Format: `[a-zA-Z0-9]`.

### Example:

```bash
curl -XGET "http://{flex}/{path}" -H "hs-ref-id: Hy6f50Ki"
```

## APIs

### **Topology API**

| Method | Path                    | Description                                       |
| ------ | ----------------------- | ------------------------------------------------- |
| GET    | /api/echo/v1/topology   | Retrieve the full "host > db > snapshot" topology |

### **Host APIs**

| Method | Path                         | Description                   |
| ------ | ---------------------------- | ----------------------------- |
| PUT    | /api/v1/hosts/{id}           | Register a host               |
| DELETE | /api/v1/hosts/{id}           | Unregister a host             |
| GET    | /api/v1/hosts/{id}           | Retrieve host info            |
| GET    | /api/v1/hosts                | Get all registered hosts info |

### **Refresh APIs**

| Method | Path                                            | Description                                 |
| ------ | ----------------------------------------------- | ------------------------------------------- |
| POST   | /api/echo/v1/hosts/{id}/databases/_refresh | replaces host dbs with dbs from a snapshot  |

### **Clone APIs**

| Method | Path                        | Description                                          |
| ------ | --------------------------- | ---------------------------------------------------- |
| POST   | /api/echo/v1/echo_dbs       | Create a snapshot and clone it to a destination host |
| DELETE | /api/echo/v1/echo_dbs       | Delete a clone                                       |

### **Snapshot APIs**

| Method | Path                                 | Description                                          |
| ------ | ------------------------------------ | ---------------------------------------------------- |
| POST   | /api/echo/v1/db_snapshots            | Create a snapshot                                    |
| DELETE | /api/echo/v1/db_snapshots/{id}       | Delete a snapshot                                    |
| POST   | /api/echo/v1/db_snapshots/{id}/echo_db | Clone a database from an existing snapshot to a host |

### **Tasks APIs**

| Method | Path                         | Description                   |
| ------ | ---------------------------- | ----------------------------- |
| GET    | /api/echo/v1/tasks/{id}      | Retrieve task info            |
| GET    | /api/echo/v1/tasks           | Get all registered tasks info |

## Host APIs

### Register Host

#### Endpoint:

`PUT /api/v1/hosts/{id}`

#### Request Body:

```json
{
  "db_vendor": "mssql"
}
```

#### Parameters:

- `id` (string): The unique identifier for the host in the URL path, typically the hostname. Must:
  - Start with a letter and end with a letter or number.
  - Only contain letters, numbers, underscores, and hyphens.
  - Be 3-32 characters in length.

  Example pattern: `^[a-zA-Z][a-zA-Z0-9_-]+[a-zA-Z0-9]$`

- `db_vendor` (string): The database vendor for the host. Currently, only `mssql` is supported.

#### Example:

```bash
curl -XPUT "http://{flex}/api/v1/hosts/{id}" \
-H "Authorization: Bearer {token}" \
-d'{"db_vendor": "mssql"}' \
```

#### Responses:

- **201 Created**

  ```json
  {
      "host_id": "host_id",
      "db_vendor": "mssql",
      "token": "vd8iofbhsdohodxhgdx"
  }
  ```
    **Notice:** The token is used to authenticate the host, you need to store it securely and use it when installing Silk Agent.

- **409 Conflict**

    Host already exists.

### Unregister Host

#### Endpoint:

`DELETE /api/v1/hosts/{id}`

#### Responses:

- **204 No Content**

    The host was successfully unregistered (or did not exist).

#### Example:

```bash
curl -XDELETE "http://{flex}/api/v1/hosts/{id}" \
-H "Authorization: Bearer {token}"
```

### Get Host Info

#### Endpoint:

`GET /api/v1/hosts/{id}`

#### Responses:

- **200 OK**

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

- **404 Not Found**

    Host does not exist.

#### Example:

```bash
curl -XGET "http://{flex}/api/v1/hosts/{id}" \
-H "Authorization: Bearer {token}"
```

### List Hosts

#### Endpoint:

`GET /api/v1/hosts`

#### Responses:

- **200 OK**

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

- **204 No Content**

    No hosts are registered.

#### Example:

```bash
curl -XGET "http://{flex}/api/v1/hosts" \
-H "Authorization: Bearer {token}"
```

## Clone APIs

### Clone DB

Takes a snapshot of a database located on host A and creates a copy on one or more hosts.

#### Endpoint

`POST /api/echo/v1/echo_dbs`

##### Validate
The request can be validated without actually being executed,
by calling the same request with "/__validate" at the end of the endpoint

`POST /api/echo/v1/echo_dbs/__validate`

#### Request Body

```json
{
  "source_host_id": "host02",
  "destinations": [
    {
      "host_id": "host03",
      "db_id": "5",
      "db_name": "employees_copy_05"
    },
    {
      "host_id": "host06",
      "db_id": "5",
      "db_name": "employees_copy_06"
    }
  ],
  "name_prefix": "snap_v10",
  "consistency_level": "crash"
}
```

#### Parameters

- `source_host_id` (string): The unique identifier for the source host.
- `destinations` (array of objects): A list of objects detailing the destination databases:
  - `host_id` (string): The unique identifier for the destination host.
  - `db_id` (string): The unique identifier of the database to clone.
  - `db_name` (string): The name of the destination database.
- `name_prefix` (string): The prefix of the name of the snapshot.
- `consistency_level` (choice):  The consistency level for the snapshot.
  Possible values: `crash`, `application`.

#### Responses

- 200 OK

  ```json
  {
      "state": "completed",
      "create_ts": 1735025889,
      "update_ts": 1735025908,
      "request_id": "Fj3U7QTsDDWL45ikk0bvk2tsanfC3H",
      "owner": "ocie-0",
      "command_type": "CreateCloneCommand",
      "ref_id": "ADD62kMoLB",
      "error": "",
      "result": {
          "db_snapshot": {"id": "primary__5__1735025906"},
          "cloned_dbs": [
              {
                  "id": "7",
                  "name": "dev_db_copy_01",
                  "host_id": "host02",
                  "source_host_id": "host01",
                  "source_db_id": 5,
                  "source_db_name": "dev_db"
              }
          ]
      },
      "location": "/api/echo/v1/tasks/Fj3U7QTsDDWL45ikk0bvk2tsanfC3H"
  }
  ```
  - `state` (string): The task state. Possible values: `running`, `completed`, `failed`, `aborted`.
  - `create_ts` (integer): The timestamp when the task was created.
  - `update_ts` (integer): The timestamp of the last task state update.
  - `request_id` (string): The original request ID.
  - `owner` (string): The Flex owner of the task.
  - `command_type` (string): The type of the task.
  - `ref_id` (string): The reference ID to track the operation.
  - `error` (string): Any error message.
  - `result` (object): Information about the created clones.
  - `location` (string): URL to query the task state.

##### Validate response

All validation responses come with the identical format:

```
{
  "valid":true/false,
  "issues":[
    {
        "issue_type": "CODE OF THE ISSUE",
        "description": "textual description",
        "body": {} // optional. additional data in {key: value} format
    }
  ]
}
```


###### No Issues

- 200 OK

  ```json
  {
    "valid":true,
    "issues":[]
  }
  ```

###### Validation Issues

- 200 OK

  ```json
  {
    "valid":false,
    "issues":[
      {
        "issue_type": "DB_NAME_IS_IN_USE",
        "description": "host_id='da39-n10li-5'. db names already in use: full_db_3",
        "body": {}
      }
    ]
  }
  ```

#### Example

```bash
curl -XPOST "http://{flex}/api/echo/v1/echo_dbs" \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer {token}" \
-d'{
  "source_host_id": "host01",
  "database_ids": [
    "5"
  ],
  "destinations": [
    {
      "host_id": "host02",
      "db_id": "5",
      "db_name": "employees_copy_05"
    }
  ]
}'
```

### Delete Cloned DB

Delete a Cloned DB from a host and related thin volumes from the SDP.

The request can be validated without actually being executed,
by calling the same request with "/__validate" at the end of the endpoint

#### Endpoint

`DELETE /api/echo/v1/echo_dbs`

##### Validate

`DELETE /api/echo/v1/echo_dbs/__validate`

#### Request Body

```json
{
    "host_id":"dev-2",
    "database_id":"6"
}
```

#### Parameters
  - `host_id` (string): The unique identifier for the host to delete from.
  - `database_id` (string): The unique identifier for the database to delete.

#### Responses

- 202 OK
  ```json
  {
    "state":"running",
    "create_ts":1722841284,
    "update_ts":1722841284,
    "request_id":"1GUQEnC1fk3sQCc0BHTpFseyB8PfUaS51_lD3iPaRP4",
    "owner":"ocie-0",
    "command_type":"DeleteCommand",
    "ref_id":"592855db",
    "error":"",
    "result":null,
    "location":"/api/echo/v1/tasks/1GUQEnC1fk3sQCc0BHTpFseyB8PfUaS51_lD3iPaRP4"
  }
  ```

#### Example

```bash
curl -XDELETE "http://{flex}/api/echo/v1/echo_dbs" -H 'Content-Type: application/json' -H 'Authorization: Bearer {token}' -d'{"host_id":"dev-2","database_id":"6"}'
```

## Refresh API

This api will replace underline volumes of the selected databases with an new volumes.
The new volumes are cloned from a desired snapshot.

In case of keep_backup is true. The original database is renamed to a new name

```
<db_name>_bkp_<timestamp>
```

db_name: is an original db name
timestamp: The time of the refresh. The timestamp is in ISO 8601 format. "20250216T143521Z"

fin-db => fin-db_bkp_20250216T143521Z

### Endpoint:

`POST /api/echo/v1/hosts/{id}/databases/_refresh`

### Validate

`POST /api/echo/v1/hosts/{id}/databases/_refresh/__validate`

#### Request Body:

```json
{
  "snapshot_id": "string",
  "db_names": [
    "string"
  ],
  "keep_backup": true
}
```

#### Parameters:

- `id` (string): The unique identifier for the host in the URL path, typically the hostname. Must:
  - Start with a letter and end with a letter or number.
  - Only contain letters, numbers, underscores, and hyphens.
  - Be 3-32 characters in length.

  Example pattern: `^[a-zA-Z][a-zA-Z0-9_-]+[a-zA-Z0-9]$`

- `snapshot_id` (string): The unique identifier for the database snapshot.
- `db_names` (array of strings): The names of the databases on the host to be replaced
- `keep_backup` (boolean): If set to true, Flex will rename the original db to `{name}_bkp_1` instead of deletion.

#### Example:

```bash
curl -XPOST "http://{flex}/api/echo/v1/hosts/{id}/databases/_refresh" \
-H "Authorization: Bearer {token}" \
-d'{"snapshot_id":"snap_1735025906","db_names": ["dev_db","dev_db2"],"keep_backup":true}'
```

#### Responses:

Following response example has a result field. This field will have a value only after operation completion. See: **Task State APIs**

- 200 OK

  ```json
  {
      "state": "completed",
      "create_ts": 1735025889,
      "update_ts": 1735025908,
      "request_id": "Gm9X2VpqAZNY78sjl5cwRbPfKtoQ6B",
      "owner": "ocie-0",
      "command_type": "ReplaceDBCommand",
      "ref_id": "HHudu8s",
      "error": "",
      "result": {
        "cloned_dbs": [{
            "id": "dest_db_id",
            "name": "dest_db_name",
            "host_id": "host_id",
            "source_host_id": "source_host_id",
            "source_db_id": "source_db_id",
            "source_db_name": "source_db_name"
        }]
      },
      "location": "/api/echo/v1/tasks/Gm9X2VpqAZNY78sjl5cwRbPfKtoQ6B"
  }
  ```

## Snapshot APIs

### Create DB Snapshot

Create a snapshot of a database.

#### Endpoint

`POST /api/echo/v1/db_snapshots`

##### Validate
The request can be validated without actually being executed,
by calling the same request with "/__validate" at the end of the endpoint

`POST /api/echo/v1/db_snapshots/__validate`

#### Request Body

```json
{
  "source_host_id": "host01",
  "database_ids": [
    "5", "6"
  ],
  "name_prefix": "snap_v10",
  "consistency_level" : "crash"
}
```

#### Parameters

- `source_host_id` (string): The unique identifier for the source host.
- `database_ids` (list of strings): The unique identifiers for the databases to snapshot.
- `name_prefix` (string): The prefix of the name of the snapshot.
- `consistency_level` (choice): The consistency level for the snapshot. Possible values: "crash", "application"

#### Responses

- 200 OK

  ```json
  {
      "state": "completed",
      "create_ts": 1735025889,
      "update_ts": 1735025908,
      "request_id": "Fj3U7QTsDDWL45ikk0bvk2tsanfC3H",
      "owner": "ocie-0",
      "command_type": "CreateDBSnapshotCommand",
      "ref_id": "ADD62kMoLB",
      "error": "",
      "result": {"db_snapshot": {"id": "primary__5__1735025906"}},
      "location": "/api/echo/v1/tasks/Fj3U7QTsDDWL45ikk0bvk2tsanfC3H"
  }
  ```

#### Example

```bash
curl -XPOST "http://{flex}/api/echo/v1/db_snapshots" \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer {token}" \
-d'{"source_host_id":"host01","database_ids":["5","6"],"name_prefix":"snap_v10", "consistency_level": "application"}'
```

### Clone DB Snapshot

Clone a database from an existing snapshot to a host.

#### Endpoint

`POST /api/echo/v1/db_snapshots/{id}/echo_db`

##### Validate
The request can be validated without actually being executed,
by calling the same request with "/__validate" at the end of the endpoint

`POST /api/echo/v1/db_snapshots/{id}/echo_db/__validate`

#### Request Body

```json
{
    "destinations": [
        {
            "host_id": "host02",
            "db_id": "5",
            "db_name": "db_name"
        }
    ]
}
```

#### Parameters

- `id` (string): The unique identifier for the database snapshot in the URL path.
- `destinations` (array of objects): A list of objects detailing the destination databases:
  - `host_id` (string): The unique identifier for the destination host.
  - `db_id` (string): The unique identifier for the database.
  - `db_name` (string): The name of the destination database.

#### Responses

- 200 OK

  ```json
  {
      "state": "running",
      "create_ts": 1735049892,
      "update_ts": 1735049892,
      "request_id": "YUiQ_S3SstXXtBQhCuyYUzDws",
      "owner": "ocie-0",
      "command_type": "ImportDBSnapshotCommand",
      "ref_id": "asdasda",
      "error": "",
      "result": null,
      "location": "/api/echo/v1/tasks/YUiQ_S3SstXXtBQhCuyYUzDws"
  }
  ```

  ```json
  {
      "state": "completed",
      "create_ts": 1735049892,
      "update_ts": 1735049907,
      "request_id": "YUiQ_S3SstXXtBQhCuyYUzDws",
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
      "location": "/api/echo/v1/tasks/YUiQ_S3SstXXtBQhCuyYUzDws"
  }
  ```

#### Example

```bash
curl -XPOST "http://{flex}/api/echo/v1/db_snapshots/primary__10__1735028786/echo_db" \
-H 'Content-Type: application/json' \
-d'{"destinations":[{"host_id":"dev-2","db_name":"alala"}]}'
```

### Delete DB Snapshot

Deletes a DB Snapshot. It is only possible to delete a DB Snapshot if there are no cloned databases that were created from that snapshot.

Note that this endpoint does not create a task. A successful status code indicates that the DB Snapshot has already been deleted.

#### Endpoint

`DELETE /api/echo/v1/db_snapshots/{id}`

##### Validate
The request can be validated without actually being executed,
by calling the same request with "/__validate" at the end of the endpoint

`DELETE /api/echo/v1/db_snapshots/{id}/__validate`

#### Responses

- 204 OK

#### Example

```bash
curl -XDELETE "http://{flex}/api/echo/v1/db_snapshots/primary__10__1735028786" -H 'Authorization: Bearer {token}'
```

## Task State APIs

### Get Task State

Retrieve the current state of a task by ID.

#### Endpoint

`GET /api/echo/v1/tasks/{id}`

#### Parameters

- `id` (string): The unique identifier for the task in the URL path.

#### Responses

- 200 OK

  ```json
  {
      "state": "running",
      "create_ts": 1723108781,
      "update_ts": 1723108781,
      "request_id": "KscTYPMYiMUjCjJleHLauR0y",
      "owner": "ocie",
      "command_type": "DeployCommand",
      "ref_id": "bjGP9ygRMew",
      "error": "",
      "result": null,
      "location": "/api/echo/v1/tasks/KscTYPMYiMUjCjJleHLauR0y"
  }
  ```
- 404 Not Found

#### Example

```bash
curl -XGET "http://{flex}/api/echo/v1/tasks/KscTYPMYiMUjCjJleHLauR0y"
```

### List Tasks

Retrieve all tasks.

#### Endpoint

`GET /api/echo/v1/tasks`

#### Responses

- 200 OK

  ```json
  [
      {
          "state": "completed",
          "create_ts": 1723108781,
          "update_ts": 1723108981,
          "request_id": "KscTYPMYiMUjCjJleHLauR0y",
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
          "location": "/api/echo/v1/tasks/KscTYPMYiMUjCjJleHLauR0y"
      }
  ]
  ```

#### Example

```bash
curl -XGET "http://{flex}/api/echo/v1/tasks"
```
