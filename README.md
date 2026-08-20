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
- The SQL user configured for the Silk Agent (`sql_user`) must have permissions to perform the snapshot/backup operations on the target databases. When using application-consistent snapshots **without VSS** (SQL Server 2022 and later), the simplest working setup is to grant the user server-wide rights:

  ```sql
  GRANT CONTROL SERVER TO "silk_agent";
  ```

  This is broader than the strictly minimal set (`ALTER SETTINGS` plus `BACKUP DATABASE` granted inside each target database), but it lets the agent operate without maintaining per-database grants. Adding the login to the `sysadmin` role has the same effect.

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

| Method | Path                  | Description                                       |
| ------ | --------------------- | ------------------------------------------------- |
| GET    | /api/echo/v1/topology | Retrieve the full "host > db > snapshot" topology |

### **Host APIs**

| Method | Path                                        | Description                   |
| ------ | ------------------------------------------- | ----------------------------- |
| PUT    | /api/v1/hosts/{host_id}                     | Register a host               |
| DELETE | /api/v1/hosts/{host_id}                     | Unregister a host             |
| GET    | /api/v1/hosts/{host_id}                     | Retrieve host info            |
| GET    | /api/v1/hosts                               | Get all registered hosts info |
| GET    | /api/v1/hosts/{host_id}/databases           | List host databases           |
| GET    | /api/v1/hosts/{host_id}/databases/{db_id}   | Get database details          |

### **Refresh APIs**

| Method | Path                                             | Description                                 |
| ------ | ------------------------------------------------ | ------------------------------------------- |
| POST   | /api/echo/v1/hosts/{host_id}/databases/_refresh | replaces host dbs with dbs from a snapshot  |

### **Clone APIs**

| Method | Path                   | Description                                          |
| ------ | ---------------------- | ---------------------------------------------------- |
| POST   | /api/echo/v1/echo_dbs | Create a snapshot and clone it to a destination host |
| DELETE | /api/echo/v1/echo_dbs | Delete a clone                                       |

### **Snapshot APIs**

| Method | Path                                    | Description                                          |
| ------ | --------------------------------------- | ---------------------------------------------------- |
| GET    | /api/echo/v1/db_snapshots               | List all snapshots                                   |
| GET    | /api/echo/v1/db_snapshots/hosts/{host_id} | List snapshot IDs taken on a host                  |
| POST   | /api/echo/v1/db_snapshots               | Create a snapshot                                    |
| DELETE | /api/echo/v1/db_snapshots/{id}          | Delete a snapshot                                    |
| POST   | /api/echo/v1/db_snapshots/{id}/echo_db | Clone a database from an existing snapshot to a host |

### **Tasks APIs**

| Method | Path                    | Description                   |
| ------ | ----------------------- | ----------------------------- |
| GET    | /api/echo/v1/tasks/{id} | Retrieve task info            |
| GET    | /api/echo/v1/tasks      | Get all registered tasks info |

## Host APIs

### Register Host

#### Endpoint:

`PUT /api/v1/hosts/{host_id}`

#### Request Body:

```json
{
  "db_vendor": "mssql"
}
```

#### Parameters:

- `host_id` (string): The unique identifier for the host, typically the hostname. Must:
  - Start with a letter and end with a letter or number.
  - Only contain letters, numbers, underscores, and hyphens.
  - Be 3-32 characters in length.

  Example pattern: `^[a-zA-Z][a-zA-Z0-9_-]+[a-zA-Z0-9]$`

- `db_vendor` (string, optional): The database vendor for the host. Default: `"mssql"`.
  - Possible values: `mssql`, `oracledb`
- `sdp_id` (string, optional): The SDP the host is attached to. When omitted, Flex resolves it.
- `host_registration_date` (integer, optional): Unix timestamp of the registration. Defaults to the current time.

#### Example:

```bash
curl -XPUT "http://{flex}/api/v1/hosts/{host_id}" \
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

`DELETE /api/v1/hosts/{host_id}`

#### Responses:

- **204 No Content**

    The host was successfully unregistered (or did not exist).

#### Example:

```bash
curl -XDELETE "http://{flex}/api/v1/hosts/{host_id}" \
-H "Authorization: Bearer {token}"
```

### Get Host Info

#### Endpoint:

`GET /api/v1/hosts/{host_id}`

#### Responses:

- **200 OK**

  ```json
  {
      "host_id": "host01",
      "db_vendor": "mssql",
      "host_registration_date": 1722841000,
      "first_connection_ts": 1722841100,
      "last_seen_ts": 1722841284,
      "is_connected": true,
      "is_operational": true,
      "not_operational_reason": "",
      "host_name": "host_wfGIWX4",
      "host_iqn": "iqn.2009-01.com.kaminario:initiator.host_wfGIWX4",
      "host_os": "Windows",
      "host_os_version": "Windows 10",
      "agent_version": "1.1.17",
      "vss_version": "2.0.20",
      "db_engine_version": "16.0.1000.6",
      "cloud_vendor": "AZURE"
  }
  ```

  Selected fields:

  - `is_connected` (boolean): The agent is currently reporting in.
  - `is_operational` (boolean): The host is usable for Echo operations.
  - `not_operational_reason` (string): Why the host is not operational. Empty when it is.
  - `first_connection_ts` (integer): Unix timestamp of the first agent connection.
  - `agent_version` / `vss_version` (string): Installed Silk Node Agent and Silk VSS Provider versions.
  - `db_engine_version` (string): The database engine version reported by the agent.
  - `db_authentication_type` (string): How the agent authenticates to the database.
  - `vss_sdp_external_ip` (string): SDP address the VSS Provider uses.
  - `storage_type`, `device_management` (string): Oracle hosts only.

- **404 Not Found**

    Host does not exist.

#### Example:

```bash
curl -XGET "http://{flex}/api/v1/hosts/{host_id}" \
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
          "host_registration_date": 1722841000,
          "first_connection_ts": 1722841100,
          "last_seen_ts": 1722841284,
          "is_connected": true,
          "is_operational": true,
          "not_operational_reason": "",
          "host_name": "host_wfGIWX4",
          "host_iqn": "iqn.2009-01.com.kaminario:initiator.host_wfGIWX4",
          "host_os": "Windows",
          "host_os_version": "Windows 10",
          "agent_version": "1.1.17",
          "vss_version": "2.0.20",
          "db_engine_version": "16.0.1000.6",
          "cloud_vendor": "AZURE"
      }
  ]
  ```

  Each entry has the same shape as **Get Host Info**.

- **200 OK** (empty array if no hosts are registered)

  ```json
  []
  ```

#### Example:

```bash
curl -XGET "http://{flex}/api/v1/hosts" \
-H "Authorization: Bearer {token}"
```

### List Databases

List all databases on a specific host.

#### Endpoint:

`GET /api/v1/hosts/{host_id}/databases`

#### Parameters:

- `host_id` (string): The unique identifier for the host.

#### Responses:

- **200 OK**

  ```json
  [
      {
          "id": "5",
          "host_id": "host01",
          "name": "analytics",
          "vendor": "mssql",
          "status": "ONLINE",
          "mssql": {
              "files": [
                  {
                      "name": "analytics",
                      "file_id": 1,
                      "kind": "data",
                      "path": "E:\\Data\\analytics.mdf",
                      "size_mb": 1024,
                      "backup_status": "ACTIVE"
                  },
                  {
                      "name": "analytics_log",
                      "file_id": 2,
                      "kind": "log",
                      "path": "F:\\Logs\\analytics_log.ldf",
                      "size_mb": 256,
                      "backup_status": "ACTIVE"
                  }
              ]
          },
          "mount_points": [
              {
                  "kind": "disk",
                  "path": "E:\\",
                  "serial": "ABC123"
              },
              {
                  "kind": "disk",
                  "path": "F:\\",
                  "serial": "DEF456"
              }
          ]
      }
  ]
  ```

- **200 OK** (empty array if no databases)

  ```json
  []
  ```

#### Example:

```bash
curl -XGET "http://{flex}/api/v1/hosts/host01/databases" \
-H "Authorization: Bearer {token}"
```

### Get Database

Retrieve details of a specific database on a host.

#### Endpoint:

`GET /api/v1/hosts/{host_id}/databases/{db_id}`

#### Parameters:

- `host_id` (string): The unique identifier for the host.
- `db_id` (string): The unique identifier for the database.

#### Responses:

- **200 OK**

  ```json
  {
      "id": "5",
      "host_id": "host01",
      "name": "analytics",
      "vendor": "mssql",
      "status": "ONLINE",
      "mssql": {
          "files": [
              {
                  "name": "analytics",
                  "file_id": 1,
                  "kind": "data",
                  "path": "E:\\Data\\analytics.mdf",
                  "size_mb": 1024,
                  "backup_status": "ACTIVE"
              },
              {
                  "name": "analytics_log",
                  "file_id": 2,
                  "kind": "log",
                  "path": "F:\\Logs\\analytics_log.ldf",
                  "size_mb": 256,
                  "backup_status": "ACTIVE"
              }
          ]
      },
      "mount_points": [
          {
              "kind": "disk",
              "path": "E:\\",
              "serial": "ABC123"
          },
          {
              "kind": "disk",
              "path": "F:\\",
              "serial": "DEF456"
          }
      ]
  }
  ```

- **404 Not Found**

    Database does not exist on the specified host.

#### Example:

```bash
curl -XGET "http://{flex}/api/v1/hosts/host01/databases/5" \
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
  "consistency_level": "crash",
  "target_state": "online"
}
```

#### Parameters

- `source_host_id` (string, required): The unique identifier for the source host. Must not be empty.
- `destinations` (array of objects, required): A list of objects detailing the destination databases. Must not be empty.
  - `host_id` (string): The unique identifier for the destination host.
  - `db_id` (string): The unique identifier of the database to clone.
  - `db_name` (string): The name of the destination database.
- `name_prefix` (string, optional): The prefix for the snapshot name. Default: `"snap"`.
  - Must start with a lowercase letter
  - Can contain lowercase letters, numbers, underscores, and hyphens
  - Length: 4-20 characters
  - Pattern: `^[a-z][a-z0-9_-]+$`
- `consistency_level` (string, optional): The consistency level for the snapshot. Default: `"application"`.
  - Possible values: `crash`, `application`
- `target_state` (string, optional): The target state for the cloned database. Default: `"online"`.
  - Possible values: `recovery`, `online`
- `use_vss` (boolean, optional): Use VSS for the application-consistent snapshot where the
  database engine supports it. Default: `true`. Ignored when `consistency_level` is `crash`.
- `backup_session_timeout_sec` (integer, optional): Timeout for the backup phase, in seconds.
- `restore_session_timeout_sec` (integer, optional): Timeout for the restore phase, in seconds.

#### Responses

- 202 Accepted

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
# This example uses default values for optional parameters:
# - name_prefix defaults to "snap"
# - consistency_level is explicitly set to "crash" (default is "application")
# - target_state defaults to "online"
# - use_vss defaults to true

curl -XPOST "http://{flex}/api/echo/v1/echo_dbs" \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer {token}" \
-d'{
  "source_host_id": "host01",
  "destinations": [
    {
      "host_id": "host02",
      "db_id": "5",
      "db_name": "employees_copy_05"
    }
  ],
  "consistency_level": "crash"
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
    "database_id":"6",
    "cascade": false
}
```

#### Parameters
  - `host_id` (string): The unique identifier for the host to delete from.
  - `database_id` (string): The unique identifier for the database to delete.
  - `cascade` (boolean, optional): Also delete everything that depends on this Echo DB.
    Default: `false`. Without it the delete is refused when dependents exist.
    The same flag works on the `/__validate` endpoint, so you can preview the cascade.

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

### Endpoint:

`POST /api/echo/v1/hosts/{host_id}/databases/_refresh`

### Validate

`POST /api/echo/v1/hosts/{host_id}/databases/_refresh/__validate`

#### Request Body:

```json
{
  "snapshot_id": "string",
  "db_names": [
    "string"
  ],
  "target_state": "online"
}
```

#### Parameters:

- `host_id` (string, required): The unique identifier for the host, typically the hostname. Must:
  - Start with a letter and end with a letter or number.
  - Only contain letters, numbers, underscores, and hyphens.
  - Be 3-32 characters in length.

  Example pattern: `^[a-zA-Z][a-zA-Z0-9_-]+[a-zA-Z0-9]$`

- `snapshot_id` (string, required): The unique identifier for the database snapshot.
- `db_names` (array of strings, required): The names of the databases on the host to be replaced.
- `target_state` (string, optional): The target state for the refreshed database. Default: `"online"`.
  - Possible values: `recovery`, `online`

#### Example:

```bash
curl -XPOST "http://{flex}/api/echo/v1/hosts/{host_id}/databases/_refresh" \
-H "Authorization: Bearer {token}" \
-d'{"snapshot_id":"snap_1735025906","db_names": ["dev_db","dev_db2"]}'
```

#### Responses:

Following response example has a result field. This field will have a value only after operation completion. See: **Task State APIs**

- 202 Accepted

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

### List DB Snapshots

Retrieve all database snapshots.

#### Endpoint

`GET /api/echo/v1/db_snapshots`

#### Responses

- 200 OK

  ```json
  [
      {
          "id": "primary__5__1735025906",
          "host_id": "primary",
          "host_name": "primary",
          "sdp_id": "sdp-001",
          "vg_snapshot_ids": [101, 102],
          "databases": [
              {
                  "db_id": "5",
                  "db_name": "analytics",
                  "is_echo_db": false
              },
              {
                  "db_id": "6",
                  "db_name": "reporting",
                  "is_echo_db": false
              }
          ],
          "timestamp": 1735025906,
          "consistency_level": "application",
          "db_engine_version": "16.0.1000.6",
          "db_vendor": "mssql",
          "is_vss_based": true,
          "deletable": false,
          "uses_count": 2
      },
      {
          "id": "daily_1735100000",
          "host_id": "primary",
          "host_name": "primary",
          "sdp_id": "sdp-001",
          "vg_snapshot_ids": [103],
          "databases": [
              {
                  "db_id": "7",
                  "db_name": "inventory",
                  "is_echo_db": false
              }
          ],
          "timestamp": 1735100000,
          "consistency_level": "crash",
          "db_engine_version": "16.0.1000.6",
          "db_vendor": "mssql",
          "is_vss_based": false,
          "deletable": true,
          "uses_count": 0
      }
  ]
  ```

- 200 OK (empty array if no snapshots)

  ```json
  []
  ```

#### Response Fields

- `id` (string): The unique identifier for the snapshot.
- `host_id` (string): The identifier of the host where the snapshot was taken.
- `host_name` (string): The name of the host.
- `sdp_id` (string): The SDP identifier associated with the snapshot.
- `vg_snapshot_ids` (array of integers): Volume group snapshot identifiers.
- `databases` (array of objects): List of databases included in the snapshot.
  - `db_id` (string): The database identifier.
  - `db_name` (string): The database name.
  - `is_echo_db` (boolean): The database was itself an Echo DB (a clone) when snapshotted.
- `timestamp` (integer): Unix timestamp when the snapshot was created.
- `consistency_level` (string): The consistency level. Values: `crash`, `application`.
- `db_engine_version` (string): The database engine version.
- `db_vendor` (string): The database vendor. Values: `mssql`, `oracledb`.
- `is_vss_based` (boolean): Whether the snapshot was created using VSS.
- `deletable` (boolean): The snapshot can be deleted now. `false` when Echo DBs still
  depend on it, or when the underlying SDP snapshot is locked.
- `uses_count` (integer): How many Echo DBs were cloned from this snapshot.

#### Example

```bash
curl -XGET "http://{flex}/api/echo/v1/db_snapshots" \
-H "Authorization: Bearer {token}"
```

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

- `source_host_id` (string, required): The unique identifier for the source host.
- `database_ids` (list of strings, required): The unique identifiers for the databases to snapshot. Must not be empty.
- `name_prefix` (string, optional): The prefix for the snapshot name. Default: `"snap"`.
  - Must start with a lowercase letter
  - Can contain lowercase letters, numbers, underscores, and hyphens
  - Length: 4-20 characters
  - Pattern: `^[a-z][a-z0-9_-]+$`
- `consistency_level` (string, optional): The consistency level for the snapshot. Default: `"application"`.
  - Possible values: `crash`, `application`
- `use_vss` (boolean, optional): Use VSS for the application-consistent snapshot where the
  database engine supports it. Default: `true`. Ignored when `consistency_level` is `crash`.
- `backup_session_timeout_sec` (integer, optional): Timeout for the backup phase, in seconds.

#### Responses

- 202 Accepted

  ```json
  {
      "state": "completed",
      "create_ts": 1735025889,
      "update_ts": 1735025908,
      "request_id": "Fj3U7QTsDDWL45ikk0bvk2tsanfC3H",
      "owner": "ocie-0",
      "command_type": "CreateVssDbSnapshotCommand",
      "ref_id": "ADD62kMoLB",
      "error": "",
      "result": {"db_snapshot": {"id": "primary__5__1735025906"}},
      "location": "/api/echo/v1/tasks/Fj3U7QTsDDWL45ikk0bvk2tsanfC3H"
  }
  ```

  `command_type` depends on how the snapshot was captured:
  `CreateVssDbSnapshotCommand`, `CreateGenericDBSnapshotCommand`, or
  `CreateDBSnapshotCrashLevelCommand`.

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

`POST /api/echo/v1/db_snapshots/{db_snapshot_id}/echo_db`

##### Validate
The request can be validated without actually being executed,
by calling the same request with "/__validate" at the end of the endpoint

`POST /api/echo/v1/db_snapshots/{db_snapshot_id}/echo_db/__validate`

#### Request Body

```json
{
    "destinations": [
        {
            "host_id": "host02",
            "db_id": "5",
            "db_name": "db_name"
        }
    ],
    "target_state": "online"
}
```

#### Parameters

- `db_snapshot_id` (string, required): The unique identifier for the database snapshot.
- `destinations` (array of objects, required): A list of objects detailing the destination databases:
  - `host_id` (string): The unique identifier for the destination host.
  - `db_id` (string): The unique identifier for the database.
  - `db_name` (string): The name of the destination database.
- `target_state` (string, optional): The target state for the cloned database. Default: `"online"`.
  - Possible values: `recovery`, `online`

#### Responses

- 202 Accepted

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
-H "Authorization: Bearer {token}" \
-d'{"destinations":[{"host_id":"dev-2","db_id":"10","db_name":"alala"}]}'
```

### Delete DB Snapshot

Deletes a DB Snapshot. By default a DB Snapshot can only be deleted when no cloned
databases were created from it. Pass `cascade` to delete the dependent Echo DBs as well.

This endpoint creates a task. Poll it with the **Task State APIs** to see the result.

#### Endpoint

`DELETE /api/echo/v1/db_snapshots/{db_snapshot_id}`

##### Validate
The request can be validated without actually being executed,
by calling the same request with "/__validate" at the end of the endpoint

`DELETE /api/echo/v1/db_snapshots/{db_snapshot_id}/__validate`

#### Request Body

The body is optional. Send it only to request a cascade delete.

```json
{
    "cascade": false
}
```

#### Parameters

- `db_snapshot_id` (string, required): The unique identifier for the database snapshot.
- `cascade` (boolean, optional): Also delete every Echo DB cloned from this snapshot.
  Default: `false`. Without it the delete is refused when dependents exist.
  The same flag works on the `/__validate` endpoint, so you can preview the cascade.

#### Responses

- 200 OK

  ```json
  {
      "state": "running",
      "create_ts": 1735049892,
      "update_ts": 1735049892,
      "request_id": "Kk2sT9pQvXm4LbNc7dRfWy",
      "owner": "ocie-0",
      "command_type": "DeleteDbSnapshotCommand",
      "ref_id": "ECHO1a2b3c",
      "error": "",
      "result": null,
      "location": "/api/echo/v1/tasks/Kk2sT9pQvXm4LbNc7dRfWy"
  }
  ```

#### Example

```bash
curl -XDELETE "http://{flex}/api/echo/v1/db_snapshots/primary__10__1735028786" -H 'Authorization: Bearer {token}'

# cascade: also delete the Echo DBs cloned from this snapshot
curl -XDELETE "http://{flex}/api/echo/v1/db_snapshots/primary__10__1735028786" \
-H 'Content-Type: application/json' \
-H 'Authorization: Bearer {token}' \
-d'{"cascade": true}'
```

### List Host DB Snapshots

List the IDs of all snapshots taken on a specific host.

#### Endpoint

`GET /api/echo/v1/db_snapshots/hosts/{host_id}`

#### Parameters

- `host_id` (string, required): The unique identifier for the host.

#### Responses

- 200 OK

  ```json
  {
      "db_snapshot_ids": ["primary__5__1735025906", "primary__6__1735100000"]
  }
  ```

#### Example

```bash
curl -XGET "http://{flex}/api/echo/v1/db_snapshots/hosts/primary" \
-H "Authorization: Bearer {token}"
```

## Task State APIs

### Get Task State

Retrieve the current state of a task by ID.

#### Endpoint

`GET /api/echo/v1/tasks/{request_id}`

#### Parameters

- `request_id` (string): The unique identifier for the task.

#### Responses

- 200 OK

  ```json
  {
      "state": "running",
      "create_ts": 1723108781,
      "update_ts": 1723108781,
      "request_id": "KscTYPMYiMUjCjJleHLauR0y",
      "owner": "ocie",
      "command_type": "ImportDBSnapshotCommand",
      "ref_id": "bjGP9ygRMew",
      "error": "",
      "result": null,
      "location": "/api/echo/v1/tasks/KscTYPMYiMUjCjJleHLauR0y"
  }
  ```
- 404 Not Found

#### Example

```bash
curl -XGET "http://{flex}/api/echo/v1/tasks/KscTYPMYiMUjCjJleHLauR0y" \
-H "Authorization: Bearer {token}"
```

### List Tasks

Retrieve all tasks.

#### Endpoint

`GET /api/echo/v1/tasks`

#### Parameters

- `state` (string, optional): Query parameter. Return only tasks in this state.
  - Possible values: `running`, `completed`, `failed`, `aborted`

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
          "command_type": "ImportDBSnapshotCommand",
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
curl -XGET "http://{flex}/api/echo/v1/tasks" \
-H "Authorization: Bearer {token}"
```
