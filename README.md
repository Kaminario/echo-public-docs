# Silk Echo

Silk Echo provides a robust solution for creating application and crush consistent snapshots of databases. With this capability, you can capture a database’s state on one host and create a copy on another host. This process can be performed manually or automated to ensure efficient, error-free database replication.

## Prerequisites

To use Silk Echo, ensure the following prerequisites are met:

- **Flex** is installed.
- **Source Host**: Running Windows Server with MSSQL and the original database.
- **Destination Host**: Running Windows Server with MSSQL.
- **Communication**: Both hosts must be able to connect to the Flex server and the SDP REST API.
- **Silk VSS**: Installed and configured on both hosts.

### Setup Steps

1. **Register the Source Host** in Flex (host with the original MSSQL database).
2. **Install Silk Agent** on the source host.
3. **Register the Destination Host** in Flex (host where the database will be restored).
4. **Install Silk Agent** on the destination host.

## Cloning a Database

After setting up the hosts, you can clone a database using the following steps:

1. *(Optional)* Use the **Echo API** to discover registered hosts and their databases.
2. Call **Flex** to clone a database from the source host to the destination host.

Most of these actions are long-running operations that can be monitored via the **Tasks API**.

---

## Authentication

Flex uses **Bearer Token Authentication**.

### Example:
```bash
curl -XGET "http://{flex}/{path}" -H "Authorization: Bearer {token}"
```
The authentication token is obtained when registering a host in Flex.

---

## Operation Tracking

A unique header parameter can be set to facilitate tracking operations.

### Header:
- `hs-ref-id` (string): A short identifier (6-8 characters) using the format `[a-zA-Z0-9]`.

### Example:
```bash
curl -XGET "http://{flex}/{path}" -H "hs-ref-id: Hy6f50Ki"
```

---

## API Reference

### **Topology API**
| Method | Path                  | Description                                   |
|--------|-----------------------|-----------------------------------------------|
| GET    | /api/ocie/v1/topology | Retrieve the full host > database > snapshot topology |

### **Host Management APIs**
| Method | Path                         | Description           |
|--------|------------------------------|-----------------------|
| PUT    | /flex/api/v1/hosts/{host_id} | Register a host       |
| DELETE | /flex/api/v1/hosts/{host_id} | Unregister a host     |
| GET    | /flex/api/v1/hosts/{host_id} | Retrieve host info    |
| GET    | /flex/api/v1/hosts           | Get all registered hosts info |

### **Database Cloning APIs**
| Method | Path                    | Description                                      |
|--------|-------------------------|--------------------------------------------------|
| POST   | /flex/api/v1/ocie/clone | Create a snapshot and clone it to a destination host |
| DELETE | /flex/api/v1/ocie/clone | Delete a clone                                   |

### **Snapshot APIs**
| Method | Path                                 | Description                                    |
|--------|-------------------------------------|------------------------------------------------|
| POST   | /flex/api/v1/db_snapshots          | Create a database snapshot                     |
| DELETE | /flex/api/v1/db_snapshots/{id}     | Delete a snapshot                              |
| POST   | /flex/api/v1/db_snapshots/{id}/clone | Clone a database from a snapshot to a host |

### **Tasks API**
| Method | Path                         | Description             |
|--------|-----------------------------|-------------------------|
| GET    | /flex/api/v1/ocie/tasks/{id} | Retrieve task info      |
| GET    | /flex/api/v1/ocie/tasks      | Get all tasks info      |

---

## Host Management

### Register a Host

#### Endpoint:
```http
PUT /flex/api/v1/hosts/{host_id}
```

#### Request Body:
```json
{
  "db_vendor": "mssql"
}
```

#### Parameters:
- `host_id` (string): Unique identifier for the host.
- `db_vendor` (string): Database vendor (currently only `mssql` is supported).

#### Example:
```bash
curl -XPUT "http://{flex}/flex/api/v1/hosts/{host_id}" \
-H "Authorization: Bearer {token}" \
-d'{"db_vendor": "mssql"}'
```

---

## Database Cloning

### Clone a Database

#### Endpoint:
```http
POST /flex/api/v1/ocie/clone
```

#### Request Body:
```json
{
  "source_host_id": "host02",
  "database_ids": ["5"],
  "destinations": [
    {
      "host_id": "host03",
      "db_id": "5",
      "db_name": "employees_copy_05"
    }
  ]
}
```

#### Example:
```bash
curl -XPOST "http://{flex}/flex/api/v1/ocie/clone" \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer {token}" \
-d'{
  "source_host_id": "host01",
  "database_ids": ["5"],
  "destinations": [{
    "host_id": "host02",
    "db_id": "5",
    "db_name": "employees_copy_05"
  }]
}'
```

---

## Snapshot Management

### Create a Snapshot

#### Endpoint:
```http
POST /flex/api/v1/db_snapshots
```

#### Request Body:
```json
{
  "source_host_id": "host01",
  "database_ids": ["5", "6"],
  "name_prefix": "snap_v10",
  "consistency_level": "application"
}
```

#### Example:
```bash
curl -XPOST "http://{flex}/flex/api/v1/db_snapshots" \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer {token}" \
-d'{"source_host_id":"host01","database_ids":["5","6"],"name_prefix":"snap_v10", "consistency_level": "application"}'
```

---

## Task Tracking

### Get Task Status

#### Endpoint:
```http
GET /flex/api/v1/ocie/tasks/{request_id}
```

#### Example:
```bash
curl -XGET "http://{flex}/flex/api/v1/ocie/tasks/KscTYPMYiMUjCjJleHLauR0y"
```

---

## Conclusion
Silk Echo simplifies database cloning and snapshot management with a structured API. By integrating these capabilities, organizations can ensure consistent, efficient, and automated database replication processes.


