# Database Forensics & Security

## SQL Databases

### MySQL/MariaDB

#### Key Artifacts
```
/var/log/mysql/ - MySQL logs
/var/lib/mysql/ - Data directory
~/.mysql_history - Command history

# Important tables
mysql.user - User accounts
mysql.db - Database permissions
mysql.tables_priv - Table permissions
information_schema - Metadata
```

#### Forensic Queries
```sql
-- Find user accounts
SELECT user, host, plugin FROM mysql.user;

-- Find recent queries
SHOW GENERAL LOGS;
SHOW BINLOG EVENTS;

-- Find privileges
SHOW GRANTS FOR 'user'@'host';

-- Find created databases
SELECT * FROM mysql.general_log;
```

### PostgreSQL

#### Key Artifacts
```
/var/log/postgresql/ - PostgreSQL logs
/var/lib/postgresql/ - Data directory
~/.psql_history - PSQL history

# Important tables
pg_catalog.pg_user - User accounts
pg_catalog.pg_database - Databases
information_schema - Metadata
```

#### Forensic Queries
```sql
-- Find all users
SELECT usename, usesysid, usertype FROM pg_catalog.pg_user;

-- Find database connections
SELECT * FROM pg_stat_activity;

-- Find recent queries
SELECT * FROM pg_stat_statements ORDER BY total_time DESC;

-- Find user privileges
SELECT * FROM information_schema.usage_priviliges;
```

### Microsoft SQL Server

#### Key Artifacts
```
C:\Program Files\Microsoft SQL Server\MSSQL\LOG - Error logs
C:\Program Files\Microsoft SQL Server\MSSQL\Data - Data files

# Important tables
sys.server_principals - Server logins
sys.database_principals - Database users
fn_dblog() - Transaction log
fn_dump_dblog() - Full transaction log
```

#### Forensic Queries
```sql
-- Find login attempts
SELECT * FROM sys.dm_exec_sessions WHERE login_name = 'sa';

-- Find recent queries
SELECT * FROM sys.dm_exec_sql_text(sql_handle);

-- Find failed logins
SELECT * FROM sys.dm_exec_connections WHERE net_transport = 'TCP';

-- Transaction log
SELECT * FROM fn_dblog(NULL, NULL);
```

## NoSQL Databases

### MongoDB

#### Key Artifacts
```
/var/log/mongodb/ - MongoDB logs
/var/lib/mongodb/ - Data directory

# Important collections
system.users - User accounts
system.version - Version info
```

#### Forensic Queries
```javascript
// Find user accounts
db.system.users.find()

// Find recent operations
db.adminCommand({ replSetGetStatus: 1 })

// Find current connections
db.serverStatus().connections
```

### Redis

#### Key Artifacts
```
/var/log/redis/ - Redis logs
/var/lib/redis/ - Data directory
```

#### Forensic Commands
```bash
# Get all keys
KEYS *

# Get config
CONFIG GET *

# Get client list
CLIENT LIST

# Get monitor logs
MONITOR
```

### Elasticsearch

#### Key Artifacts
```
/var/log/elasticsearch/ - ES logs
/var/lib/elasticsearch/ - Data directory
```

#### Forensic Queries
```bash
# Get cluster health
GET _cluster/health

# Get indices
GET _cat/indices

# Search logs
GET /logstash-*/_search
{
  "query": { "match_all": {} },
  "sort": [{ "@timestamp": "desc" }],
  "size": 100
}
```

## Database Security

### Common Vulnerabilities
| Vulnerability | Description | Prevention |
|--------------|-------------|------------|
| SQL Injection | User input in queries | Parameterized queries |
| Weak Auth | Default credentials | Strong passwords, MFA |
| Overprivileged Users | Too many permissions | Least privilege |
| Unencrypted Data | Data at rest | Encryption |
| Cleartext Passwords | Passwords in config | Secrets management |

### Hardening Checklist
- [ ] Change default credentials
- [ ] Enable SSL/TLS
- [ ] Implement least privilege
- [ ] Enable audit logging
- [ ] Regular security patches
- [ ] Network segmentation
- [ ] Backups verified

### Database Firewalls
- **MySQL**: GreenSQL
- **PostgreSQL**: pgSQL firewall
- **Oracle**: Oracle Database Firewall
- **MongoDB**: MongoDB Atlas

## Database Forensics Tools

### Extraction Tools
- **MySQL**: mysqlbinlog
- **PostgreSQL**: pg_resetwal
- **SQL Server**: ApexSQL
- **MongoDB**: mongodump

### Log Analysis
- **MySQL**: MariaDB Audit Plugin
- **PostgreSQL**: pgaudit
- **SQL Server**: SQL Server Audit

## Database Recovery

### Point-in-Time Recovery
```bash
# PostgreSQL
pg_restore -h localhost -U postgres -d dbname backup.dump

# MySQL
mysqlbinlog binlog.000001 | mysql -u root -p

# SQL Server
RESTORE LOG database FROM DISK = 'backup.trn' WITH STOPAT = '2024-01-01 12:00:00'
```

## Database Security Tools

### Vulnerability Scanners
- **Nessus**: Database plugins
- **OpenVAS**: Database checks
- **SQLMap**: SQL injection
- **BBR**: Blind Blob Recovery

### Monitoring
- **MySQL**: MySQL Enterprise Monitor
- **PostgreSQL**: pgAdmin, Datadog
- **SQL Server**: SQL Monitor

## Common Attack Patterns

### SQL Injection
```sql
-- Basic
' OR '1'='1

-- Union based
UNION SELECT username, password FROM users--

-- Error based
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--

-- Time based
' AND SLEEP(5)--
```

### NoSQL Injection
```javascript
// MongoDB
{"$ne": null}
{"$gt": ""}
{"$where": "this.password.length > 1"}
```

### Default Credentials
| Database | Default User | Default Password |
|----------|-------------|-----------------|
| MySQL | root | (none) |
| PostgreSQL | postgres | (none) |
| MongoDB | (none) | (none) |
| Redis | (none) | (none) |
| Elasticsearch | elastic | changeme |
