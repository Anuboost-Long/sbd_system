#!/usr/bin/env bash
# Print the evidence queries (database/evidence_queries.sql) from the SQL container.
set -euo pipefail
cd "$(dirname "$0")/.."
docker exec sql_server_container mkdir -p /tmp/db && docker cp database/. sql_server_container:/tmp/db
docker exec sql_server_container /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa \
  -P "$(grep -m1 '^MSSQL_SA_PASSWORD=' .env | cut -d= -f2-)" -C -b -I -W -i /tmp/db/evidence_queries.sql
