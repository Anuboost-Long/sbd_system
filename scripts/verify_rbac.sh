#!/usr/bin/env bash
# Run database/verify_rbac.sql inside the SQL container; every line should say PASS (evidence for R4).
set -euo pipefail
cd "$(dirname "$0")/.."
docker exec sql_server_container mkdir -p /tmp/db && docker cp database/. sql_server_container:/tmp/db
docker exec sql_server_container /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa \
  -P "$(grep -m1 '^MSSQL_SA_PASSWORD=' .env | cut -d= -f2-)" -C -b -I -i /tmp/db/verify_rbac.sql
