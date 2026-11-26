#!/usr/bin/env bash
# Run the API in a Linux container so Kestrel can serve TLS 1.3 only (macOS .NET cannot), reachable at https://localhost:7443.
# Needs: certs from scripts/dev_cert.sh, SQL Server running on this machine, .env filled in.
# Demo-only settings for the container: the database host and the allowed caller addresses (Docker's bridge address for the host).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f certs/api-cert.pem ] || ./scripts/dev_cert.sh

dotnet publish SBD.API -c Release -o publish >/dev/null
gateway=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
callers="$gateway,192.168.65.1,192.168.65.254,172.17.0.1"

docker rm -f sbd_api >/dev/null 2>&1 || true
docker run -d --name sbd_api -p 127.0.0.1:7443:8443 \
  -v "$PWD/publish:/app:ro" -v "$PWD/certs:/certs:ro" -w /app \
  --env-file <(grep -vE '^\s*(#|$)' .env | sed -E 's/Server=localhost/Server=host.docker.internal/') \
  -e Security__AllowedIps="$callers" -e Security__AdminAllowedIps="$callers" \
  -e ASPNETCORE_URLS=https://+:8443 \
  -e Kestrel__Certificates__Default__Path=/certs/api-cert.pem \
  -e Kestrel__Certificates__Default__KeyPath=/certs/api-key.pem \
  mcr.microsoft.com/dotnet/aspnet:8.0 dotnet SBD.API.dll
echo "API starting at https://localhost:7443 (docker logs -f sbd_api)"
