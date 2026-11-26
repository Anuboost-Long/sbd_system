#!/usr/bin/env bash
# [Guide §2.3] Make the demo certificate: ECDSA P-384, self-signed, valid for localhost.
# Why: the guide asks for ECDSA P-384 (or RSA 3072+) certificates; production uses a CA-signed one (deployment item).
# Standard: ASD ISM-1139, ISM-1369, ISM-1372.
# Evidence: evidence/tls-check.txt (E7).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p certs
openssl ecparam -name secp384r1 -genkey -noout -out certs/api-key.pem
openssl req -new -x509 -key certs/api-key.pem -sha384 -days 90 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -out certs/api-cert.pem
chmod 600 certs/api-key.pem
echo "OK: certs/api-cert.pem and certs/api-key.pem (demo only, git-ignored)"
