#!/usr/bin/env bash
# [Guide §3.2] Build the submission ZIP without secrets, build output, evidence or planning files.
# Why: .env holds the keys and passwords (risk R7); it must never be in the ZIP.
# Standard: OWASP ASVS 5.0 V16.
# Evidence: the listing check at the end fails the build if any .env file is inside.
set -euo pipefail
cd "$(dirname "$0")/.."
out="Ly_K_SBD403_A3_code.zip"
rm -f "$out"

zip -r "$out" . \
  -x ".env" ".env.*" "*/.env" "*/.env.*" \
  -x "*/bin/*" "*/obj/*" "bin/*" "obj/*" ".vs/*" ".idea/*" ".git/*" \
  -x "evidence/*" "project/ROADMAP.md" "project/MISMATCHES.md" "project/AGENTS.md" "project/*.docx" "sbd-web/*" "sbd-web/AGENTS.md" "sbd-web/CLAUDE.md" "certs/*" "publish/*" "report/*" "review_package/*" "*.zip" "sbd-web/.dev.log" "sbd-web/tsconfig.tsbuildinfo" ".vscode/*" ".config/*" "build_pack/*" "$out" \
  -x "*/node_modules/*" "*/.next/*" "*.DS_Store" "Log/*" "*/Log/*" >/dev/null
zip -d "$out" ".env.example" >/dev/null 2>&1 || true
zip "$out" .env.example >/dev/null

if unzip -Z1 "$out" | grep -E '(^|/)\.env($|\.)' | grep -v '\.env\.example$'; then
  rm -f "$out"; echo "FAIL: .env file found in ZIP" >&2; exit 1
fi
echo "OK: $out ($(unzip -Z1 "$out" | wc -l | tr -d ' ') files, no .env)"
