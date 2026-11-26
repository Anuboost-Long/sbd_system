#!/usr/bin/env bash
# [Guide §5] Release checks: any failure stops the release.
# Why: authorisation tests, injection tests, dependency and secret checks run before every release (DevSecOps).
# Standard: NIST SP 800-218 (SSDF); OWASP SAMM.
# Evidence: run output of this script.
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "FAIL: $1" >&2; exit 1; }

echo "1/5 build with warnings as errors"
dotnet build -warnaserror >/dev/null || fail "build"

echo "2/5 tests (authorisation, injection, route matrix)"
dotnet test --no-build >/dev/null || fail "tests"

echo "3/5 vulnerable packages"
report=$(dotnet list package --vulnerable --include-transitive 2>&1)
echo "$report" | grep -qi "has the following vulnerable packages" && { echo "$report"; fail "vulnerable packages"; }

echo "4/5 raw SQL"
if grep -rnE "FromSqlRaw|ExecuteSqlRaw|SqlCommand" SBD.API SBD.API.Tests --include='*.cs' | grep -v "/obj/\|/bin/"; then
  fail "raw SQL found"
fi

echo "5/5 secrets"
if [ -d .git ] && git ls-files --error-unmatch .env >/dev/null 2>&1; then fail ".env is tracked by git"; fi
# connection-string style secrets (Password=value; or Pwd=value;) in source or config
if grep -rnEi "(password|pwd)=[^;\"{$ ]+" SBD.API SBD.API.Tests --include='*.cs' --include='*.json' | grep -v "/obj/\|/bin/"; then
  fail "connection-string password in source"
fi
# any real value from .env (12+ characters) appearing anywhere in the source tree
if [ -f .env ]; then
  while IFS= read -r value; do
    [ "${#value}" -ge 12 ] || continue
    case "$value" in 127.*|::*) continue;; esac
    if grep -rqF --exclude=".env*" --exclude="*.log" --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=bin --exclude-dir=obj -- "$value" SBD.API SBD.API.Tests sbd-web database scripts requests.http README.md 2>/dev/null; then
      fail "a value from .env appears in the source tree"
    fi
  done < <(grep -vE '^\s*(#|$)' .env | cut -d= -f2-)
fi

echo "OK: release checks passed"
