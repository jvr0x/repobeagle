#!/usr/bin/env bash
# Temp clone dirs must not leak on failure or signals. Uses an isolated TMPDIR.
cd "$(dirname "$0")/.." || exit 1
fail=0; T=$(mktemp -d); export TMPDIR=$T
left(){ ls -d "$T"/repobeagle-* 2>/dev/null | wc -l; }
./repobeagle scan https://github.com/jvr0x/this-repo-does-not-exist-404 --no-docker --no-osv --no-trust >/dev/null 2>&1
[[ $(left) == 0 ]] && echo "PASS cleanup after failing fetch" || { echo "FAIL $(left) temp dir(s) left after failing fetch"; fail=1; }
./repobeagle scan refusing:bad-target --no-docker >/dev/null 2>&1
[[ $(left) == 0 ]] && echo "PASS cleanup after rejected target" || { echo "FAIL temp dir left after rejected target"; fail=1; }
./repobeagle scan tests/fixtures/control-clean --no-docker --no-osv --no-trust >/dev/null 2>&1 & P=$!
for _ in $(seq 50); do [[ $(left) -gt 0 ]] && break; sleep 0.1; done
kill -TERM $P 2>/dev/null; wait $P 2>/dev/null
[[ $(left) == 0 ]] && echo "PASS cleanup after SIGTERM" || { echo "FAIL temp dir left after SIGTERM"; fail=1; }
./repobeagle scan tests/fixtures/control-clean --no-docker --no-osv --no-trust --keep >/dev/null 2>&1
[[ $(left) == 1 ]] && echo "PASS --keep keeps the clone" || { echo "FAIL --keep did not keep the clone"; fail=1; }
rm -rf "$T"; exit $fail
