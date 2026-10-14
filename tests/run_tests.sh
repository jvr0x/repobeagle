#!/usr/bin/env bash
# Regression tests. Shallow clone only; nothing is executed or extracted.
# Usage: tests/run_tests.sh [--offline]   (offline = local fixtures only)
cd "$(dirname "$0")/.." || exit 1
RG=./repobeagle; fail=0
check(){ # target expected-verdicts(regex) [extra args]; RULES="a b" = rule names that must appear
  local t=$1 exp=$2; shift 2
  local j; j=$(mktemp)
  $RG scan "$t" --no-color --json "$j" "$@" >/dev/null 2>&1
  local v; v=$(python3 -c "import json;print(json.load(open('$j'))['verdict'])" 2>/dev/null || echo ERROR)
  if [[ $v =~ ^($exp)$ ]]; then echo "PASS $v  $t"; else echo "FAIL $v (want $exp)  $t"; fail=1; fi
  if [[ -n "${RULES:-}" ]]; then
    local miss; miss=$(python3 -c "import json,sys;t={f['title'].split(':')[0] for f in json.load(open('$j'))['findings']};print(' '.join(r for r in sys.argv[1:] if r not in t))" $RULES 2>/dev/null)
    if [[ -z $miss ]]; then echo "PASS rules  $t"; else echo "FAIL missing rules: $miss  $t"; fail=1; fi
  fi
  rm -f "$j"
}
check tests/fixtures/trap-npm   RED
check tests/fixtures/trap-skill RED
L="--no-osv --no-trust"
RULES="gha-pwn-request gha-secret-echo gha-curl-pipe-shell gha-privileged-trigger gha-write-permissions gha-unpinned-action" \
  check tests/fixtures/trap-gha "YELLOW|RED" $L
RULES="md-comment-instruction md-details-instruction md-alt-title-instruction md-css-hidden md-padded-line" \
  check tests/fixtures/trap-markdown "YELLOW|RED" $L
RULES="go-generate-fetch rust-build-rs node-gyp-action pip-build-hook install-time-fetch make-just-hooks" \
  check tests/fixtures/trap-build "YELLOW|RED" $L
RULES="magic-mismatch typosquat-dep high-entropy-blob minified-outside-dist" \
  check tests/fixtures/trap-binary "YELLOW|RED" $L
check tests/fixtures/trap-gha RED $L --strict
check tests/fixtures/control-clean GREEN $L --strict   # pinned actions, dist bundle, normal README, real deps
python3 tests/test_trust.py || fail=1
tests/test_cleanup.sh || fail=1
if [[ "${1:-}" != "--offline" ]]; then
  check https://github.com/psf/requests                              "GREEN|YELLOW"
  check https://github.com/tj/commander.js                           "GREEN|YELLOW"
  check https://github.com/invariantlabs-ai/mcp-injection-experiments RED      # MCP tool poisoning
  check https://github.com/juice-shop/juice-shop                     YELLOW   # control: vulnerable, not malicious
  check https://github.com/DataDog/malicious-software-packages-dataset "YELLOW|RED" --no-osv  # zips listed via ls-tree, never downloaded
fi
exit $fail
