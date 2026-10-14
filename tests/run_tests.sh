#!/usr/bin/env bash
# Regression tests. Shallow clone only; nothing is executed or extracted.
# Usage: tests/run_tests.sh [--offline]   (offline = local fixtures only)
cd "$(dirname "$0")/.." || exit 1
RG=./beagle; fail=0
check(){ # target expected-verdicts(regex) [extra args]
  local t=$1 exp=$2; shift 2
  local j; j=$(mktemp)
  $RG scan "$t" --no-color --json "$j" "$@" >/dev/null 2>&1
  local v; v=$(python3 -c "import json;print(json.load(open('$j'))['verdict'])" 2>/dev/null || echo ERROR)
  if [[ $v =~ ^($exp)$ ]]; then echo "PASS $v  $t"; else echo "FAIL $v (want $exp)  $t"; fail=1; fi
  rm -f "$j"
}
check tests/fixtures/trap-npm   RED
check tests/fixtures/trap-skill RED
if [[ "${1:-}" != "--offline" ]]; then
  check https://github.com/psf/requests                              "GREEN|YELLOW"
  check https://github.com/tj/commander.js                           "GREEN|YELLOW"
  check https://github.com/invariantlabs-ai/mcp-injection-experiments RED      # MCP tool poisoning
  check https://github.com/juice-shop/juice-shop                     YELLOW   # control: vulnerable, not malicious
  check https://github.com/DataDog/malicious-software-packages-dataset "YELLOW|RED" --no-osv  # zips listed via ls-tree, never downloaded
fi
exit $fail
