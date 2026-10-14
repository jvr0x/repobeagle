#!/usr/bin/env python3
"""Offline unit tests for trust signals (no network)."""
import datetime as D, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import repobeagle as rb

NOW = D.datetime(2026, 10, 14, tzinfo=D.timezone.utc)
ago = lambda d: (NOW - D.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
rules = lambda fs: {f["title"].split(":")[0] for f in fs}
fail = 0
def check(name, got, want, absent=()):
    global fail
    ok = want <= got and not (set(absent) & got)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  got={sorted(got)}"))
    fail |= not ok

sus = rb.trust_findings("evil/tool", {"full_name": "newowner/tool", "created_at": ago(10), "stargazers_count": 900, "forks_count": 1},
                        {"created_at": ago(20)}, 1, NOW)
check("suspicious repo", rules(sus), {"trust-signals", "repo-moved", "young-repo", "young-owner", "star-spike", "single-contributor"})
check("trust is LOW/INFO only", {f["severity"] for f in sus}, set(), absent={"medium", "high", "critical"})
v, _, _ = rb.verdict(sus, "strict", None)
check("never RED alone (strict)", {v}, {"YELLOW"})
ok = rb.trust_findings("psf/requests", {"full_name": "psf/requests", "created_at": ago(5000), "stargazers_count": 52000, "forks_count": 9000},
                       {"created_at": ago(6000)}, 700, NOW)
check("established repo", rules(ok), {"trust-signals"}, absent={"repo-moved", "young-repo", "young-owner", "star-spike", "single-contributor"})
check("non-github target skipped", {str(rb.trust_signals("/tmp/x"))}, {"([], None)"})
import os; os.environ["BEAGLE_GITHUB_API"] = "http://127.0.0.1:9"
fs, note = rb.trust_signals("https://github.com/a/b")
check("offline is graceful", {bool(note), len(fs)}, {True, 0})
sys.exit(fail)
