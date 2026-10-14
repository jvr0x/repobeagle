#!/usr/bin/env python3
"""Offline unit tests for the startup banner (no network, no scanners)."""
import argparse, contextlib, io, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import repobeagle as rb

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    fail |= not ok

plain, colored = rb.banner(False), rb.banner(True)
check("fits 79 columns", max(map(len, plain.splitlines())) <= 79)
check("plain has no ANSI codes", "\033" not in plain)
check("colored strips to plain", re.sub(r"\033\[[0-9;]*m", "", colored) == plain)
check("tagline present", rb.BANNER_TAG in plain)

# Banner goes to stderr only, so piped stdout reports stay clean. fetch() is stubbed to stop the scan early.
def stop(*_): raise RuntimeError("stop")
rb.fetch = stop
out, err = io.StringIO(), io.StringIO()
a = argparse.Namespace(target="x", strict=False, relaxed=False, keep=False, no_color=False)
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), contextlib.suppress(RuntimeError):
    rb.cmd_scan(a)
check("banner on stderr, not stdout", rb.BANNER_TAG in err.getvalue() and out.getvalue() == "")
check("no color when not a TTY", "\033" not in err.getvalue())
sys.exit(fail)
