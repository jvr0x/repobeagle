#!/usr/bin/env bash
# repo-guard installer: idempotent. Installs gitleaks, osv-scanner, semgrep, guarddog,
# vendors Semgrep registry rules for offline use, and builds the Docker image.
#   ./install.sh            # everything
#   ./install.sh --no-docker  # skip image build
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${REPO_GUARD_HOME:-$HOME/.local/share/repo-guard}"
BIN="${REPO_GUARD_BIN:-$HOME/.local/bin}"
GITLEAKS_FALLBACK="8.30.1"; OSV_FALLBACK="2.7.0"
BUILD_DOCKER=1; [[ "${1:-}" == "--no-docker" ]] && BUILD_DOCKER=0
mkdir -p "$PREFIX" "$BIN"
say(){ printf '\033[1;36m[repo-guard]\033[0m %s\n' "$*"; }

case "$(uname -m)" in
  aarch64|arm64) GL_ARCH=arm64; OSV_ARCH=arm64 ;;
  x86_64|amd64)  GL_ARCH=x64;   OSV_ARCH=amd64 ;;
  *) echo "Unsupported arch $(uname -m)"; exit 1 ;;
esac
say "arch: $(uname -m) (gitleaks=$GL_ARCH osv=$OSV_ARCH)"

latest(){ curl -fsSL "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["tag_name"].lstrip("v"))' 2>/dev/null || true; }

# gitleaks
if command -v gitleaks >/dev/null 2>&1; then say "gitleaks present: $(gitleaks version)"; else
  V="$(latest gitleaks/gitleaks)"; V="${V:-$GITLEAKS_FALLBACK}"
  say "installing gitleaks $V"
  T="$(mktemp -d)"; curl -fsSL -o "$T/gl.tgz" "https://github.com/gitleaks/gitleaks/releases/download/v$V/gitleaks_${V}_linux_${GL_ARCH}.tar.gz"
  tar -xzf "$T/gl.tgz" -C "$T" gitleaks && install -m 0755 "$T/gitleaks" "$BIN/gitleaks"; rm -rf "$T"
fi
# osv-scanner
if command -v osv-scanner >/dev/null 2>&1; then say "osv-scanner present: $(osv-scanner --version 2>&1 | head -1)"; else
  V="$(latest google/osv-scanner)"; V="${V:-$OSV_FALLBACK}"
  say "installing osv-scanner $V"
  curl -fsSL -o "$BIN/osv-scanner" "https://github.com/google/osv-scanner/releases/download/v$V/osv-scanner_linux_${OSV_ARCH}"
  chmod 0755 "$BIN/osv-scanner"
fi
# semgrep + guarddog in a private venv
if [[ ! -x "$PREFIX/venv/bin/guarddog" || ! -x "$PREFIX/venv/bin/semgrep" ]]; then
  say "creating venv with semgrep + guarddog in $PREFIX/venv"
  python3 -m venv "$PREFIX/venv"
  "$PREFIX/venv/bin/pip" install -q --upgrade pip
  "$PREFIX/venv/bin/pip" install -q semgrep guarddog
fi
for t in semgrep guarddog; do
  command -v "$t" >/dev/null 2>&1 && [[ "$(command -v $t)" != "$BIN/$t" ]] && { say "$t present on PATH"; continue; }
  ln -sf "$PREFIX/venv/bin/$t" "$BIN/$t"
done

# vendor Semgrep registry packs so scans work with no network
for p in security-audit secrets; do
  f="$HERE/rules/vendor/$p.yml"
  if [[ -s "$f" ]]; then say "rules/vendor/$p.yml cached"; else
    say "vendoring semgrep p/$p"; curl -fsSL "https://semgrep.dev/c/p/$p" -o "$f.tmp" && mv "$f.tmp" "$f"
  fi
done

# launcher
ln -sf "$HERE/repo-guard" "$BIN/repo-guard"; chmod +x "$HERE/repo-guard"

# validate
export PATH="$BIN:$PATH"
for t in gitleaks osv-scanner semgrep guarddog; do command -v "$t" >/dev/null || { echo "MISSING: $t"; exit 1; }; done
say "host tools OK"

if [[ $BUILD_DOCKER == 1 ]]; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    say "building docker image repo-guard-scanner (native arch)"
    docker build -t repo-guard-scanner "$HERE"
  else say "docker not available; scans will use --no-docker fallback"; fi
fi
case ":$PATH:" in *":$BIN:"*) ;; *) say "add $BIN to PATH";; esac
say "done. Try: repo-guard scan https://github.com/psf/requests"
