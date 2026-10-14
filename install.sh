#!/usr/bin/env bash
# repobeagle installer (idempotent).
#   ./install.sh                 pull prebuilt image ghcr.io/jvr0x/repobeagle:<VERSION> + install wrapper
#   ./install.sh --build-local   build the image locally from this folder instead of pulling
#   ./install.sh --local-tools   also install gitleaks/semgrep/guarddog/bandit on the host (for --no-docker fallback)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(tr -d '[:space:]' < "$HERE/VERSION" 2>/dev/null || true)"; VERSION="${VERSION:-v1.0.0}"
IMAGE="${BEAGLE_IMAGE:-ghcr.io/jvr0x/repobeagle:$VERSION}"
PREFIX="${BEAGLE_HOME:-$HOME/.local/share/repobeagle}"
BIN="${BEAGLE_BIN:-$HOME/.local/bin}"
BUILD_LOCAL=0; LOCAL_TOOLS=0
for a in "$@"; do case "$a" in --build-local) BUILD_LOCAL=1;; --local-tools) LOCAL_TOOLS=1;; *) echo "unknown option $a"; exit 1;; esac; done
say(){ printf '\033[1;36m[repobeagle]\033[0m %s\n' "$*"; }
mkdir -p "$BIN" "$PREFIX"
case "$(uname -m)" in
  aarch64|arm64) GL_ARCH=arm64; OSV_ARCH=arm64 ;;
  x86_64|amd64)  GL_ARCH=x64;   OSV_ARCH=amd64 ;;
  *) echo "Unsupported arch $(uname -m)"; exit 1 ;;
esac
latest(){ curl -fsSL "https://api.github.com/repos/$1/releases/latest" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["tag_name"].lstrip("v"))' 2>/dev/null || true; }

command -v git >/dev/null && command -v python3 >/dev/null || { echo "need git and python3"; exit 1; }

# 1) scanner image
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if [[ $BUILD_LOCAL == 1 ]]; then
    say "building $IMAGE locally ($(uname -m))"; docker build -t "$IMAGE" "$HERE"
  else
    say "pulling $IMAGE"
    docker pull "$IMAGE" || { echo "pull failed (check your network or Docker), or use --build-local"; exit 1; }
  fi
else
  say "Docker not available -> scans will run with host tools (--no-docker). Installing them."; LOCAL_TOOLS=1
fi

# 2) osv-scanner on the host (needs network for the vuln DB; reads lockfiles only)
if ! command -v osv-scanner >/dev/null 2>&1; then
  V="$(latest google/osv-scanner)"; V="${V:-2.7.0}"; say "installing osv-scanner $V ($OSV_ARCH)"
  curl -fsSL -o "$BIN/osv-scanner" "https://github.com/google/osv-scanner/releases/download/v$V/osv-scanner_linux_${OSV_ARCH}" && chmod 0755 "$BIN/osv-scanner"
fi

# 3) optional host tools for the no-docker fallback
if [[ $LOCAL_TOOLS == 1 ]]; then
  if ! command -v gitleaks >/dev/null 2>&1; then
    V="$(latest gitleaks/gitleaks)"; V="${V:-8.30.1}"; say "installing gitleaks $V ($GL_ARCH)"
    T="$(mktemp -d)"; curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v$V/gitleaks_${V}_linux_${GL_ARCH}.tar.gz" | tar -xz -C "$T" gitleaks
    install -m 0755 "$T/gitleaks" "$BIN/gitleaks"; rm -rf "$T"
  fi
  if [[ ! -x "$PREFIX/venv/bin/semgrep" || ! -x "$PREFIX/venv/bin/guarddog" || ! -x "$PREFIX/venv/bin/bandit" ]]; then
    say "installing semgrep + guarddog + bandit into $PREFIX/venv"
    python3 -m venv "$PREFIX/venv"; "$PREFIX/venv/bin/pip" install -q --upgrade pip semgrep guarddog bandit
  fi
  for t in semgrep guarddog bandit; do command -v $t >/dev/null 2>&1 || ln -sf "$PREFIX/venv/bin/$t" "$BIN/$t"; done
fi

# 4) thin wrapper
cat > "$BIN/repobeagle" <<WRAP
#!/usr/bin/env bash
export BEAGLE_IMAGE="\${BEAGLE_IMAGE:-$IMAGE}"
export PATH="$BIN:\$PATH"
exec python3 "$HERE/repobeagle.py" "\$@"
WRAP
chmod +x "$BIN/repobeagle"
grep -qs repobeagle.py "$BIN/beagle" && rm -f "$BIN/beagle"  # remove only our old wrapper
say "installed $BIN/repobeagle (image: $IMAGE)"
case ":$PATH:" in *":$BIN:"*) ;; *) say "add $BIN to your PATH";; esac
say "try: repobeagle scan https://github.com/psf/requests"
