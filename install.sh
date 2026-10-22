#!/bin/sh
# Installs sweep-and-secure from a GitHub release.
#
# Downloads sweep_and_secure.py and SHA256SUMS from the release, checks the
# script's SHA-256 against the sums file, and installs it as "sweep-and-secure"
# in a folder on your PATH. The script needs python3; TruffleHog and dotenvx are
# installed separately (see the README).
#
#   curl -sSfL https://github.com/voxgig/sweep-and-secure/releases/latest/download/install.sh | sh -s -- -b /usr/local/bin
#
# Options:
#   -b DIR   install into DIR (default: /usr/local/bin when writable, else ~/.local/bin)
#   -v TAG   install release TAG, e.g. v1.1.0 (default: the latest release)
#   -u URL   fetch the assets from this base URL instead of the GitHub release
#   -k       skip the checksum check (not recommended)
#   -h       show this help
set -eu

REPO="voxgig/sweep-and-secure"
NAME="sweep-and-secure"
FILE="sweep_and_secure.py"
BINDIR=""
TAG="latest"
BASE_URL=""
VERIFY=1

usage() {
    cat <<USAGE
Install $NAME from a GitHub release.

  curl -sSfL https://github.com/$REPO/releases/latest/download/install.sh | sh -s -- [options]

  -b DIR   install into DIR (default: /usr/local/bin when writable, else ~/.local/bin)
  -v TAG   install release TAG, e.g. v1.1.0 (default: the latest release)
  -u URL   fetch the assets from this base URL instead of the GitHub release
  -k       skip the checksum check (not recommended)
  -h       show this help
USAGE
}

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

while getopts "b:v:u:kh" opt; do
    case "$opt" in
        b) BINDIR="$OPTARG" ;;
        v) TAG="$OPTARG" ;;
        u) BASE_URL="$OPTARG" ;;
        k) VERIFY=0 ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

if [ -z "$BASE_URL" ]; then
    if [ "$TAG" = "latest" ]; then
        BASE_URL="https://github.com/$REPO/releases/latest/download"
    else
        case "$TAG" in v*) ;; *) TAG="v$TAG" ;; esac
        BASE_URL="https://github.com/$REPO/releases/download/$TAG"
    fi
fi

if [ -z "$BINDIR" ]; then
    if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        BINDIR=/usr/local/bin
    else
        BINDIR="${HOME:?}/.local/bin"
    fi
fi

fetch() {  # fetch URL DEST
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        die "need curl or wget"
    fi
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    fi
}

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t sweep-and-secure)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "Downloading $FILE from $BASE_URL ..."
fetch "$BASE_URL/$FILE" "$TMP/$FILE" || die "could not download $BASE_URL/$FILE (is there a release yet?)"

if [ "$VERIFY" = 1 ]; then
    fetch "$BASE_URL/SHA256SUMS" "$TMP/SHA256SUMS" || die "could not download $BASE_URL/SHA256SUMS; use -k to skip the check"
    expected="$(grep " $FILE\$" "$TMP/SHA256SUMS" | awk '{print $1}' | head -n 1)"
    [ -n "$expected" ] || die "SHA256SUMS has no entry for $FILE"
    actual="$(sha256 "$TMP/$FILE")"
    [ -n "$actual" ] || die "need sha256sum, shasum or openssl to check the download; use -k to skip the check"
    [ "$expected" = "$actual" ] || die "checksum mismatch for $FILE: expected $expected, got $actual"
    say "Checksum OK."
else
    say "Checksum check skipped (-k)."
fi

head -c 2 "$TMP/$FILE" | grep -q '#!' || die "downloaded file does not look like the script"

mkdir -p "$BINDIR" 2>/dev/null || die "cannot create $BINDIR"
[ -w "$BINDIR" ] || die "cannot write to $BINDIR (try: -b \$HOME/.local/bin, or run with sudo)"
cp "$TMP/$FILE" "$BINDIR/$NAME.tmp.$$" && chmod 755 "$BINDIR/$NAME.tmp.$$" && mv -f "$BINDIR/$NAME.tmp.$$" "$BINDIR/$NAME"
say "Installed $BINDIR/$NAME"

if command -v python3 >/dev/null 2>&1; then
    say "  $("$BINDIR/$NAME" --version 2>&1 || true)"
else
    say "  python3 was not found on your PATH; the script needs Python 3.8 or newer to run."
fi
case ":${PATH:-}:" in
    *":$BINDIR:"*) ;;
    *) say "  $BINDIR is not on your PATH; add it, or run $BINDIR/$NAME directly." ;;
esac
say "Next: install TruffleHog and dotenvx (see https://github.com/$REPO#requirements), then check the setup with: $NAME --check-setup"
