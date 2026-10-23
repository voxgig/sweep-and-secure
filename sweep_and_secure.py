#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sweep_and_secure.py -- find plaintext API keys and secrets, then lock them up.

Scans the current folder (or a folder you name) and every sub-folder with
TruffleHog, shows you what it found, and -- only if you say yes -- encrypts
those secrets with dotenvx:

  * a secret inside a dotenv file (.env, .env.production, prod.env ...) is
    encrypted in place:
        STRIPE_KEY=sk_live_...        ->  STRIPE_KEY="encrypted:..."
  * a secret anywhere else (source code, JSON, YAML, Markdown ...) is moved
    into an encrypted entry of the project's .env file, and the plaintext in
    the original file is replaced by a placeholder:
        token = "sk_live_..."         ->  token = "${STRIPE_KEY}"

Usage
    python sweep_and_secure.py                  # interactive: scan, list, ask, encrypt
    python sweep_and_secure.py path/to/project  # sweep a different folder
    python sweep_and_secure.py --dry-run        # scan and list only, change nothing
    python sweep_and_secure.py --yes            # never ask (scripts / CI)
    python sweep_and_secure.py --help           # every option

Runs on Python 2.7 and Python 3.x and needs no third-party packages.
It needs TruffleHog (https://trufflesecurity.com/trufflehog) and dotenvx
(https://dotenvx.com) installed; if either is missing it says so and prints
where to get them.
"""
from __future__ import absolute_import, division, print_function

import argparse
import base64
import binascii
import bz2
import gzip
import hashlib
import io
import json
import mmap
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import zipfile
import zlib
from collections import OrderedDict, deque

try:
    import lzma
except ImportError:  # pragma: no cover - Python 2 without the backport
    lzma = None

__version__ = "1.5.1"

# --------------------------------------------------------------------------
# Python 2 / 3 compatibility
# --------------------------------------------------------------------------

PY2 = sys.version_info[0] == 2

if PY2:  # pragma: no cover - only runs under Python 2
    text_type = unicode  # noqa: F821
    binary_type = str
    read_line = raw_input  # noqa: F821
else:
    text_type = str
    binary_type = bytes
    read_line = input

FS_ENCODING = sys.getfilesystemencoding() or "utf-8"


def to_text(value, encoding="utf-8"):
    """Return value as text (unicode on 2, str on 3); bytes are decoded leniently."""
    if value is None:
        return u""
    if isinstance(value, text_type):
        return value
    if isinstance(value, binary_type):
        return value.decode(encoding, "replace")
    return text_type(value)


def to_bytes(value, encoding="utf-8"):
    if isinstance(value, binary_type):
        return value
    return to_text(value).encode(encoding)


def fs_text(path):
    """A filesystem path as text, whatever type the OS/argv handed us."""
    return to_text(path, FS_ENCODING)


RUN_LOG = None   # this run's RunLog once main() has opened it; say() copies every line into it
ANSI_RE = re.compile(u"\x1b\\[[0-9;]*m")


class RunLog(object):
    """One plain-text log per run, in a common folder, for debugging: everything printed
    (without colour), the prompts and answers, the tool commands and their diagnostics, the
    exit code. Secret values never go in: the run prints masked previews only, and the
    output of `dotenvx get` is never logged."""

    def __init__(self, path):
        self.path = path
        self.handle = io.open(path, "a", encoding="utf-8")
        self.lock = threading.Lock()

    def write(self, text, prefix=u""):
        stamp = time.strftime("%H:%M:%S")
        with self.lock:
            try:
                for line in to_text(text).split(u"\n"):
                    self.handle.write(u"%s %s%s\n" % (stamp, prefix, ANSI_RE.sub(u"", line)))
                self.handle.flush()
            except (IOError, OSError, ValueError):
                pass

    def close(self):
        try:
            self.handle.close()
        except (IOError, OSError, ValueError):
            pass


def log_only(text):
    """A line for the run log alone (commands, diagnostics), not for the screen."""
    if RUN_LOG is not None:
        RUN_LOG.write(text, u"| ")


def default_log_dir():
    """Where run logs go unless --log-dir or SWEEP_AND_SECURE_LOG_DIR says otherwise: the
    user's state folder, so that every run on this machine is found in one place."""
    chosen = os.environ.get("SWEEP_AND_SECURE_LOG_DIR")
    if chosen:
        return fs_text(chosen)
    home = fs_text(os.path.expanduser("~"))
    if os.name == "nt":
        base = fs_text(os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local"))
        return os.path.join(base, "sweep-and-secure", "logs")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Logs", "sweep-and-secure")
    base = fs_text(os.environ.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state"))
    return os.path.join(base, "sweep-and-secure", "logs")


def open_run_log(args, root):
    """Create this run's log file and drop this tool's oldest logs beyond LOG_KEEP: (RunLog or
    None, note). Only files named the way this tool names them are ever removed: a shared
    --log-dir can hold other programs' logs."""
    if args.no_log:
        return None, u""
    folder = fs_text(args.log_dir) if args.log_dir else default_log_dir()
    try:
        if not os.path.isdir(folder):
            os.makedirs(folder)
        stamp = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())
        label = re.sub(u"[^A-Za-z0-9_.-]+", u"_", os.path.basename(root) or u"root")[:40]
        log = RunLog(os.path.join(folder, u"%s-%s-%d.log" % (stamp, label, os.getpid())))
        logs = sorted(name for name in os.listdir(folder)
                      if RUN_LOG_NAME_RE.match(name) and name != os.path.basename(log.path))
        excess = len(logs) - (LOG_KEEP - 1)   # the new log is one of the LOG_KEEP kept
        for name in logs[:excess] if excess > 0 else []:
            try:
                os.remove(os.path.join(folder, name))
            except OSError:
                pass
        return log, u""
    except (IOError, OSError) as exc:
        return None, u"no run log: cannot write to %s (%s)" % (folder, to_text(str(exc)))


def say(text=u"", stream=None, log_text=None):
    """print() that never dies: odd terminal encodings, a closed pipe or a missing
    stdout (pythonw) must not take the run down half way through a rewrite. Every line
    also goes to the run log, when there is one (log_text in its place, when given)."""
    if RUN_LOG is not None:
        RUN_LOG.write(text if log_text is None else log_text,
                      u"" if (stream is None or stream is sys.stdout) else u"! ")
    stream = stream or sys.stdout
    if stream is None:
        return
    if PY2 and isinstance(text, text_type):  # pragma: no cover
        text = text.encode(getattr(stream, "encoding", None) or "utf-8", "replace")
    try:
        try:
            stream.write(text)
        except UnicodeEncodeError:
            encoding = getattr(stream, "encoding", None) or "ascii"
            stream.write(text.encode(encoding, "replace").decode(encoding, "replace"))
        stream.write("\n")
        stream.flush()
    except (IOError, OSError, ValueError):  # closed or broken stream
        pass


def configure_streams():
    """Ask Python 3.7+ to replace rather than choke on characters the console cannot show."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (ValueError, TypeError, AttributeError):  # pragma: no cover
                pass


# --------------------------------------------------------------------------
# The two tools we depend on
# --------------------------------------------------------------------------

TOOLS = OrderedDict([
    ("trufflehog", {
        "job": "finds the secrets",
        "links": [
            "https://trufflesecurity.com/trufflehog",
            "https://github.com/trufflesecurity/trufflehog#floppy_disk-installation",
        ],
        "install": [
            "brew install trufflehog",
            "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh"
            " | sh -s -- -b /usr/local/bin",
        ],
        "min_version": (3, 6, 0),
        "why_version": "TruffleHog 3.6 or newer is needed (JSON results that name the detector; 3.0 to 3.5"
                       " do not). Later options it may lack are worked around.",
    }),
    ("dotenvx", {
        "job": "encrypts the secrets",
        "links": [
            "https://dotenvx.com",
            "https://dotenvx.com/docs/install",
            "https://github.com/dotenvx/dotenvx",
        ],
        "install": [
            "curl -sfS https://dotenvx.sh | sh",
            "brew install dotenvx/brew/dotenvx",
            "npm install -g @dotenvx/dotenvx",
        ],
        "min_version": (1, 4, 0),
        "why_version": "dotenvx 1.4 or newer is needed (encrypt -k encrypts one key at a time; 1.0 rejects -k).",
    }),
])

# Paths TruffleHog should not bother with, and we should never rewrite. Regular
# expressions matched against the full path; TruffleHog sees the path as the OS
# spells it (backslashes on Windows), so both separators are accepted.
# Never scanned and never rewritten, whatever the options say:
QUARANTINE_DEFAULT = ".secrets-quarantine"   # where --quarantine puts archives, unless told otherwise
QUARANTINE_MANIFEST = "MANIFEST.txt"      # one line per moved file: when, where it is now, where it was
QUARANTINE_INDEX = "index.json"           # the same mapping as JSON, one record per moved file
LOG_KEEP = 100                            # run logs kept in the log folder (the newest)
QUARANTINE_KEYS_ENV = ".env"              # the quarantine's own dotenvx file: the passphrase of each *.enc
QUARANTINE_KEY_PREFIX = u"QUARANTINE_KEY_"
QUARANTINE_CIPHER = "aes-256-cbc"         # what `openssl enc` encrypts a quarantined file with
ENCRYPTED_SUFFIX = u".enc"
# A moved file never takes the name of the quarantine's own files (some file systems ignore case).
QUARANTINE_OWN_FILES = (QUARANTINE_MANIFEST.lower(), QUARANTINE_INDEX.lower(), QUARANTINE_KEYS_ENV, ".env.keys")
QUARANTINE_MANIFEST_HEADER = (
    u"# Files moved here by sweep-and-secure, one line each: when, stored name <- original path, detectors, why.\n"
    u"# A *.enc file is AES-256 encrypted (openssl enc); its passphrase is the QUARANTINE_KEY_* named on its line,\n"
    u"# kept in .env here, encrypted by dotenvx. Restore one:  sweep-and-secure --restore <stored name>\n"
    u"# or by hand, from inside this folder with the private key at hand (the OS store, or -fk <path to .env.keys>):\n"
    u"#   dotenvx get QUARANTINE_KEY_N -f .env | openssl enc -d -aes-256-cbc -pbkdf2 -pass stdin -in NAME.enc -out NAME\n"
    u"# (leave out -pbkdf2 for a line that says kdf legacy)\n")
OPENSSL_INFO = {}                         # path, version line and key derivation of the openssl this run uses
OPENSSL_WINDOWS_PLACES = (r"C:\Program Files\Git\usr\bin\openssl.exe", r"C:\Program Files\Git\mingw64\bin\openssl.exe",
                          r"C:\Program Files (x86)\Git\usr\bin\openssl.exe", r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
                          r"C:\Program Files\OpenSSL\bin\openssl.exe")
# How this tool names its log files; nothing else in the log folder is ever removed.
RUN_LOG_NAME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-.+-\d+\.log$")
# Package integrity hashes (npm "sha512-...", pip/Poetry "sha256:...", go.sum "h1:...") are long
# random-looking strings that loose detector regexes match. A finding that sits entirely inside
# one is a checksum, not a secret. A digest must have exactly its algorithm's length (base64:
# 27, 43, 64 or 86 characters before the padding for sha1, sha256, sha384, sha512; hex: 40, 64,
# 96 or 128) and end there, so that a longer random string is never taken for one.
INTEGRITY_HASH_RE = re.compile(br"(?:\bsha1-[A-Za-z0-9+/]{27}=?|\bsha256-[A-Za-z0-9+/]{43}=?"
                               br"|\bsha384-[A-Za-z0-9+/]{64}|\bsha512-[A-Za-z0-9+/]{86}={0,2}"
                               br"|\bh1:[A-Za-z0-9+/]{43}=?"
                               br"|\bsha1:[0-9a-fA-F]{40}|\bsha256:[0-9a-fA-F]{64}"
                               br"|\bsha384:[0-9a-fA-F]{96}|\bsha512:[0-9a-fA-F]{128})(?![A-Za-z0-9+/=])")
# The other long random strings a generated lock file is made of: bare checksums and commit ids, hex of
# a digest's length (a commit id, the sha1 URL fragment in yarn.lock, Cargo.lock's checksum, yarn berry's
# 10c0/...) or base64 of one (packages.lock.json's contentHash). TruffleHog's keyword detectors take
# them for tokens when a package is called cloudflare, sentry, datadog ... One is set aside only where
# it is seen to be public: a URL's fragment or path (LOCK_URL_CONTEXT_RE), a checksum, revision or
# reference field, a mix.lock entry (LOCK_FIELD_CONTEXT_RE), or an entry of a checksum section such as
# Podfile.lock's SPEC CHECKSUMS (LOCK_SECTION_RE on the header line); and never where it looks like a
# credential: a URL's user information (user:secret@host), after an equals sign (?token=secret) or after
# a telling word (LOCK_CREDENTIAL_RE). Anything else in a lock file stays a finding.
LOCK_DIGEST_RE = re.compile(br"(?<![0-9A-Za-z+=])(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{96}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}"
                            br"|[0-9a-fA-F]{32}|[A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{64}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{27}=)"
                            br"(?![0-9A-Za-z+/=])")
LOCK_CREDENTIAL_RE = re.compile(br"(?i)(?:token|passw(?:or)?d|pwd|secret|auth|api[_-]?key|access[_-]?key|private|credential)"
                                br"[^0-9A-Za-z]{0,8}$")
LOCK_URL_CONTEXT_RE = re.compile(br"://[^\s\"'<>]*(?:[#/]|[\"']\s*:\s*[\"'])$")   # ...tgz#<digest>, .../tar.gz/<digest>, "<url>": "<digest>"
LOCK_FIELD_CONTEXT_RE = re.compile(br"(?i)(?:integrity|checksum|hash|sha(?:1|256|384|512)?|md5|digest|reference|revision|\b[pr]?rev"
                                   br"|commit|resolved|resolution|version|shasum|head|signature|fingerprint)s?[\"']?\s*[:=]\s*[\"']?"
                                   br"(?:[0-9a-z]{1,8}[/:])?\s*$"
                                   br"|\{:(?:hex|git),")   # mix.lock: {:hex, :name, "1.0.0", "<checksum>", ...}
LOCK_SECTION_RE = re.compile(br"(?i)integrity|checksum|hash|digest|revision|commit|resolution|sha(?:1|256|384|512)?\b")

ALWAYS_EXCLUDES = [
    r"(^|[/\\])\.env\.keys(\.[^/\\]*)?$",   # dotenvx private keys: .env.keys, .env.keys.bak ... (files, not folders)
    r"(^|[/\\])\.env\.vault$",        # legacy dotenvx vault files
    r"(^|[/\\])\.sweep-and-secure-",   # our own staging files, left by an interrupted run
    r"(^|[/\\])\.secrets-quarantine([/\\]|$)",   # archives moved out of the way by --quarantine
]

# Archives TruffleHog looks inside: recognised by their first bytes, then by name.
ARCHIVE_MAGIC = [
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
]
ARCHIVE_EXTENSIONS = (".zip", ".jar", ".war", ".ear", ".apk", ".whl", ".egg", ".nupkg", ".tar", ".tgz",
                      ".gz", ".bz2", ".tbz2", ".xz", ".txz", ".7z", ".rar", ".zst", ".cab")
ZIP_KINDS = ("zip", "jar", "war", "ear", "apk", "whl", "egg", "nupkg")
TAR_OR_COMPRESSED_KINDS = ("tar", "tgz", "gzip", "gz", "bzip2", "bz2", "tbz2", "xz", "txz", "tar.gz", "tar.bz2", "tar.xz")
# Looking inside archives (which files hold the secrets TruffleHog reported):
INSPECT_MAX_DEPTH = 3                        # archives inside archives inside archives
INSPECT_BUDGET_BYTES = 512 * 1024 * 1024     # uncompressed content read per archive, at most
INSPECT_FULL_READ_BYTES = 64 * 1024 * 1024   # members up to this size are searched in memory
INSPECT_CHUNK = 4 * 1024 * 1024              # bigger members are searched in chunks of this size
# Compiled code: programs and libraries. A secret compiled into one cannot be fixed here, and moving
# the file breaks whatever uses it, while what an old TruffleHog matches in them is mostly symbol
# names and random bytes (TruffleHog 3.75 and later skip them itself). Recognised by name and by the
# first bytes; not scanned unless --scan-compiled, and then only listed.
COMPILED_EXTENSIONS = ("so", "dll", "dylib", "exe", "o", "a", "pyc", "pyo", "pyd", "class", "wasm", "node",
                       "ko", "ocx", "dex", "elf")   # not .sys, .obj, .lib: text files carry those names too
COMPILED_NAME_PATTERN = r"(?i)\.(%s)(?:\.\d+)*$" % "|".join(COMPILED_EXTENSIONS)   # libz.so.1.2 too
COMPILED_NAME_RE = re.compile(COMPILED_NAME_PATTERN)
COMPILED_MAGIC = [
    (b"\x7fELF", u"ELF binary"), (b"\xfe\xed\xfa\xce", u"Mach-O binary"), (b"\xce\xfa\xed\xfe", u"Mach-O binary"),
    (b"\xfe\xed\xfa\xcf", u"Mach-O binary"), (b"\xcf\xfa\xed\xfe", u"Mach-O binary"),
    (b"\xca\xfe\xba\xbe", u"Mach-O or Java class"), (b"\x00asm", u"WebAssembly module"),
]
TRUFFLEHOG_SKIPS_COMPILED = (3, 75, 0)   # measured: 3.70 reads an ELF library, 3.75 and later do not
# Skipped unless --no-default-excludes: version control, vendored and generated trees.
DEFAULT_EXCLUDES = [
    r"(^|[/\\])\.git([/\\]|$)",
    r"(^|[/\\])\.hg([/\\]|$)",
    r"(^|[/\\])\.svn([/\\]|$)",
    r"(^|[/\\])node_modules([/\\]|$)",
    r"(^|[/\\])__pycache__([/\\]|$)",
    r"(^|[/\\])\.venv([/\\]|$)",
    r"(^|[/\\])venv([/\\]|$)",
    r"(^|[/\\])\.tox([/\\]|$)",
]

TEMP_PREFIX = ".sweep-and-secure-"

# .env.example, .env.sample, template.env ...: placeholders for humans, not secrets to lock up.
EXAMPLE_ENV_WORDS = set("example sample template dist defaults tpl".split())

# Generated files that tooling checks or regenerates: a placeholder inside them breaks the
# tool, so the secret has to be removed by regenerating the file.
LOCKFILE_NAMES = set("""
    package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock bun.lockb
    poetry.lock pipfile.lock uv.lock pdm.lock cargo.lock composer.lock gemfile.lock
    mix.lock pubspec.lock packages.lock.json flake.lock .terraform.lock.hcl
    go.sum podfile.lock package.resolved cartfile.resolved deno.lock gopkg.lock paket.lock
    renv.lock shrinkwrap.yaml conan.lock gradle.lockfile
    """.split())

# U+FEFF: a UTF-8 byte order mark, which dotenvx (JavaScript's \s) skips like whitespace;
# after dotenvx prepends its public-key header the mark sits at the start of a later line.
ENV_ENTRY_RE = re.compile(u"^[\\s\ufeff]*(?:export\\s+)?([A-Za-z_][A-Za-z0-9_.\\-]*)\\s*=(.*)$")
KEYS_HINT_RE = re.compile(r"^\s*DOTENV_PUBLIC_KEY\w*\s*=.*#\s*-fk\s+(\S+)", re.MULTILINE)
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")

# "<identifier> <operator> <opening quote>" right before a secret on its line,
# e.g.  API_KEY = "   |   "apiKey": "   |   password:   |   os.environ["KEY"] = "
NAME_BEFORE_VALUE_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.\-]*)"       # the name we want
    r"\s*[\"'`]?\s*[\]\)]?\s*"            # optional closing quote / bracket
    r"(?:=>|:=|[=:,])"                    # assignment-ish operator
    r"\s*[\(\[\{]?\s*[\"'`]?\s*$"         # optional opening bracket / quote
)

# Names too vague to stand alone; they get the detector name prefixed
# (TOKEN found by the Github detector becomes GITHUB_TOKEN).
GENERIC_NAMES = set("""
    KEY TOKEN SECRET SECRETS PASSWORD PASS PASSWD PWD VALUE AUTH API_KEY APIKEY
    API_TOKEN API_SECRET ACCESS_KEY SECRET_KEY ACCESS_TOKEN CREDENTIAL CREDENTIALS
    CLIENT_SECRET PRIVATE_KEY URL URI DSN CONNECTION_STRING AUTHORIZATION BEARER
    DEFAULT KEY_ID ID ACCESS_KEY_ID SECRET_ACCESS_KEY WEBHOOK WEBHOOK_URL HOOK
    """.split())

# A detector whose name ends in one of these already says "secret"
# (PRIVATE_KEY, SLACK_WEBHOOK); such names are used as-is for generic contexts.
SECRETISH_WORDS = set("KEY TOKEN SECRET PASSWORD WEBHOOK URI URL DSN CREDENTIALS".split())

ENCRYPTED_PREFIX = "encrypted:"
# Private key custody is dotenvx's: from 2.3 `dotenvx native up` keeps a key in the OS secret
# store (macOS Keychain, Windows Credential Manager, Linux Secret Service) and dotenvx looks there
# itself when it runs; before that, and where no store is reachable, the key lives in .env.keys.
DOTENVX_NATIVE_SINCE = (2, 3, 0)
DOTENVX_KEYS_FILE_OPTION_SINCE = (1, 38, 0)   # -fk on encrypt and get: before it, keys sit next to the file
DOTENVX_PROVIDER_SINCE = (2, 25, 0)            # `dotenvx keypair provider`: where an existing key is held
DOTENVX_INFO = {}                              # path and version of the dotenvx this run uses, once located
NATIVE_STORE_NAMES = (("darwin", u"macOS Keychain"), ("win", u"Windows Credential Manager"),
                      ("linux", u"Linux Secret Service"))
MIN_FRAGMENT_LENGTH = 16   # a RawV2 remainder must be at least this long to be trusted
PAIR_DELIMITERS = (":", ";", ",", "|", "&")   # what TruffleHog puts between RawV2 parts
URL_TAIL_PUNCTUATION = b".,;:!?"
URL_CLOSERS = {b")": b"(", b"]": b"[", b"}": b"{"}
MAX_FILE_BYTES = 64 * 1024 * 1024
UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


class ToolError(Exception):
    """Something went wrong running TruffleHog or dotenvx."""


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

class Style(object):
    """ANSI colours when stdout is a terminal, plain text otherwise."""

    def __init__(self, enabled):
        self.enabled = enabled

    def _wrap(self, code, text):
        if not self.enabled:
            return text
        return u"\x1b[%sm%s\x1b[0m" % (code, text)

    def ok(self, text):
        return self._wrap("32", text)

    def warn(self, text):
        return self._wrap("33", text)

    def bad(self, text):
        return self._wrap("31", text)

    def bold(self, text):
        return self._wrap("1", text)

    def dim(self, text):
        return self._wrap("2", text)


def colour_wanted(flag_no_color):
    if flag_no_color or "NO_COLOR" in os.environ:
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if os.name == "nt" and not (os.environ.get("WT_SESSION") or os.environ.get("ANSICON")
                                or os.environ.get("TERM_PROGRAM")):
        return False
    return True


def which(name):
    """shutil.which() with a fallback for Python 2."""
    try:
        from shutil import which as _which  # Python 3.3+
    except ImportError:  # pragma: no cover - Python 2
        _which = None
    if _which is not None:
        return _which(name)
    if os.path.dirname(name):  # pragma: no cover - Python 2
        return name if os.path.isfile(name) and os.access(name, os.X_OK) else None
    exts = [""]  # pragma: no cover - Python 2
    if sys.platform.startswith("win"):
        exts += os.environ.get("PATHEXT", ".EXE;.CMD;.BAT;.COM").split(os.pathsep)
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        for ext in exts:
            candidate = os.path.join(folder.strip('"'), name + ext)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def run_command(cmd, cwd=None, extra_env=None, stdin_text=u""):
    """Run cmd, feed it stdin_text, return (exit code, stdout text, stderr text).

    If we are interrupted while the child runs, the child is killed and reaped
    first, so that it cannot keep writing files after we have given up on it."""
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    if PY2:  # pragma: no cover - Popen wants byte strings on Python 2
        cmd = [a.encode(FS_ENCODING) if isinstance(a, text_type) else a for a in cmd]
        cwd = cwd.encode(FS_ENCODING) if isinstance(cwd, text_type) else cwd
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(to_bytes(stdin_text))
    except BaseException:
        try:
            proc.kill()
        except (OSError, IOError):
            pass
        try:
            proc.wait()
        except (OSError, IOError):
            pass
        raise
    return proc.returncode, to_text(out), to_text(err)


def read_bytes(path):
    with io.open(path, "rb") as fh:
        return fh.read()


def write_bytes(path, data):
    """Write data to path atomically (temp file + rename) so that an interrupt can
    never leave a truncated file behind. A symbolic link is written through to its
    target instead of being replaced by a plain file; permission bits (and the
    owner, when we are allowed to) are kept."""
    if os.path.islink(path):
        path = os.path.realpath(path)
    folder = os.path.dirname(path) or "."
    try:
        handle, tmp = tempfile.mkstemp(prefix=TEMP_PREFIX, dir=folder)
    except (IOError, OSError):
        return write_in_place(path, data)
    try:
        with io.open(handle, "wb") as fh:
            fh.write(data)
        if os.path.exists(path):
            copy_attributes(path, tmp)
        replace = getattr(os, "replace", None)
        if replace is None and os.name == "nt" and os.path.exists(path):  # Python 2 on Windows
            os.remove(path)
        (replace or os.rename)(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def write_in_place(path, data):
    """Used when the folder refuses us a temp file: overwrite in place, and put the
    old content back if the write fails half way. Not atomic, but never silently
    truncated."""
    original = None
    if os.path.isfile(path):
        try:
            original = read_bytes(path)
        except (IOError, OSError):
            original = None
    try:
        with io.open(path, "wb") as fh:
            fh.write(data)
    except BaseException:
        if original is not None:
            try:
                with io.open(path, "wb") as fh:
                    fh.write(original)
            except (IOError, OSError):
                pass
        raise


def copy_attributes(src, dst):
    """Keep the mode bits and, where we are privileged enough, the owner and group.
    Timestamps are deliberately not copied: the file did change."""
    try:
        shutil.copymode(src, dst)
    except (IOError, OSError):
        pass
    if hasattr(os, "chown"):
        try:
            st = os.stat(src)
            os.chown(dst, st.st_uid, st.st_gid)
        except (IOError, OSError, AttributeError):
            pass


def read_text(path):
    return to_text(read_bytes(path))


def slash_path(path):
    return path.replace(os.sep, "/") if os.sep != "/" else path


def is_excluded(path, exclude_res, is_dir=False):
    probes = [slash_path(path) + ("/" if is_dir else "")]
    if os.sep != "/":
        probes.append(path + (os.sep if is_dir else ""))
    for rx in exclude_res:
        for probe in probes:
            if rx.search(probe):
                return True
    return False


def is_env_file(name):
    """Is this file name a dotenv file dotenvx can encrypt?"""
    if name.startswith(".env.keys") or name in (".env.vault", ".envrc"):
        return False
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def is_example_env_file(name):
    """.env.example, .env.sample, template.env ...: placeholders, not secrets to encrypt."""
    if not is_env_file(name):
        return False
    return any(part in EXAMPLE_ENV_WORDS for part in name.lower().split("."))


def is_lockfile(name):
    return name.lower() in LOCKFILE_NAMES


def archive_kind(path):
    """'zip', 'gzip', 'tar' ... when the file is an archive TruffleHog looked inside, else None."""
    try:
        with io.open(path, "rb") as fh:
            head = fh.read(512)
    except (IOError, OSError):
        return None
    for magic, kind in ARCHIVE_MAGIC:
        if head.startswith(magic):
            return kind
    if head[257:262] == b"ustar":
        return "tar"
    name = os.path.basename(path).lower()
    for ext in ARCHIVE_EXTENSIONS:
        if name.endswith(ext):
            return ext.lstrip(".")
    return None


def read_head(path, size=4096):
    """The first bytes of a file; b"" when it cannot be read."""
    try:
        with io.open(path, "rb") as fh:
            return fh.read(size)
    except (IOError, OSError):
        return b""


def compiled_kind(path, cache=None):
    """'.so file', 'ELF binary', 'Windows PE binary' ... when the file is compiled code, a program
    or a library, by its name or by its first bytes; else None."""
    if cache is not None and path in cache:
        return cache[path]
    kind = None
    match = COMPILED_NAME_RE.search(os.path.basename(path))
    if match:
        kind = u".%s file" % match.group(1).lower()
    else:
        head = read_head(path)
        for magic, label in COMPILED_MAGIC:
            if head.startswith(magic):
                kind = label
                break
        if kind is None and head[:2] == b"MZ" and len(head) >= 64:
            # a DOS stub followed by the PE header: an .exe or .dll without its extension
            offset = struct.unpack("<I", head[60:64])[0]
            if 64 <= offset <= len(head) - 4 and head[offset:offset + 4] == b"PE\x00\x00":
                kind = u"Windows PE binary"
    if cache is not None:
        cache[path] = kind
    return kind


class CompiledFile(object):
    """A program or library TruffleHog reported secrets in (--scan-compiled): listed, never changed."""

    def __init__(self, path, kind):
        self.path = path
        self.kind = kind
        self.findings = []


def strings_near(path, finding, secrets, width=40):
    """What surrounds the reported text in the file, the way `strings` shows it: the printable run
    around its first occurrence, cut at NUL bytes and line ends and at most width characters either
    side, with every secret reported for the file masked. u"" when the text is not in the file as
    such (an encoded match) or the file cannot be read."""
    needles = []
    for candidate in candidate_secrets(finding):
        needle = to_bytes(candidate)
        # an old TruffleHog sometimes reports a byte or two beyond the string: try without them too
        for trimmed in (needle, needle[:-1], needle[:-2]) if len(needle) > 16 else (needle,):
            if trimmed and trimmed not in needles:
                needles.append(trimmed)
    if not needles:
        return u""
    pad = width + max([len(secret) for secret in secrets] + [0])   # room to mask a secret that starts in view
    try:
        with io.open(path, "rb") as fh:
            try:
                view = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            except (ValueError, EnvironmentError):   # an empty file, or a file system without mmap
                view = fh.read(INSPECT_FULL_READ_BYTES)
            try:
                total = len(view)
                for needle in needles:
                    start = view.find(needle)
                    if start >= 0:
                        break
                else:
                    return u""
                lo, hi = max(0, start - pad), min(total, start + len(needle) + pad)
                chunk = bytearray(view[lo:hi])
            finally:
                if hasattr(view, "close"):
                    view.close()
    except (IOError, OSError, ValueError):
        return u""
    pos = start - lo
    begin, end = pos, pos + len(needle)
    while begin > 0 and 0x20 <= chunk[begin - 1] <= 0x7e:
        begin -= 1
    while end < len(chunk) and 0x20 <= chunk[end] <= 0x7e:
        end += 1
    left, right = bytes(chunk[begin:pos]), bytes(chunk[pos + len(needle):end])
    # Mask before clipping, so that a reported secret cut by the edge of the view cannot show in part.
    # (A secret TruffleHog did not report cannot be masked; the width keeps what is shown short.)
    for secret in sorted(set(secrets), key=len, reverse=True):
        hidden = to_bytes(mask(to_text(secret)))
        left, right = left.replace(secret, hidden), right.replace(secret, hidden)
    clipped_left = len(left) > width or (begin == 0 and lo > 0)
    clipped_right = len(right) > width or (end == len(chunk) and hi < total)
    text = to_text(left[-width:] if width else b"") + mask(to_text(needle)) + to_text(right[:width])
    return (u"..." if clipped_left else u"") + text + (u"..." if clipped_right else u"")


def find_closing_quote(body, quote):
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i
        i += 1
    return -1


def parse_env_entries(text):
    """Yield (key, value, line_number) for each KEY=value entry in dotenv text.

    Follows the dotenv/dotenvx reading rules closely enough to compare values:
    quoted values ('...', "...", `...`) may span lines and keep their content
    verbatim, an unquoted value stops at the first '#'. Nothing is unescaped.
    """
    if text.startswith(u"\ufeff"):  # UTF-8 BOM (Notepad): dotenvx reads past it, so do we
        text = text[1:]
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        match = ENV_ENTRY_RE.match(lines[i])
        if not match:
            i += 1
            continue
        key, rest = match.group(1), match.group(2).strip()
        start = i
        if rest[:1] in ("'", '"', "`"):
            quote = rest[0]
            body = rest[1:]
            end = find_closing_quote(body, quote)
            while end < 0 and i + 1 < len(lines):
                i += 1
                body += "\n" + lines[i]
                end = find_closing_quote(body, quote)
            value = body[:end] if end >= 0 else body
        else:
            value = rest.split("#", 1)[0].strip()
        yield key, value, start + 1
        i += 1


def value_holds(value, token):
    if token in value:
        return True
    if "\n" in token:
        first = token.split("\n")[0].strip()
        return bool(first) and first in value
    return False


def quote_env_value(value):
    """Quote a value for a .env line so dotenvx reads back exactly what we stored.

    Measured against dotenvx 2.38: single quotes are fully literal; backticks are
    literal except that $NAME is expanded (a backslash before the $ prevents it);
    double quotes expand $NAME, \\n and \\t, honour \\$, and keep \\" and \\\\ as they
    are (nothing is unescaped). So a value without an apostrophe goes in single
    quotes, one with an apostrophe in backticks or double quotes with every $
    escaped, and a value that also contains a backslash (or an apostrophe, a
    backtick and a double quote together) cannot be written exactly at all.
    Returns (quoted_text, exact); callers must not store an inexact value.
    """
    if "'" not in value:
        return "'" + value + "'", True
    escaped = value.replace("$", "\\$")
    if "`" not in value and "\\" not in value:
        return "`" + escaped + "`", True
    if '"' not in value and "\\" not in value:
        return '"' + escaped + '"', True
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"', False


def inexact_reason(value):
    if "\\" in value:
        return u"it contains both an apostrophe and a backslash"
    return u"it contains an apostrophe, a backtick and a double quote"


def normalize_name(raw):
    name = re.sub(r"[^A-Za-z0-9]+", "_", to_text(raw)).strip("_").upper()
    return re.sub(r"_+", "_", name)


def detector_words(detector):
    """'GoogleGeminiAPIKey' -> 'GOOGLE_GEMINI_API_KEY', 'AWS' -> 'AWS'."""
    words = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", to_text(detector))
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", words)
    return normalize_name(words) or "SECRET"


def choose_name(detector, context, secret):
    """Pick an environment variable name for a secret found in a source file.

    Prefer the identifier it was assigned to (API_KEY = "..."), made specific
    with the detector name when it is too generic (TOKEN -> GITHUB_TOKEN); fall
    back to the detector name plus a short hash of the secret.
    """
    det = detector_words(detector)
    det_names_a_secret = det.rsplit("_", 1)[-1] in SECRETISH_WORDS
    name = normalize_name(context) if context else ""
    if name and (len(name) < 3 or name in GENERIC_NAMES) and name != det and not name.startswith(det + "_"):
        name = det if det_names_a_secret else det + "_" + name
    if name and name[0].isdigit():
        name = det + "_" + name
    if not name:
        digest = hashlib.sha256(to_bytes(secret)).hexdigest()[:6].upper()
        name = det + "_" + digest if det_names_a_secret else det + "_SECRET_" + digest
    if name.startswith("DOTENV_"):
        name = "APP_" + name
    return name[:64].rstrip("_")


def guess_name_from_prefix(prefix):
    match = NAME_BEFORE_VALUE_RE.search(prefix.rstrip())
    return match.group(1) if match else None


def mask(secret):
    flat = secret.replace("\r", " ").replace("\n", " ").strip()
    if len(flat) >= 16:
        return flat[:4] + "..." + flat[-2:]
    if len(flat) >= 8:
        return flat[:2] + "..." + flat[-1:]
    return "***"


def parse_selection(text, count):
    """'1 3 5-7' -> [1, 3, 5, 6, 7]; 'all' -> everything; None when unparseable."""
    text = text.strip().lower()
    if text in ("all", "a", "*"):
        return list(range(1, count + 1))
    chosen = set()
    for part in re.split(r"[\s,]+", text):
        if not part:
            continue
        match = re.match(r"^(\d+)(?:-(\d+))?$", part)
        if not match:
            return None
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) else low
        if low < 1 or high > count or low > high:
            return None
        chosen.update(range(low, high + 1))
    return sorted(chosen)


# --------------------------------------------------------------------------
# Locating the tools
# --------------------------------------------------------------------------

def find_tool(name, override, root):
    candidates = []
    if override:
        candidates.append(override)
    env_override = os.environ.get(name.upper() + "_BIN")
    if env_override:
        candidates.append(env_override)
    candidates.append(name)
    if name == "dotenvx":  # a project-local npm install also counts
        candidates.append(os.path.join(root, "node_modules", ".bin", "dotenvx"))
    for candidate in candidates:
        found = None
        if os.name == "nt" and os.path.dirname(candidate) and not os.path.splitext(candidate)[1]:
            # npm installs both a POSIX shell script "dotenvx" and "dotenvx.cmd"; only the
            # latter can be executed here, and shutil.which() before 3.12 would return the former.
            for ext in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep):
                if ext and os.path.isfile(candidate + ext):
                    found = candidate + ext
                    break
        found = found or which(candidate)
        if found:
            # absolute, because the tools are later run with the swept folder as cwd
            return os.path.abspath(fs_text(found))
    return None


def tool_version(path):
    """(version tuple or None, raw version text)."""
    try:
        code, out, err = run_command([path, "--version"])
    except (OSError, IOError) as exc:
        return None, to_text(str(exc))
    text = (out + " " + err).strip()
    match = VERSION_RE.search(text)
    version = tuple(int(part) for part in match.groups()) if match else None
    return version, text.splitlines()[0] if text else u""


def complain_about_tool(name, problem, style):
    info = TOOLS[name]
    say(style.bad("[!!] ") + style.bold(u"%s %s." % (name, problem)), sys.stderr)
    say(u"     %s is required: it %s. Get it here:" % (name, info["job"]), sys.stderr)
    for link in info["links"]:
        say(u"       %s" % link, sys.stderr)
    say(u"     Quick install:", sys.stderr)
    for line in info["install"]:
        say(u"       %s" % line, sys.stderr)
    say(u"     (or point me at it with --%s PATH or the %s_BIN environment variable)"
        % (name, name.upper()), sys.stderr)
    say(u"", sys.stderr)


def locate_tools(args, root, style, keep_going=False, names=None):
    """Find TruffleHog and dotenvx (or just the tools in names), print one [ok] line each and
    return them. A missing or unusable tool is explained with install links and ends the run with
    exit code 1, unless keep_going is set: the setup check then reports every tool and returns
    (found, problems)."""
    found = {}
    problems = 0
    for name, info in TOOLS.items():
        if names and name not in names:
            continue
        path = find_tool(name, getattr(args, name), root)
        if not path:
            complain_about_tool(name, "is not installed (or not on your PATH)", style)
            problems += 1
            continue
        version, text = tool_version(path)
        if version is None and not args.no_version_check:
            complain_about_tool(name, u"at %s did not report a usable version (%s), so it probably cannot"
                                u" be run from here; pass --no-version-check to try it anyway"
                                % (path, text or u"no output"), style)
            problems += 1
            continue
        if version is not None and version < info["min_version"]:
            complain_about_tool(name, u"%s is too old. %s" % (text, info["why_version"]), style)
            problems += 1
            continue
        found[name] = {"path": path, "version": version, "text": text}
        if name == "dotenvx":
            DOTENVX_INFO.clear()
            DOTENVX_INFO.update(found[name])
        say(u"  %s %-11s %-10s %s" % (style.ok("[ok]"), name,
                                      ".".join(str(v) for v in version) if version else "?",
                                      style.dim(path)))
        if name == "trufflehog" and version and version < TRUFFLEHOG_SKIPS_COMPILED:
            say(style.dim(u"       an old release, used as it is; %s and later skip compiled files themselves and later"
                          u" releases keep tightening their detectors, so upgrade when you can"
                          % u".".join(str(v) for v in TRUFFLEHOG_SKIPS_COMPILED)))
    if keep_going:
        return found, problems
    if problems:
        say(style.bad(u"Cannot continue: %d required tool(s) missing. Install them and run me again."
                      % problems), sys.stderr)
        sys.exit(1)
    return found


# --------------------------------------------------------------------------
# --check-setup: is this machine ready?
# --------------------------------------------------------------------------

def check_setup(args, root, style):
    """Report Python, the two tools and git, then run TruffleHog and dotenvx in a scratch
    folder the way a real run uses them. Nothing under root is read or written. Exit code
    0 means a real run will find everything it needs; 1 names what is missing or broken."""
    say(u"Python %s (%s) on %s" % (platform.python_version(), fs_text(sys.executable or u"?"), platform.platform()))
    if sys.version_info < (3, 8):
        say(u"  %s Python %d.%d is older than the versions this script is tested with (3.8 to 3.13)."
            % (style.warn("[--]"), sys.version_info[0], sys.version_info[1]))
    tools, problems = locate_tools(args, root, style, keep_going=True)
    git = which("git")
    if git:
        version, text = tool_version(git)
        say(u"  %s %-11s %-10s %s" % (style.ok("[ok]"), "git",
                                      ".".join(str(v) for v in version) if version else "?",
                                      style.dim(u"%s  (optional: keeps .env.keys out of commits)" % fs_text(git))))
    else:
        say(u"  %s %-11s %s" % (style.warn("[--]"), "git",
                                style.dim(u"not found  (optional: .gitignore is still written; git cannot confirm it)")))
    openssl = find_openssl(args)
    if openssl:
        info = openssl_setup(openssl)
        words = (info.get("version") or u"").split()
        if info.get("kdf"):
            say(u"  %s %-11s %-10s %s" % (style.ok("[ok]"), "openssl", words[1] if len(words) > 1 else "?",
                                          style.dim(u"%s  (optional: encrypts quarantined files; key derivation %s)"
                                                    % (openssl, info["kdf"]))))
        else:
            say(u"  %s %-11s %s" % (style.warn("[--]"), "openssl",
                                    style.dim(u"%s could not encrypt a probe file (%s): quarantined files would be moved as"
                                              u" they are" % (openssl, info.get("error") or u"no output"))))
    elif getattr(args, "openssl", None):
        say(u"  %s %-11s %s" % (style.warn("[--]"), "openssl",
                                style.dim(u"--openssl %s is not a file  (optional: quarantined files would be moved as"
                                          u" they are)" % fs_text(args.openssl))))
    else:
        say(u"  %s %-11s %s" % (style.warn("[--]"), "openssl",
                                style.dim(u"not found  (optional: quarantined files would be moved as they are; install"
                                          u" openssl or pass --openssl)")))
    scratch = None
    try:
        try:
            scratch = tempfile.mkdtemp(prefix="sweep-and-secure-check-")
        except (IOError, OSError) as exc:
            say(style.bad(u"[!!] cannot create a scratch folder in the system temp folder: %s"
                          % to_text(str(exc))), sys.stderr)
            problems += 1
        if scratch and "trufflehog" in tools:
            problems += 0 if check_trufflehog(tools["trufflehog"]["path"], scratch, args, style) else 1
        if scratch and "dotenvx" in tools:
            problems += 0 if check_dotenvx(tools["dotenvx"]["path"], scratch, args, style) else 1
    finally:
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)
    say(u"")
    if problems:
        say(style.bad(u"Setup check failed: %d problem(s), see above. Nothing was changed." % problems))
        return 1
    say(style.ok(u"Setup looks good.") + u" Nothing was changed. Next: %s --dry-run in a project folder."
        % (os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "sweep-and-secure"))
    return 0


def check_trufflehog(binary, scratch, args, style):
    """Scan a scratch folder holding one harmless file with the exact TruffleHog command a
    run uses. Proves the binary runs here and that its options (or the fallbacks an older
    release needs) work; with a current TruffleHog the file count also proves the progress
    signal (its per-file log lines) is understood."""
    probe = os.path.join(scratch, "probe.txt")
    try:
        with io.open(probe, "w", encoding="utf-8") as fh:
            fh.write(u"sweep-and-secure setup check: this file holds no secret\n")
    except (IOError, OSError) as exc:
        say(style.bad(u"[!!] trufflehog check skipped: cannot write %s (%s)" % (probe, to_text(str(exc)))),
            sys.stderr)
        return False
    progress = ScanProgress(stream=None)
    try:
        findings, code, notes = run_trufflehog(binary, scratch, list(ALWAYS_EXCLUDES), args, progress)
    except ToolError as exc:
        say(style.bad(u"[!!] trufflehog could not scan a scratch folder: %s" % to_text(str(exc))), sys.stderr)
        return False
    if progress.files_known and progress.files < 1:
        say(style.bad(u"[!!] trufflehog scanned the scratch folder but did not report the file in it;"
                      u" its progress output is not what this version of the script understands"
                      u" (the scan would still run, but without a live file count)."), sys.stderr)
        return False
    if findings:
        say(style.bad(u"[!!] trufflehog reported %d finding(s) in a file that holds no secret; check the"
                      u" installed version" % len(findings)), sys.stderr)
        return False
    if progress.files_known:
        say(u"  %s trufflehog  ran in a scratch folder: exit status %d, %d file(s) scanned, no findings"
            % (style.ok("[ok]"), code, progress.files))
    else:
        say(u"  %s trufflehog  ran in a scratch folder: exit status %d, no findings (an older TruffleHog, used as"
            u" it is)" % (style.ok("[ok]"), code))
    for note in notes:
        say(style.dim(u"       %s" % note))
    return True


def check_dotenvx(dotenvx, scratch, args, style):
    """Encrypt a throw-away value into a scratch .env through encrypt_env_file, exactly as a
    run does (staging copy, dotenvx encrypt, decrypt-and-compare, atomic install), and
    confirm the private key file appeared next to it."""
    env_path = os.path.join(scratch, ".env")
    job = {"new": [(u"SWEEP_AND_SECURE_CHECK", u"setup check value")], "keys": [u"SWEEP_AND_SECURE_CHECK"],
           "items": []}
    decryptor = make_decryptor(dotenvx, scratch, args)
    custody = {}
    ok, note, warnings = encrypt_env_file(env_path, job, dotenvx, scratch, args, decryptor, custody=custody)
    if not ok:
        say(style.bad(u"[!!] dotenvx could not encrypt a value in a scratch folder: %s" % note), sys.stderr)
        return False
    kind, where, note = custody.get(env_path) or (None, None, u"")
    keys_file = os.path.join(scratch, ".env.keys")
    if kind == "native":
        # take the scratch key out of the user's secret store again
        ok_down, detail = dotenvx_native(dotenvx, "down", env_path, keys_file, scratch, args)
        if not ok_down:
            warnings.append(u"the scratch key could not be removed from the %s (%s); `dotenvx native down -f %s`"
                            u" removes it" % (where, detail, env_path))
    elif kind == "file":
        if not os.path.isfile(keys_file):
            say(style.bad(u"[!!] dotenvx encrypted a value but wrote no .env.keys next to the file (looked for %s)"
                          % keys_file), sys.stderr)
            return False
    else:
        say(style.bad(u"[!!] dotenvx encrypted a value but where its private key went is unclear"), sys.stderr)
        return False
    if warnings:
        say(style.bad(u"[!!] dotenvx encrypted a value in a scratch folder but it could not be checked: %s"
                      % u"; ".join(warnings)), sys.stderr)
        return False
    value, reason = decrypt_env_value(dotenvx, env_path, u"SWEEP_AND_SECURE_CHECK", scratch, args)
    if value != u"setup check value":
        say(style.bad(u"[!!] dotenvx get did not return the value that was encrypted: %s"
                      % (reason or u"got something else")), sys.stderr)
        return False
    if kind == "native":
        say(u"  %s dotenvx     ran in a scratch folder: encrypted a value, decrypted it back; the private key went"
            u" to the %s and was removed again" % (style.ok("[ok]"), where))
    else:
        say(u"  %s dotenvx     ran in a scratch folder: encrypted a value, decrypted it back; the private key went"
            u" to .env.keys (%s)" % (style.ok("[ok]"), file_custody_reason(args, note)))
    return True


# --------------------------------------------------------------------------
# Scanning with TruffleHog
# --------------------------------------------------------------------------

class Finding(object):
    """One TruffleHog result."""

    __slots__ = ("path", "line", "detector", "raw", "raw_v2", "verified", "decoder", "extra")

    def __init__(self, path, line, detector, raw, raw_v2, verified, decoder, extra):
        self.path = path
        self.line = line
        self.detector = detector
        self.raw = raw
        self.raw_v2 = raw_v2
        self.verified = verified
        self.decoder = decoder
        self.extra = extra

    @classmethod
    def from_json(cls, obj, root):
        meta = obj.get("SourceMetadata") or {}
        data = meta.get("Data") or {}
        where = data.get("Filesystem")
        if not isinstance(where, dict):
            for value in data.values():
                if isinstance(value, dict) and value.get("file"):
                    where = value
                    break
        if not isinstance(where, dict) or not where.get("file"):
            return None
        path = to_text(where.get("file"))
        if not os.path.isabs(path):
            path = os.path.join(root, path)
        try:
            line = int(where.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        extra = obj.get("ExtraData")
        raw, raw_v2 = to_text(obj.get("Raw") or ""), to_text(obj.get("RawV2") or "")
        if "DecoderName" not in obj and "RawV2" not in obj:
            # TruffleHog 3.6 to 3.12 wrote Raw as Go bytes, which its JSON shows as base64
            raw, raw_v2 = legacy_bytes_field(raw), legacy_bytes_field(raw_v2)
        return cls(
            path=os.path.normpath(path),
            line=line,
            detector=to_text(obj.get("DetectorName") or "Unknown"),
            raw=raw,
            raw_v2=raw_v2,
            verified=bool(obj.get("Verified")),
            decoder=to_text(obj.get("DecoderName") or "PLAIN"),
            extra=extra if isinstance(extra, dict) else {},
        )


LEGACY_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
AWS_ID_RE = re.compile(r"^(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}$")
AWS_SECRET_RE = re.compile(br"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])")
AWS_PAIR_WINDOW = 400   # bytes either side of a key id in which its secret is looked for


def legacy_bytes_field(text):
    """A Raw/RawV2 value as TruffleHog 3.6 to 3.12 wrote it: base64 of the bytes. Decoded
    when it is valid base64 holding UTF-8 text, else returned as it is."""
    if not text or len(text) % 4 or not LEGACY_BASE64_RE.match(text):
        return text
    try:
        return base64.b64decode(text).decode("utf-8")
    except (ValueError, TypeError, binascii.Error, UnicodeDecodeError):
        return text


def complete_aws_pairs(findings):
    """A TruffleHog before 3.34 reports an AWS key pair as its id alone (no RawV2 with the
    secret access key), which would leave the secret in place. Like the current AWS detector,
    look next to the id in the same file for the one 40-character secret and pair them, so
    both are handled. Returns the number of pairs completed."""
    completed = 0
    cache = {}
    for finding in findings:
        if finding.detector != "AWS" or finding.raw_v2 or not AWS_ID_RE.match(finding.raw):
            continue
        if finding.path not in cache:
            try:
                data = read_bytes(finding.path) if os.path.getsize(finding.path) <= MAX_FILE_BYTES else b""
            except (IOError, OSError):
                data = b""
            cache[finding.path] = b"" if b"\x00" in data else data
        data = cache[finding.path]
        key_id = finding.raw.encode("ascii")
        position = data.find(key_id)
        if position < 0:
            continue
        window = data[max(0, position - AWS_PAIR_WINDOW):position + len(key_id) + AWS_PAIR_WINDOW]
        secrets = set(match.group(0) for match in AWS_SECRET_RE.finditer(window)) - set([key_id])
        if len(secrets) == 1:
            finding.raw_v2 = finding.raw + u":" + secrets.pop().decode("ascii")
            completed += 1
    return completed


class ScanProgress(object):
    """A 'still working' line while TruffleHog runs: files scanned so far (its per-file
    log lines at --log-level=3), findings so far (its JSON lines) and the time spent.
    On a terminal the line is redrawn in place; elsewhere a heartbeat line is printed
    every HEARTBEAT seconds, so that a CI log shows the scan is alive."""

    HEARTBEAT = 15.0
    REDRAW = 0.2

    def __init__(self, stream=None, is_tty=None, heartbeat=None):
        self.stream = stream if stream is not None else sys.stdout
        if is_tty is None:
            is_tty = bool(self.stream is not None and hasattr(self.stream, "isatty") and self.stream.isatty())
        self.is_tty = is_tty
        self.heartbeat = self.HEARTBEAT if heartbeat is None else heartbeat
        self.files = 0
        self.files_known = True   # False when this TruffleHog cannot log the file it is scanning
        self.findings = 0
        self.start = time.time()
        self.last_draw = None
        self.drawn = 0
        self.lock = threading.Lock()

    def saw_stderr(self, line):
        if b'"scanning file"' in line:
            with self.lock:
                self.files += 1

    def saw_stdout(self, line):
        if line.lstrip().startswith(b"{"):
            with self.lock:
                self.findings += 1

    def elapsed(self):
        seconds = int(time.time() - self.start)
        return u"%d:%02d" % (seconds // 60, seconds % 60)

    def text(self):
        if not self.files_known:
            return u"  scanning ... %d finding(s) so far, %s" % (self.findings, self.elapsed())
        return u"  scanning ... %d file(s), %d finding(s) so far, %s" % (self.files, self.findings, self.elapsed())

    def summary(self, findings):
        """The line printed when the scan is over."""
        if not self.files_known:
            return u"  Scan took %s; TruffleHog reported %d finding(s)." % (self.elapsed(), findings)
        return u"  Scanned %d file(s) in %s; TruffleHog reported %d finding(s)." % (self.files, self.elapsed(), findings)

    def tick(self):
        """Called regularly by the waiting thread; draws when it is time to."""
        if self.stream is None:
            return
        now = time.time()
        interval = self.REDRAW if self.is_tty else self.heartbeat
        if self.last_draw is None:
            self.last_draw = self.start   # the first heartbeat waits a full interval
        if now - self.last_draw < interval:
            return
        self.last_draw = now
        text = self.text()
        try:
            if self.is_tty:
                self.stream.write(u"\r" + text.ljust(self.drawn))
                self.drawn = max(self.drawn, len(text))
            else:
                self.stream.write(text + u"\n")
            self.stream.flush()
        except (IOError, OSError, ValueError, UnicodeEncodeError):
            pass

    def finish(self):
        if self.stream is not None and self.is_tty and self.drawn:
            try:
                self.stream.write(u"\r" + u" " * self.drawn + u"\r")
                self.stream.flush()
            except (IOError, OSError, ValueError):
                pass


def run_streaming(cmd, cwd, on_stdout, on_stderr, tick, keep_stderr=200):
    """Run cmd, handing each stdout/stderr line to a callback as it arrives (so that a
    long scan can show progress), and return (exit code, stdout lines, last stderr lines).
    A KeyboardInterrupt kills the child before it propagates."""
    env = dict(os.environ)
    if PY2:  # pragma: no cover
        cmd = [a.encode(FS_ENCODING) if isinstance(a, text_type) else a for a in cmd]
        cwd = cwd.encode(FS_ENCODING) if isinstance(cwd, text_type) else cwd
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out_lines, err_lines = [], deque(maxlen=keep_stderr)

    def pump(pipe, store, callback):
        try:
            for line in iter(pipe.readline, b""):
                store.append(line)
                callback(line)
        except (IOError, OSError, ValueError):
            pass
        finally:
            try:
                pipe.close()
            except (IOError, OSError):
                pass

    readers = [threading.Thread(target=pump, args=(proc.stdout, out_lines, on_stdout)),
               threading.Thread(target=pump, args=(proc.stderr, err_lines, on_stderr))]
    for reader in readers:
        reader.daemon = True
        reader.start()
    try:
        proc.stdin.close()
    except (IOError, OSError):
        pass
    try:
        while proc.poll() is None:
            time.sleep(0.1)
            tick()
        for reader in readers:
            reader.join()
    except BaseException:
        try:
            proc.kill()
        except (OSError, IOError):
            pass
        try:
            proc.wait()
        except (OSError, IOError):
            pass
        raise
    return proc.returncode, out_lines, list(err_lines)


UNKNOWN_FLAG_RE = re.compile(r"unknown (?:long|short) flag '(-{1,2}[A-Za-z0-9-]+)'")
UNEXPECTED_ARG_RE = re.compile(r"\berror: unexpected ")

# Options a current TruffleHog takes that older 3.x releases lack (measured: --exclude-paths
# arrived around 3.28, a positional path around 3.34, --log-level in the 3.8x releases), and
# what a run loses without each.
TRUFFLEHOG_OPTION_NOTES = {
    u"--log-level": u"this TruffleHog has no --log-level, so it cannot say which file it is scanning: the"
                    u" progress line shows findings and time only",
    u"--exclude-paths": u"this TruffleHog has no --exclude-paths, so it scanned the excluded folders (.git,"
                        u" node_modules, ...) as well; findings there are ignored here, but the scan takes longer",
    u"--no-verification": u"this TruffleHog has no --no-verification, so it checked the credentials it found"
                          u" against their services over the network",
    u"--no-update": u"",
}


def drop_flag(flags, flag):
    """Remove flag (given as --name) and any value it carries from flags; True if it was there."""
    for index, entry in enumerate(flags):
        if entry == flag or entry.startswith(flag + u"="):
            takes_value = entry == flag and flag in (u"--exclude-paths",)
            del flags[index:index + (2 if takes_value else 1)]
            return True
    return False


def run_trufflehog(binary, root, exclude_patterns, args, progress=None):
    """Run TruffleHog over root and read its JSON results: (findings, exit status, notes).

    The command is the one a current TruffleHog takes. An older 3.x that rejects an option
    ("unknown long flag") is run again without it, and one that takes no path argument is
    given --directory instead, so an old install is used as it is. The notes say what was
    left out and what that costs. --json is the one option that cannot go: without it there
    are no results to read."""
    exclude_file = None
    if exclude_patterns:
        handle, exclude_file = tempfile.mkstemp(prefix="sweep-and-secure-", suffix=".txt")
        with io.open(handle, "w", encoding="utf-8") as fh:
            fh.write(u"\n".join(to_text(p) for p in exclude_patterns) + u"\n")
    # --log-level=3 makes TruffleHog log every file it scans to stderr: that is the
    # progress signal; results stay on stdout as JSON lines.
    flags = [u"--json", u"--no-update", u"--log-level=3"]
    if not args.verify:
        flags.append(u"--no-verification")
    if exclude_file:
        flags.extend([u"--exclude-paths", exclude_file])
    positional = True
    notes = []
    if progress is None:
        progress = ScanProgress(stream=None)
    try:
        for attempt in range(8):
            cmd = [binary, "filesystem"] + ([root] if positional else [u"--directory=" + root]) + flags
            log_only(u"$ " + u" ".join(cmd))
            if args.verbose:
                say(u"  $ " + u" ".join(cmd))
            try:
                code, out_lines, err_lines = run_streaming(cmd, root, progress.saw_stdout, progress.saw_stderr,
                                                          progress.tick)
            except (OSError, IOError) as exc:
                raise ToolError(u"could not run %s: %s" % (binary, to_text(str(exc))))
            findings = []
            for raw in out_lines:
                line = to_text(raw).strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                finding = Finding.from_json(obj, root)
                if finding is not None:
                    findings.append(finding)
            err = u"\n".join(to_text(line).rstrip(u"\r\n") for line in err_lines
                             if b'"scanning file"' not in line)
            log_only(u"trufflehog exit status %d, %d result line(s); stderr tail:\n%s"
                     % (code, len(findings), u"\n".join(err.strip().splitlines()[-12:])))
            if code == 0 or findings:
                break
            # No results and a non-zero status: an option this TruffleHog does not know?
            match = UNKNOWN_FLAG_RE.search(err)
            if match:
                flag = match.group(1)
                if flag == u"--json":
                    raise ToolError(u"this TruffleHog has no --json output, so its results cannot be read;"
                                    u" TruffleHog 3.6 or newer is needed")
                if drop_flag(flags, flag):
                    note = TRUFFLEHOG_OPTION_NOTES.get(flag, u"this TruffleHog has no %s; it was left out" % flag)
                    if note:
                        notes.append(note)
                    continue
            elif positional and UNEXPECTED_ARG_RE.search(err):
                positional = False   # before about 3.34 the folder went in --directory
                continue
            tail = u"\n".join(err.strip().splitlines()[-8:])
            raise ToolError(u"trufflehog exited with status %d:\n%s" % (code, tail))
        else:
            raise ToolError(u"trufflehog kept rejecting its options; last error:\n%s"
                            % u"\n".join(err.strip().splitlines()[-4:]))
    finally:
        progress.finish()
        if exclude_file:
            try:
                os.remove(exclude_file)
            except OSError:
                pass
    if not any(entry.startswith(u"--log-level") for entry in flags):
        progress.files_known = False
    say(progress.summary(len(findings)))
    if args.verbose and err.strip():
        say(style_dim_block(err))
    return findings, code, notes


def style_dim_block(text):
    return u"\n".join(u"    | " + line for line in text.strip().splitlines()[-12:])


# --------------------------------------------------------------------------
# What is already in the env files
# --------------------------------------------------------------------------

def inventory_env_files(root, exclude_res, protect=(), compiled=None):
    """Return (encrypted, plaintext, stale) over all dotenv files: lists of
    (path, key, line) / (path, key, line, value), and the staging files or folders
    an earlier interrupted run left behind. Paths in protect (the store) are never
    reported as stale, whatever they are called. When a list is passed as compiled,
    every file whose name says compiled code (.so, .dll, .pyc, ...) is added to it."""
    protected = set(os.path.normpath(path) for path in protect)
    encrypted, plaintext, stale = [], [], []
    for dirpath, dirnames, filenames in os.walk(root):
        keep = []
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if name.startswith(TEMP_PREFIX) and not os.path.islink(full) and os.path.normpath(full) not in protected:
                stale.append(full)
            elif not is_excluded(full, exclude_res, is_dir=True):
                keep.append(name)
        dirnames[:] = sorted(keep)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if name.startswith(TEMP_PREFIX) and os.path.normpath(path) not in protected:
                stale.append(path)
                continue
            if (compiled is not None and COMPILED_NAME_RE.search(name) and not os.path.islink(path)
                    and not is_excluded(path, exclude_res)):
                compiled.append(path)
            if not is_env_file(name) or is_example_env_file(name):
                continue
            if is_excluded(path, exclude_res) or os.path.islink(path):
                continue
            try:
                text = read_text(path)
            except (IOError, OSError):
                continue
            for key, value, line in parse_env_entries(text):
                if key.startswith("DOTENV_PUBLIC_KEY") or key.startswith("DOTENV_PRIVATE_KEY"):
                    continue
                if value.startswith(ENCRYPTED_PREFIX):
                    encrypted.append((path, key, line))
                elif value:
                    plaintext.append((path, key, line, value))
    return encrypted, plaintext, stale


def remove_stale(stale):
    """Delete staging leftovers (ours: the name prefix is unique). Returns what is gone."""
    removed = []
    for path in stale:
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            removed.append(path)
        except (IOError, OSError):
            pass
    return removed


# --------------------------------------------------------------------------
# Planning: what will we do with each secret?
# --------------------------------------------------------------------------

class Item(object):
    """One distinct plaintext secret in one file, and what we intend to do about it."""

    def __init__(self, path, offset, line, detector, verified, secret, secret_bytes, encoding, extra):
        self.path = path
        self.offset = offset
        self.line = line
        self.detector = detector
        self.verified = verified
        self.secret = secret              # the value to store (decoded form)
        self.secret_bytes = secret_bytes  # the bytes as they sit in the file (replaced)
        self.encoding = encoding
        self.extra = extra or {}
        self.context = None       # identifier guessed from the surrounding line
        self.kind = None          # "env": encrypt in place  "source": move + placeholder  "quarantine": move the file
        self.key = None           # env var name holding the value
        self.store = None         # env file that holds (or will hold) the value
        self.new_entry = False    # must we append KEY=value to self.store?
        self.number = 0           # 1-based number shown in the listing
        self.status = "planned"   # planned | done | stored | skipped | failed
        self.note = u""           # shown in the listing (naming) or the result (failures)
        self.replaced = 0


class Plan(object):
    def __init__(self, root, store, quarantine=None):
        self.root = root
        self.store = store
        self.quarantine = quarantine   # folder archives with secrets are moved to, or None
        self.quarantine_flagged = True # False when it is only offered because the run is interactive
        self.items = []
        self.unfixable = OrderedDict()  # path -> Unfixable: files whose secrets cannot be fixed in place
        self.hashes = 0              # findings inside package integrity hashes: checksums, not secrets
        self.encrypted = []          # (path, key, line) already encrypted
        self.plain_env = []          # (path, key, line, value) unflagged plaintext env keys
        self.extra_env_keys = {}     # env path -> [keys] that must be encrypted as well
        self.ignored = 0             # findings inside excluded folders (TruffleHog on Windows)
        self.compiled = OrderedDict()  # path -> CompiledFile: findings in programs and libraries (--scan-compiled)
        self.compiled_skipped = OrderedDict()  # path -> kind: compiled files TruffleHog read anyway, set aside
        self.compiled_by_name = []   # compiled files seen in the tree and left out of the scan
        self.custody = OrderedDict()  # env path -> ("native", store) | ("file", keys path) | ("existing", None)
        self.quarantine_crypto = None  # {"openssl", "kdf", "dotenvx", "version"} when quarantined files are encrypted
        self.quarantine_plain_reason = u""   # why they are moved as they are, when they are
        self.upgrades = None           # what a later run can tighten: keys in files, plaintext quarantined files
        self.quarantine_upgraded = []  # (old stored name, new stored name) of files encrypted in place this run
        self.upgrade_failures = []     # keys that could not be moved into the store (the run still succeeds)
        self.quarantine_upgrade_failed = []   # stored names that could not be encrypted in place (the run fails)
        self.args = None

    def rel(self, path):
        try:
            rel = os.path.relpath(path, self.root)
        except ValueError:  # different drive on Windows
            return slash_path(path)
        return slash_path(rel) if not rel.startswith("..") else slash_path(path)


def candidate_secrets(finding):
    """The strings worth looking for in the file: Raw, RawV2 and the part of RawV2
    that is not Raw (TruffleHog reports an AWS pair as Raw=id, RawV2=id:secret)."""
    out = []
    for text in (finding.raw, finding.raw_v2):
        if text and text not in out:
            out.append(text)
    if finding.raw and finding.raw_v2 and finding.raw_v2 != finding.raw and finding.raw in finding.raw_v2:
        before, after = finding.raw_v2.split(finding.raw, 1)
        # Drop only the one delimiter TruffleHog puts between the parts ("id:secret");
        # characters such as '=' or '/' may be a real part of the credential.
        before, after = before.strip(), after.strip()
        if before[-1:] in PAIR_DELIMITERS:
            before = before[:-1]
        if after[:1] in PAIR_DELIMITERS:
            after = after[1:]
        for fragment in (before, after):
            if (len(fragment) >= MIN_FRAGMENT_LENGTH and fragment not in out
                    and re.match(r"^[A-Za-z0-9+/=_.\-]+$", fragment)):
                out.append(fragment)
    return out


def token_pattern(secret_bytes, secret_text, encoding):
    """A regex that matches the secret, extended to the end of the URL when the
    secret is a URL (TruffleHog may report a database URL without its /dbname path)."""
    if "://" in secret_text and encoding == "utf-8":
        return re.compile(re.escape(secret_bytes) + br"[^\s\"'`<>)]*")
    return re.compile(re.escape(secret_bytes))


def trim_url_tail(token, needle):
    """Drop sentence punctuation and unbalanced closing brackets that the URL
    extension swallowed (`See https://x/y.` or `[https://x/y]`), never cutting
    into the part TruffleHog itself reported."""
    while len(token) > len(needle):
        last = token[-1:]
        if last in URL_TAIL_PUNCTUATION:
            token = token[:-1]
        elif last in URL_CLOSERS and token.count(URL_CLOSERS[last]) < token.count(last):
            token = token[:-1]
        else:
            break
    return token


def locate(data, secret, decoder):
    """Find every occurrence of secret in data.

    Returns [(token_bytes, encoding, offset, canonical_text)]: token_bytes is what
    sits in the file (and gets replaced), canonical_text is the value to store,
    which is the decoded secret when the file holds an escaped form of it.
    """
    encodings = ["utf-8"]
    if data[:2] == b"\xff\xfe":
        encodings = ["utf-16-le"]
    elif data[:2] == b"\xfe\xff":
        encodings = ["utf-16-be"]
    elif "UTF16" in (decoder or "").upper():
        encodings = ["utf-16-le", "utf-16-be"]
    variants = [secret]
    if "\n" in secret:
        variants.append(secret.replace("\n", "\\n"))
        variants.append(secret.replace("\n", "\r\n"))
    for encoding in encodings:
        for variant in variants:
            try:
                needle = variant.encode(encoding)
            except UnicodeError:
                continue
            if not needle or needle not in data:
                continue
            pattern = token_pattern(needle, variant, encoding)
            found = []
            for match in pattern.finditer(data):
                token = match.group(0)
                if "://" in variant:
                    token = trim_url_tail(token, needle)
                canonical = token.decode(encoding, "replace") if variant == secret else secret
                found.append((token, encoding, match.start(), canonical))
            if found:
                return found
    return []


def load_for_edit(path, cache):
    """Read a file we may rewrite. Returns (bytes or None, reason when None)."""
    if path in cache:
        return cache[path]
    result = (None, u"")
    name = os.path.basename(path)
    if os.path.islink(path):
        result = (None, u"symbolic link")
    elif not os.path.isfile(path):
        result = (None, u"file is gone (moved or deleted during the scan)")
    elif is_example_env_file(name):
        result = (None, u"example env file")
    elif is_lockfile(name):
        result = (None, u"generated lock file")
    elif name.lower().endswith(".pdf"):
        result = (None, u"PDF")
    else:
        try:
            size = os.path.getsize(path)
            if size > MAX_FILE_BYTES:
                result = (None, u"larger than %d MB" % (MAX_FILE_BYTES // (1024 * 1024)))
            else:
                data = read_bytes(path)
                if b"\x00" in data and data[:2] not in UTF16_BOMS:
                    kind = archive_kind(path)
                    result = (None, u"%s archive" % kind if kind else u"binary file")
                else:
                    result = (data, u"")
        except (IOError, OSError) as exc:
            result = (None, u"cannot be read: %s" % to_text(str(exc)))
    cache[path] = result
    return result


class Unfixable(object):
    """A file holding secrets that cannot be fixed in place: an archive, a binary, a PDF, a
    generated lock file, an example env file, a file too big or unreadable, or a text file
    whose only secrets are encoded, too short or unstorable. The whole file can be moved to
    quarantine instead (when movable), which is what its quarantine Item does."""

    def __init__(self, path, why, kind=None, movable=True):
        self.path = path
        self.why = why          # short reason, shown in the listing and recorded in quarantine
        self.kind = kind        # the archive kind when it is one ('zip', 'tar.gz', ...), else None
        self.movable = movable  # False for a symbolic link, a file that is gone, or a file whose
        self.partial = False    #   other secrets are fixed in place (partial)
        self.in_use = False     # True when this run stores other files' secrets in it: never moved
        self.findings = []      # every TruffleHog result reported for this file
        self.item = None        # the quarantine Item when this run may move it, else None
        self.inside = []        # archives: (path inside, [findings that file holds]) in archive order
        self.unplaced = []      # archives: findings no file inside holds verbatim
        self.note = u""         # why the view inside is incomplete, when it is


def detectors_of(findings):
    names = []
    for finding in findings:
        if finding.detector not in names:
            names.append(finding.detector)
    return names


def file_bytes(path, cache):
    """The bytes of a file up to MAX_FILE_BYTES, cached; b"" when it cannot be read."""
    if path not in cache:
        try:
            cache[path] = read_bytes(path) if os.path.getsize(path) <= MAX_FILE_BYTES else b""
        except (IOError, OSError):
            cache[path] = b""
    return cache[path]


def inside_integrity_hash(finding, data):
    """True when every occurrence of the reported text sits inside a package integrity hash
    (npm sha512-..., Go h1:..., pip sha256:...) in data: a checksum that happened to match
    a detector's pattern, not a secret. False when the text is not found at all."""
    if not data:
        return False
    found = False
    for candidate in candidate_secrets(finding):
        needle = to_bytes(candidate)
        start = data.find(needle)
        while start >= 0:
            found = True
            line_start = data.rfind(b"\n", 0, start) + 1
            line_end = data.find(b"\n", start)
            line = data[line_start:line_end if line_end >= 0 else len(data)]
            offset = start - line_start
            covered = any(match.start() <= offset and match.end() >= offset + len(needle)
                          for match in INTEGRITY_HASH_RE.finditer(line))
            if not covered:
                return False
            start = data.find(needle, start + 1)
    return found


def section_header(data, line_start, indent):
    """The nearest line above the one at line_start that is indented less than indent: the header
    of the YAML-like section the line belongs to (Podfile.lock's SPEC CHECKSUMS:, a hashes = [ block).
    b"" when there is none within 400 lines, or the line is not indented."""
    pos = line_start
    for _ in range(400):
        if pos <= 0 or indent <= 0:
            return b""
        prev_start = data.rfind(b"\n", 0, pos - 1) + 1
        prev = data[prev_start:pos - 1].rstrip(b"\r")
        stripped = prev.lstrip()
        if stripped and len(prev) - len(stripped) < indent:
            return prev
        pos = prev_start
    return b""


def lockfile_identifier(finding, data):
    """In a generated lock file: True when every occurrence of the reported text is a bare checksum
    or commit id (LOCK_DIGEST_RE) in a place seen to be public (a URL's fragment or path, a checksum,
    revision or reference field, a mix.lock entry, an entry of a checksum section) and in none that
    looks like a credential (a URL's user information, after an equals sign or after a telling word).
    Anything else, and text that is not found at all, is False: it stays a finding."""
    if not data:
        return False
    found = False
    for candidate in candidate_secrets(finding):
        needle = to_bytes(candidate)
        start = data.find(needle)
        while start >= 0:
            found = True
            line_start = data.rfind(b"\n", 0, start) + 1
            line_end = data.find(b"\n", start)
            line = data[line_start:line_end if line_end >= 0 else len(data)]
            offset = start - line_start
            span = None
            for match in LOCK_DIGEST_RE.finditer(line):
                if match.start() <= offset and match.end() >= offset + len(needle):
                    span = match
                    break
            if span is None:
                return False
            before, after = line[:span.start()], line[span.end():]
            if after.lstrip()[:1] == b"@" or before.rstrip()[-1:] == b"=" or LOCK_CREDENTIAL_RE.search(before):
                return False   # a credential, whatever its shape
            if not (LOCK_URL_CONTEXT_RE.search(before) or LOCK_FIELD_CONTEXT_RE.search(before)):
                header = section_header(data, line_start, len(line) - len(line.lstrip()))
                if not LOCK_SECTION_RE.search(header):
                    return False   # a digest nobody vouches for: it is listed
            start = data.find(needle, start + 1)
    return found


def gzip_member_name(head, fallback):
    """The original file name recorded in a gzip header (FNAME), else fallback."""
    if len(head) < 10 or not head.startswith(b"\x1f\x8b"):
        return fallback
    flags = ord(head[3:4])
    pos = 10
    if flags & 0x04:  # FEXTRA
        if len(head) < pos + 2:
            return fallback
        pos += 2 + (ord(head[pos:pos + 1]) | (ord(head[pos + 1:pos + 2]) << 8))
    if flags & 0x08:  # FNAME
        end = head.find(b"\x00", pos)
        if end > pos:
            return head[pos:end].decode("latin-1")
    return fallback


def archive_kind_of_bytes(head, name):
    """archive_kind() for data already in hand: magic bytes first, then the name."""
    for magic, kind in ARCHIVE_MAGIC:
        if head.startswith(magic):
            return kind
    if head[257:262] == b"ustar":
        return "tar"
    lowered = name.lower()
    for ext in ARCHIVE_EXTENSIONS:
        if lowered.endswith(ext):
            return ext.lstrip(".")
    return None


def safe_text(text):
    """text with any undecodable bytes (tarfile keeps them as surrogates) replaced, so that it
    can be printed and encoded without surprises."""
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except (UnicodeError, LookupError):  # pragma: no cover - Python 2 has no surrogateescape
        return text.encode("ascii", "replace").decode("ascii")


def walk_archive(opener, kind, name, prefix, depth, notes):
    """Yield (path inside, size or None, opener) for every regular file in the archive that
    opener() streams, descending into archives found inside it up to INSPECT_MAX_DEPTH deep.
    name is the archive's own name (used in notes, and for a lone compressed file that does
    not record the name of its content); prefix is prepended to the paths inside. Each member
    opener() returns a fresh stream of that member's content. Nothing is written anywhere."""
    # Every stream opened here is closed before the walk ends: an open handle on the archive
    # would stop Windows from renaming it into quarantine later on.
    open_streams = []
    try:
        if kind in ZIP_KINDS:
            stream = opener()
            open_streams.append(stream)
            archive = zipfile.ZipFile(stream)
            open_streams.append(archive)
            for info in archive.infolist():
                member = safe_text(to_text(info.filename))
                if member.endswith(u"/"):
                    continue
                if info.flag_bits & 0x1:
                    notes.append(u"%s%s is password-protected" % (prefix, member))
                    continue
                for entry in member_entries(prefix + member, info.file_size,
                                            lambda info=info: archive.open(info), depth, notes):
                    yield entry
        elif kind in TAR_OR_COMPRESSED_KINDS:
            stream = opener()
            open_streams.append(stream)
            try:
                tar = tarfile.open(fileobj=stream, mode="r:*")
                open_streams.append(tar)
            except tarfile.TarError:
                tar = None
            if tar is not None:
                for member in tar:
                    if not member.isfile():
                        continue
                    for entry in member_entries(prefix + safe_text(to_text(member.name)), member.size,
                                                lambda member=member: tar.extractfile(member), depth, notes):
                        yield entry
            else:
                # one compressed file (gzip, bzip2 or xz): named after the gzip header when it
                # has one, else after the archive itself without the compression suffix
                stream.seek(0)
                head = stream.read(512)
                stem = os.path.basename(name)
                for ext in (u".gz", u".bz2", u".xz", u".bzip2", u".gzip"):
                    if stem.lower().endswith(ext):
                        stem = stem[:-len(ext)]
                        break
                if head.startswith(b"\x1f\x8b"):
                    member = gzip_member_name(head, stem)
                    decompress = lambda: Decompressed(opener(), lambda raw: gzip.GzipFile(fileobj=raw))
                elif head.startswith(b"BZh"):
                    member, decompress = stem, lambda: Decompressed(opener(), bz2.BZ2File)
                elif head.startswith(b"\xfd7zXZ\x00") and lzma is not None:
                    member, decompress = stem, lambda: Decompressed(opener(), lzma.LZMAFile)
                else:
                    notes.append(u"cannot read %s from here" % name)
                    return
                for entry in member_entries(prefix + safe_text(member), None, decompress, depth, notes):
                    yield entry
        else:
            notes.append(u"cannot look inside a %s archive from here" % kind)
    except (zipfile.BadZipfile, tarfile.TarError, IOError, OSError, EOFError, zlib.error,
            RuntimeError, ValueError, NotImplementedError) as exc:
        notes.append(u"could not read %s (%s)" % (name, to_text(str(exc)) or exc.__class__.__name__))
    finally:
        for handle in reversed(open_streams):
            close_quietly(handle)


def close_quietly(handle):
    try:
        handle.close()
    except Exception:  # pragma: no cover - closing is best effort
        pass


class Decompressed(object):
    """A decompressing reader (gzip, bzip2, xz) over a raw stream that closes both when
    closed; the standard library readers leave a stream they were handed open."""

    def __init__(self, raw, wrap):
        self.raw = raw
        try:
            self.inner = wrap(raw)
        except Exception:
            close_quietly(raw)
            raise

    def read(self, size=-1):
        return self.inner.read(size)

    def close(self):
        close_quietly(self.inner)
        close_quietly(self.raw)


def member_entries(display, size, opener, depth, notes):
    """One member: descend into it when it is an archive itself, else yield it."""
    if depth < INSPECT_MAX_DEPTH:
        try:
            probe = opener()
            try:
                head = probe.read(512)
            finally:
                close_quietly(probe)
        except (IOError, OSError, EOFError, zlib.error, RuntimeError, ValueError, NotImplementedError) as exc:
            notes.append(u"could not read %s (%s)" % (display, to_text(str(exc)) or exc.__class__.__name__))
            return
        inner = archive_kind_of_bytes(head, display)
        if inner:
            for entry in walk_archive(opener, inner, display, display + u"!", depth + 1, notes):
                yield entry
            return
    yield (display, size, opener)


def read_up_to(stream, limit):
    """Up to limit + 1 bytes from stream: one byte more than limit tells the caller there is more."""
    chunks, total = [], 0
    while total <= limit:
        chunk = stream.read(min(INSPECT_CHUNK, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def search_stream(stream, needles, overlap, budget, head=b""):
    """Which needles (plain bytes) occur in head + the rest of stream, read chunk by chunk
    while budget lasts: (hits, budget left, exhausted). head is content already read and
    charged; a needle straddling the head and the first chunk is still found."""
    hits = set(needle for needle in needles if needle in head)
    tail = head[-overlap:] if overlap else b""
    while budget > 0:
        chunk = stream.read(INSPECT_CHUNK)
        if not chunk:
            return hits, budget, False
        budget -= len(chunk)
        window = tail + chunk
        for needle in needles:
            if needle not in hits and needle in window:
                hits.add(needle)
        tail = window[-overlap:] if overlap else b""
    return hits, budget, True


def inspect_archive(archive):
    """Fill in archive.inside, .unplaced and .note: which files inside hold the secrets
    TruffleHog reported. zip, tar (any compression), gzip, bzip2 and xz are opened with the
    standard library, archives nested in archives too; at most INSPECT_BUDGET_BYTES of
    content is read, every byte decompressed counted once. Members up to
    INSPECT_FULL_READ_BYTES are searched like files (same decoders), bigger ones chunk by
    chunk for the plain text. Nothing is written."""
    notes = []
    if archive.kind in ("gzip", "bzip2", "xz"):
        # the magic bytes say "compressed"; is it a compressed tar? (shown as tar.gz etc.)
        try:
            tarfile.open(archive.path, "r:*").close()
            archive.kind = u"tar." + {"gzip": u"gz", "bzip2": u"bz2", "xz": u"xz"}[archive.kind]
            if archive.why.endswith(u" archive"):
                archive.why = archive.kind + u" archive"
            if archive.item is not None:
                archive.item.note = archive.why
        except (tarfile.TarError, IOError, OSError, EOFError, zlib.error, ValueError):
            pass
    wanted = [(finding, [c for c in candidate_secrets(finding) if c]) for finding in archive.findings]
    needles = sorted(set(to_bytes(c) for _, cs in wanted for c in cs), key=len, reverse=True)
    overlap = len(needles[0]) - 1 if needles else 0
    budget = INSPECT_BUDGET_BYTES
    held = OrderedDict()
    exhausted = False
    opener = lambda: io.open(archive.path, "rb")
    name = os.path.basename(archive.path)
    for display, size, member_opener in walk_archive(opener, archive.kind, name, u"", 0, notes):
        if budget <= 0:
            exhausted = True
            break
        found = []
        stream = None
        try:
            stream = member_opener()
            data = b"" if (size is not None and size > INSPECT_FULL_READ_BYTES) else read_up_to(stream, INSPECT_FULL_READ_BYTES)
            budget -= len(data)
            if data and len(data) <= INSPECT_FULL_READ_BYTES:
                for finding, candidates in wanted:
                    if any(locate(data, c, finding.decoder) for c in candidates):
                        found.append(finding)
            else:
                # too big to hold: the part already read is searched for the plain text and the
                # rest follows from the same stream, so nothing is decompressed or charged twice
                hits, budget, ran_out = search_stream(stream, needles, overlap, budget, data)
                exhausted = exhausted or ran_out
                for finding, candidates in wanted:
                    if any(to_bytes(c) in hits for c in candidates):
                        found.append(finding)
        except (IOError, OSError, EOFError, zlib.error, RuntimeError, ValueError, NotImplementedError) as exc:
            notes.append(u"could not read %s (%s)" % (display, to_text(str(exc)) or exc.__class__.__name__))
            continue
        finally:
            if stream is not None:
                close_quietly(stream)
        if found:
            held[display] = found
    placed = set(id(f) for found in held.values() for f in found)
    archive.inside = list(held.items())
    archive.unplaced = [f for f in archive.findings if id(f) not in placed]
    if exhausted:
        notes.append(u"stopped looking after %d MB of content; the rest was not checked"
                     % (INSPECT_BUDGET_BYTES // (1024 * 1024)))
    if archive.unplaced and (archive.inside or notes):
        decoders = sorted(set(f.decoder for f in archive.unplaced))
        notes.append(u"%d secret(s) not found verbatim in any file inside (TruffleHog decoder: %s)"
                     % (len(archive.unplaced), u", ".join(decoders)))
    if len(notes) > 3:
        notes = notes[:3] + [u"and %d more problem(s)" % (len(notes) - 3)]
    archive.note = u"; ".join(notes)


def build_plan(findings, root, store, args, env_plaintext, exclude_res=(), decryptor=None, quarantine=None):
    plan = Plan(root, store, quarantine)
    plan.args = args
    cache = {}
    raw_cache = {}
    seen = {}
    leftovers = []   # (finding, why): secrets in text files that could not be handled
    compiled_cache = {}
    ordered = sorted(findings, key=lambda f: (f.path, f.line, f.raw))
    for finding in ordered:
        if exclude_res and is_excluded(finding.path, exclude_res):
            plan.ignored += 1   # TruffleHog did not honour the exclude (Windows paths); we do
            continue
        kind = compiled_kind(finding.path, compiled_cache)
        if kind:
            # a program or library: never rewritten or moved; listed with --scan-compiled, else set aside
            if args.scan_compiled:
                entry = plan.compiled.get(finding.path)
                if entry is None:
                    entry = plan.compiled[finding.path] = CompiledFile(finding.path, kind)
                entry.findings.append(finding)
            else:
                plan.compiled_skipped[finding.path] = kind
                log_only(u"set aside, compiled code: %s (%s) %s" % (plan.rel(finding.path), kind, finding.detector))
            continue
        data, reason = load_for_edit(finding.path, cache)
        if data is None:
            if not reason.endswith(u" archive"):
                raw = file_bytes(finding.path, raw_cache)
                if inside_integrity_hash(finding, raw):
                    set_aside_hash(plan, finding, u"inside a package integrity hash")
                    continue
                if reason == u"generated lock file" and lockfile_identifier(finding, raw):
                    set_aside_hash(plan, finding, u"a checksum or commit id in a lock file")
                    continue
            entry = plan.unfixable.get(finding.path)
            if entry is None:
                kind = archive_kind(finding.path) if reason.endswith(u" archive") else None
                movable = not (reason.startswith(u"symbolic link") or reason.startswith(u"file is gone"))
                entry = Unfixable(finding.path, reason, kind, movable)
                plan.unfixable[finding.path] = entry
            entry.findings.append(finding)
            continue
        if inside_integrity_hash(finding, data):
            set_aside_hash(plan, finding, u"inside a package integrity hash")
            continue
        located = False
        too_short = False
        for candidate in candidate_secrets(finding):
            if len(candidate) < args.min_length:
                too_short = True
                continue
            for token_bytes, encoding, offset, canonical in locate(data, candidate, finding.decoder):
                located = True
                ident = (finding.path, token_bytes)
                if ident in seen:
                    continue
                line = data.count(b"\n", 0, offset) + 1
                line_start = data.rfind(b"\n", 0, offset) + 1
                prefix = data[line_start:offset].decode(encoding, "replace")
                item = Item(finding.path, offset, line, finding.detector, finding.verified,
                            canonical, token_bytes, encoding, finding.extra)
                item.context = guess_name_from_prefix(prefix)
                seen[ident] = item
                plan.items.append(item)
        if not located:
            if too_short:
                why = u"secret shorter than %d characters (--min-length)" % args.min_length
            elif (finding.decoder or u"PLAIN").upper() != u"PLAIN":
                why = u"secret is %s-encoded in the file" % finding.decoder
            else:
                why = u"secret text not found verbatim in the file"
            leftovers.append((finding, why))

    # Secrets found inside env files: which KEY=... entries hold the secret? Every one of
    # them must be encrypted, so each becomes an item of its own.
    text_cache = {}
    twins = []
    for item in plan.items:
        if item.kind == "quarantine":
            continue
        if not is_env_file(os.path.basename(item.path)):
            item.kind = "source"
            continue
        if item.path not in text_cache:
            text_cache[item.path] = list(parse_env_entries(to_text(cache[item.path][0])))
        holders = [(key, line) for key, value, line in text_cache[item.path]
                   if value_holds(value, item.secret) and not value.startswith(ENCRYPTED_PREFIX)]
        if not holders:
            item.kind = "source"   # e.g. a secret in a comment of the .env file
            continue
        item.kind, item.key, item.store, item.line = "env", holders[0][0], item.path, holders[0][1]
        for key, line in holders[1:]:
            twin = Item(item.path, item.offset, line, item.detector, item.verified, item.secret,
                        item.secret_bytes, item.encoding, item.extra)
            twin.kind, twin.key, twin.store = "env", key, item.path
            twins.append(twin)
    plan.items.extend(twins)

    # --env-all: every other plaintext key in env files becomes an item too.
    if args.env_all:
        covered = set((item.path, item.key) for item in plan.items if item.kind == "env")
        for path, key, line, value in env_plaintext:
            if (path, key) in covered or not value.strip():
                continue
            data, reason = load_for_edit(path, cache)
            if data is None:
                continue
            item = Item(path, 0, line, "env file", False, value, to_bytes(value), "utf-8", {})
            item.kind, item.key, item.store = "env", key, path
            plan.items.append(item)
            covered.add((path, key))

    plan.items.sort(key=lambda it: (it.path, it.line, it.offset))
    assign_names(plan, decryptor)

    # A value dotenvx cannot store exactly must not be moved: the mangled copy would be
    # the only one left. Every copy of it joins the secrets that cannot be fixed in place:
    # the later copies share the first one's key, which is never written.
    unstorable = set(item.secret for item in plan.items
                     if item.kind == "source" and item.new_entry and not quote_env_value(item.secret)[1])
    keep = []
    for item in plan.items:
        if item.kind == "source" and item.secret in unstorable:
            stand_in = Finding(item.path, item.line, item.detector, item.secret, u"", item.verified, "PLAIN",
                               item.extra)
            leftovers.append((stand_in, u"value cannot be stored exactly by dotenvx (%s)"
                              % inexact_reason(item.secret)))
            continue
        keep.append(item)
    plan.items = keep

    # Files that cannot be fixed in place. A text file some of whose secrets are fixed above is
    # listed for the rest but never moved: moving it would undo the fixes. Nor is the env file
    # that receives other files' secrets: the placeholders written there point into it.
    fixable = set(item.path for item in plan.items if item.kind in ("env", "source"))
    stores = set(os.path.normpath(item.store) for item in plan.items if item.kind == "source")
    for finding, why in leftovers:
        entry = plan.unfixable.get(finding.path)
        if entry is None:
            entry = Unfixable(finding.path, why, None, movable=finding.path not in fixable)
            entry.partial = finding.path in fixable
            plan.unfixable[finding.path] = entry
        elif why not in entry.why:
            entry.why += u"; " + why
        entry.findings.append(finding)
    for entry in plan.unfixable.values():
        if os.path.normpath(entry.path) in stores:
            entry.movable, entry.in_use = False, True
        if entry.kind:
            inspect_archive(entry)   # which files inside hold the secrets: shown in the listing
        if entry.movable and quarantine:
            first = entry.findings[0]
            item = Item(entry.path, 0, 0, u", ".join(detectors_of(entry.findings)),
                        any(f.verified for f in entry.findings), first.raw, b"", "utf-8", first.extra)
            item.kind, item.key, item.note = "quarantine", u"-", entry.why
            entry.item = item
            plan.items.append(item)

    plan.items.sort(key=lambda it: (it.path, it.line, it.offset))
    for number, item in enumerate(plan.items, 1):
        item.number = number
    return plan


def set_aside_hash(plan, finding, what):
    """Count a finding that is a public identifier (inside a package integrity hash, or a checksum
    or commit id in a lock file), and name it in the run log so that a set-aside can always be
    checked afterwards (the value itself is never logged)."""
    plan.hashes += 1
    log_only(u"set aside, %s: %s line %s (%s)" % (what, plan.rel(finding.path), finding.line, finding.detector))


UNKNOWN = object()   # an encrypted store value we could not decrypt here


def assign_names(plan, decryptor=None):
    """Decide the env var name and storage file for every 'source' item.

    A secret that already sits in the store under some key - in plaintext, or
    encrypted where the private key lets us check - is reused under that key,
    so a second run (after --no-rewrite, a crash or a failed rewrite) does not
    pile up KEY_2, KEY_3 duplicates. A name that is taken by a different value
    gets a numeric suffix, and the listing says why.
    """
    store_entries = []
    if os.path.isfile(plan.store):
        try:
            store_entries = list(parse_env_entries(read_text(plan.store)))
        except (IOError, OSError):
            store_entries = []
    by_secret = {}
    for item in plan.items:
        if item.kind == "env":
            by_secret.setdefault(item.secret, (item.key, item.path))
    pending = [item for item in plan.items if item.kind == "source" and item.secret not in by_secret]

    # What the store holds, by key (last definition wins, as it does for dotenvx):
    # plaintext as written, encrypted values decrypted when we can.
    values = OrderedDict()
    plaintext_keys = set()
    for key, value, _ in store_entries:
        if value.startswith(ENCRYPTED_PREFIX):
            if pending and decryptor is not None:
                decrypted, _reason = decryptor(plan.store, key)
                values[key] = UNKNOWN if decrypted is None else decrypted
            else:
                values[key] = UNKNOWN
            plaintext_keys.discard(key)
        else:
            values[key] = value
            plaintext_keys.add(key)
    taken = dict(values)
    for item in plan.items:
        if item.kind == "env":
            taken[item.key] = item.secret

    for item in plan.items:
        if item.kind != "source":
            continue
        if item.secret in by_secret:
            item.key, item.store = by_secret[item.secret]
            continue
        same_value = [key for key, value in values.items() if value == item.secret]
        if same_value:
            item.key, item.store = same_value[0], plan.store
        else:
            contexts = [other.context for other in plan.items
                        if other.secret == item.secret and other.context]
            base = choose_name(item.detector, contexts[0] if contexts else None, item.secret)
            name, counter = base, 2
            while name in taken and taken[name] != item.secret:
                name = u"%s_%d" % (base, counter)
                counter += 1
            if name != base:
                if taken[base] is UNKNOWN:
                    item.note = u"%s holds an encrypted value that could not be decrypted here" % base
                else:
                    item.note = u"%s already holds a different value" % base
            taken[name] = item.secret
            item.key, item.store, item.new_entry = name, plan.store, True
        # Plaintext entries of the store that hold this secret (equal to it, or containing
        # it) must be encrypted along, or the secret would stay readable there.
        for key in plaintext_keys:
            if value_holds(values[key], item.secret):
                extra = plan.extra_env_keys.setdefault(plan.store, [])
                if key not in extra:
                    extra.append(key)
        by_secret[item.secret] = (item.key, item.store)


# --------------------------------------------------------------------------
# Showing the plan and asking
# --------------------------------------------------------------------------

def table(rows, headers, indent=u"  "):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = [indent + u"  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    for row in rows:
        lines.append(indent + u"  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
    return lines


def action_text(item, plan, args):
    if item.kind == "quarantine":
        return u"move to %s%s" % (plan.rel(quarantine_target(item, plan)), u" (encrypted)" if plan.quarantine_crypto else u"")
    store = plan.rel(item.store)
    if item.kind == "env":
        return u"encrypt in place"
    placeholder = args.placeholder.replace("NAME", item.key)
    why = u" (%s)" % item.note if item.note else u""
    if args.no_rewrite:
        return u"store encrypted in %s (file left as is)%s" % (store, why)
    if item.new_entry:
        return u"move to %s, replace with %s%s" % (store, placeholder, why)
    return u"replace with %s (value already in %s)" % (placeholder, store)


def find_openssl(args):
    """The openssl that encrypts quarantined files: --openssl, the PATH, or on Windows the copies
    Git for Windows and the OpenSSL installers put under Program Files. None when there is none."""
    chosen = getattr(args, "openssl", None)
    if chosen:
        return fs_text(chosen) if os.path.isfile(chosen) else None
    found = which("openssl")
    if found:
        return fs_text(found)
    if sys.platform.startswith("win"):
        for place in OPENSSL_WINDOWS_PLACES:
            if os.path.isfile(place):
                return place
    return None


def openssl_run(openssl, kdf, src, dst, passphrase, decrypt=False):
    """`openssl enc [-d] -aes-256-cbc [-pbkdf2] -salt -pass stdin -in src -out dst`, the passphrase
    on stdin so that it never shows in a process list. Returns (ok, last line of openssl's output)."""
    cmd = [openssl, "enc"]
    if decrypt:
        cmd.append("-d")
    cmd.append("-" + QUARANTINE_CIPHER)
    if kdf == "pbkdf2":
        cmd.append("-pbkdf2")
    if not decrypt:
        cmd.append("-salt")
    cmd.extend(["-pass", "stdin", "-in", src, "-out", dst])
    log_only(u"$ " + u" ".join(cmd) + u"   (the passphrase goes in on stdin)")
    try:
        code, out, err = run_command(cmd, stdin_text=passphrase + u"\n")
    except (OSError, IOError) as exc:
        return False, to_text(str(exc))
    lines = [line.strip() for line in (out + u"\n" + err).splitlines()
             if line.strip() and u"would be better" not in line]   # the legacy derivation's advice line
    detail = lines[-1] if lines else u""
    if code != 0 or not os.path.isfile(dst):
        return False, detail or u"openssl exited with status %d" % code
    return True, detail


def openssl_setup(openssl):
    """Probe openssl once: its version line and the key derivation `enc` accepts, -pbkdf2 (OpenSSL
    1.1.1 and later) or the old one. Fills and returns OPENSSL_INFO; "kdf" stays None when openssl
    cannot round-trip a probe file, with "error" saying what it said."""
    if OPENSSL_INFO.get("path") == openssl and OPENSSL_INFO.get("probed"):
        return OPENSSL_INFO
    info = {"path": openssl, "version": u"", "kdf": None, "error": u"", "probed": True}
    try:
        code, out, err = run_command([openssl, "version"])
        text = (out + u"\n" + err).strip()
        info["version"] = text.splitlines()[0].strip() if text else u""
        scratch = tempfile.mkdtemp(prefix=TEMP_PREFIX)
    except (IOError, OSError) as exc:
        info["error"] = to_text(str(exc))
        OPENSSL_INFO.clear()
        OPENSSL_INFO.update(info)
        return info
    try:
        src = os.path.join(scratch, "probe.txt")
        write_bytes(src, b"sweep-and-secure openssl probe\n")
        for kdf in ("pbkdf2", "legacy"):
            enc, back = os.path.join(scratch, "probe." + kdf), os.path.join(scratch, "back." + kdf)
            ok, detail = openssl_run(openssl, kdf, src, enc, u"probe passphrase")
            if ok:
                ok, detail = openssl_run(openssl, kdf, enc, back, u"probe passphrase", decrypt=True)
            if ok and os.path.isfile(back) and read_bytes(back) == read_bytes(src):
                info["kdf"] = kdf
                break
            info["error"] = detail or u"the probe file did not round-trip"
    except (IOError, OSError) as exc:
        info["error"] = to_text(str(exc))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    OPENSSL_INFO.clear()
    OPENSSL_INFO.update(info)
    return info


def sha256_file(path):
    digest = hashlib.sha256()
    with io.open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def remove_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


PUBLIC_KEY_VALUE_RE = re.compile(r"^\s*DOTENV_PUBLIC_KEY(\w*)\s*=\s*[\"']?([0-9A-Za-z]+)", re.M)


def store_public_key(store):
    """(name suffix, value) of the public key the store env file carries, or (None, None)."""
    try:
        match = PUBLIC_KEY_VALUE_RE.search(read_text(store))
    except (IOError, OSError):
        match = None
    return (match.group(1), match.group(2)) if match else (None, None)


def store_private_key_env(store, root):
    """{"DOTENV_PRIVATE_KEY": value} when the store's private key sits in a keys file: how a dotenvx
    too old for -fk is handed the key of another file that shares the store's key pair."""
    suffix, value = store_public_key(store)
    if suffix is None:
        return {}
    private = private_keys_from(discover_keys_files([store], root)).get("DOTENV_PRIVATE_KEY" + suffix)
    return {"DOTENV_PRIVATE_KEY": private} if private else {}


def prepare_quarantine_crypto(plan, dotenvx, args):
    """Can quarantined files be encrypted here? Sets plan.quarantine_crypto, or
    plan.quarantine_plain_reason when they will have to be moved as they are."""
    plan.quarantine_crypto, plan.quarantine_plain_reason = None, u""
    openssl = find_openssl(args)
    if not openssl:
        plan.quarantine_plain_reason = (u"openssl was not found at --openssl %s" % fs_text(args.openssl)
                                        if getattr(args, "openssl", None)
                                        else u"openssl was not found (install it, or point --openssl at it)")
        return
    info = openssl_setup(openssl)
    if not info.get("kdf"):
        plan.quarantine_plain_reason = u"openssl at %s could not encrypt a probe file (%s)" % (
            openssl, info.get("error") or info.get("version") or u"no output")
        return
    plan.quarantine_crypto = {"openssl": openssl, "kdf": info["kdf"], "dotenvx": dotenvx, "version": info.get("version", u"")}


def quarantine_env_path(plan):
    return os.path.join(plan.quarantine, QUARANTINE_KEYS_ENV)


def next_quarantine_key_name(env_path):
    """QUARANTINE_KEY_<n>, one above the highest number already in the quarantine's .env."""
    highest = 0
    try:
        for key, _, _ in parse_env_entries(read_text(env_path)):
            tail = key[len(QUARANTINE_KEY_PREFIX):]
            if key.startswith(QUARANTINE_KEY_PREFIX) and tail.isdigit():
                highest = max(highest, int(tail))
    except (IOError, OSError):
        pass
    return u"%s%d" % (QUARANTINE_KEY_PREFIX, highest + 1)


def quarantine_shares_store(plan):
    """Is the quarantine's .env encrypted to the store's key pair (same public key)?"""
    env_path = quarantine_env_path(plan)
    if not plan.store or not os.path.isfile(env_path):
        return False
    public = store_public_key(env_path)[1]
    return public is not None and public == store_public_key(plan.store)[1]


def store_key_at_hand(plan, dotenvx):
    """Can dotenvx decrypt the store here? Proven on one of its encrypted entries; a store with
    no encrypted entry (or none) proves nothing, and the quarantine then gets its own key pair."""
    if not plan.store or not os.path.isfile(plan.store):
        return False
    try:
        entries = parse_env_entries(read_text(plan.store))
    except (IOError, OSError):
        return False
    for key, value, _ in entries:
        if value.startswith(ENCRYPTED_PREFIX):
            got, _ = decrypt_env_value(dotenvx, plan.store, key, plan.root, plan.args)
            return got is not None
    return False


def quarantine_decryptor(plan, dotenvx):
    """A decryptor for the quarantine's .env. When it shares the store's key pair, that key file sits
    elsewhere and an old dotenvx needs the key from the environment; when it has a key pair of its
    own, the store's key must not get in the way (dotenvx tries the environment first)."""
    if not quarantine_shares_store(plan):
        return make_decryptor(dotenvx, plan.root, plan.args)
    return make_decryptor(dotenvx, plan.root, plan.args, extra_env=store_private_key_env(plan.store, plan.root),
                          extra_keys_files=discover_keys_files([plan.store], plan.root))


def store_quarantine_key(plan, name, passphrase, journal):
    """Keep the passphrase of one encrypted quarantine file in the quarantine's .env, encrypted by
    dotenvx: to the store's key pair when the store has one (its public key is seeded into the new
    file, so no second key pair appears), else to a key pair of the quarantine's own, with the usual
    custody. Returns (ok, note, warnings) like encrypt_env_file."""
    dotenvx = plan.quarantine_crypto["dotenvx"]
    env_path = quarantine_env_path(plan)
    created = not os.path.isfile(env_path)
    if created:
        public = store_public_key(plan.store)[1] if plan.store else None
        header = (u"# The passphrase of each *.enc file in this quarantine, kept encrypted by dotenvx.\n"
                  u"# Restore a file:  sweep-and-secure --restore <stored name>   (MANIFEST.txt has the openssl recipe)\n")
        if public and store_key_at_hand(plan, dotenvx):
            header += u"DOTENV_PUBLIC_KEY=\"%s\"\n" % public
        write_bytes(env_path, header.encode("utf-8"))
        try:
            os.chmod(env_path, 0o600)
        except (IOError, OSError):
            pass
    job = {"new": [(name, passphrase)], "keys": [name], "items": []}
    ok, note, warnings = encrypt_env_file(env_path, job, dotenvx, plan.root, plan.args, quarantine_decryptor(plan, dotenvx),
                                          journal, custody=plan.custody, strict=True)
    if not ok and created:
        remove_quietly(env_path)   # a header without a single key: the next run starts afresh
        plan.custody.pop(env_path, None)
    return ok, note, warnings


def encrypt_into_quarantine(plan, source, candidate, journal):
    """Encrypt source into candidate inside the quarantine folder: openssl under a fresh passphrase,
    the copy decrypted again and compared, the passphrase kept by dotenvx in the quarantine's .env,
    and only then the source removed. Returns (index record extras, warnings); raises IOError with
    the source untouched when a step fails."""
    crypto = plan.quarantine_crypto
    passphrase = to_text(binascii.hexlify(os.urandom(32)))
    size = os.path.getsize(source)
    ok, detail = openssl_run(crypto["openssl"], crypto["kdf"], source, candidate, passphrase)
    if not ok:
        remove_quietly(candidate)
        raise IOError(u"openssl could not encrypt it: %s" % detail)
    digest = sha256_file(source)
    staging = make_staging_dir(plan.root)   # the check copy goes where an interrupted run's leftovers are cleaned up
    check = os.path.join(staging, os.path.basename(candidate) + u".check")
    try:
        ok, detail = openssl_run(crypto["openssl"], crypto["kdf"], candidate, check, passphrase, decrypt=True)
        if not ok or sha256_file(check) != digest:
            raise IOError(u"the encrypted copy does not decrypt back to the original (%s)"
                          % (detail or u"different content"))
    except (IOError, OSError):
        remove_quietly(candidate)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    name = next_quarantine_key_name(quarantine_env_path(plan))
    ok, note, warnings = store_quarantine_key(plan, name, passphrase, journal)
    if not ok:
        remove_quietly(candidate)
        raise IOError(u"its passphrase could not be stored with dotenvx: %s" % note)
    if journal is not None:
        journal.add("quarantine", source, candidate)   # before anything else can fail: the copy is in place
    try:
        os.remove(source)
    except OSError:
        remove_quietly(candidate)
        raise
    extras = OrderedDict([("encrypted", True), ("key", name), ("cipher", QUARANTINE_CIPHER), ("kdf", crypto["kdf"]),
                          ("sha256", digest), ("size", size)])
    return extras, warnings


def quarantine_target(item, plan):
    """Where --quarantine puts this file: the same relative path under the quarantine folder (plus
    .enc when the quarantine is encrypted), with a numeric suffix when that name is taken there or
    is one of the quarantine's own files (MANIFEST.txt, index.json, .env), which a moved file must
    never replace."""
    try:
        rel = os.path.relpath(item.path, plan.root)
    except ValueError:
        rel = os.path.basename(item.path)
    if rel.startswith(".."):
        rel = os.path.basename(item.path)
    suffix = ENCRYPTED_SUFFIX if plan.quarantine_crypto else u""
    target = os.path.join(plan.quarantine, rel)
    reserved = rel.lower() in QUARANTINE_OWN_FILES
    candidate, counter = target + suffix, 1
    while reserved or os.path.exists(candidate):
        reserved = False
        candidate = u"%s.%d%s" % (target, counter, suffix)
        counter += 1
    return candidate


def move_to_quarantine(item, plan, journal=None):
    """Move one file out of the tree into the quarantine folder, under its relative path (a
    numeric suffix when that name is taken or reserved). Rename when possible; copy then delete across
    file systems. The move is journaled first; then a line goes into the quarantine's
    MANIFEST.txt and a record into its index.json, both mapping the stored name to where
    the file came from. Returns (new path, warning): the warning is set when the file moved
    but the manifest or index could not be written."""
    candidate = quarantine_target(item, plan)   # a free name, .enc when the quarantine is encrypted
    folder = os.path.dirname(candidate)
    if not os.path.isdir(folder):
        os.makedirs(folder)
    crypto = plan.quarantine_crypto
    extras = OrderedDict()
    warnings = []
    try:
        extras["mode"] = u"%04o" % stat.S_IMODE(os.stat(item.path).st_mode)   # openssl writes with the default mode
    except (IOError, OSError):
        pass
    if crypto:
        # encrypt into place, prove the copy decrypts back to the original, keep the passphrase with
        # dotenvx, and only then remove the original
        more, key_warnings = encrypt_into_quarantine(plan, item.path, candidate, journal)
        extras.update(more)
        warnings.extend(key_warnings)
    else:
        try:
            os.rename(item.path, candidate)
        except OSError:
            # another file system: copy into place under a temporary name, then remove the original
            handle, tmp = tempfile.mkstemp(prefix=TEMP_PREFIX, dir=folder)
            os.close(handle)
            try:
                shutil.copy2(item.path, tmp)
                if os.path.getsize(tmp) != os.path.getsize(item.path):
                    raise IOError(u"copy of %s is incomplete" % item.path)
                (getattr(os, "replace", None) or os.rename)(tmp, candidate)
            except BaseException:
                remove_quietly(tmp)
                raise
            os.remove(item.path)
        if journal is not None:
            journal.add("quarantine", item.path, candidate)   # before anything else can fail: the file has moved
        extras["encrypted"] = False
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry = plan.unfixable.get(item.path)
    inside = [safe_text(member) for member, _ in entry.inside] if entry is not None else []
    stored = slash_path(os.path.relpath(candidate, plan.quarantine))
    record = OrderedDict([
        ("quarantined", stored),                 # relative to the quarantine folder
        ("original", plan.rel(item.path)),       # relative to the swept folder
        ("original_absolute", slash_path(item.path)),
        ("moved_at", stamp),
        ("why", entry.why if entry is not None else u""),
        ("detectors", item.detector.split(u", ")),
        ("inside", inside),
    ])
    record.update(extras)
    if extras.get("encrypted"):
        tail = u"  enc: %s (%s, kdf %s)" % (extras["key"], extras["cipher"], extras["kdf"])
    else:
        tail = u"  PLAINTEXT" if plan.quarantine_plain_reason else u""
    line = u"%s  %s  <- %s  (%s)  why: %s%s%s\n" % (stamp, stored, record["original"], item.detector, record["why"],
                                                     (u"  inside: " + u", ".join(inside)) if inside else u"", tail)
    problems = []
    manifest = os.path.join(plan.quarantine, QUARANTINE_MANIFEST)
    try:
        with io.open(manifest, "ab") as fh:
            if fh.tell() == 0:
                fh.write(QUARANTINE_MANIFEST_HEADER.encode("utf-8"))
            fh.write(line.encode("utf-8", "replace"))
    except (IOError, OSError, UnicodeError) as exc:
        problems.append(u"%s could not be updated: %s" % (QUARANTINE_MANIFEST, to_text(str(exc))))
    index = os.path.join(plan.quarantine, QUARANTINE_INDEX)
    try:
        records = []
        if os.path.isfile(index):
            try:
                loaded = json.loads(read_text(index))
                if isinstance(loaded, list):
                    records = loaded
            except ValueError:
                problems.append(u"%s was not valid JSON and was rewritten" % QUARANTINE_INDEX)
        records.append(record)
        write_bytes(index, (json.dumps(records, indent=2, ensure_ascii=False) + u"\n").encode("utf-8", "replace"))
    except (IOError, OSError, UnicodeError, ValueError, TypeError) as exc:
        problems.append(u"%s could not be updated: %s" % (QUARANTINE_INDEX, to_text(str(exc))))
    problems = warnings + problems
    if problems:
        return candidate, u"moved, but " + u"; ".join(problems)
    return candidate, u""


def keys_file_holding(env_path, keys_files):
    """(keys file, key name) when one of keys_files holds the private key named after env_path's
    public key (DOTENV_PRIVATE_KEY<suffix>), the file nearest the env file first; else None."""
    suffix = store_public_key(env_path)[0]
    if suffix is None:
        return None
    wanted = u"DOTENV_PRIVATE_KEY" + suffix
    for keys_file in reversed(list(keys_files)):   # discover_keys_files lists the root's file first
        try:
            for key, value, _ in parse_env_entries(read_text(keys_file)):
                if key == wanted and value:
                    return keys_file, wanted
        except (IOError, OSError):
            continue
    return None


def key_file_serves(env_path, keys_file, dotenvx, plan, args):
    """Does the private key in keys_file decrypt env_path? A key of the same name may belong to
    another file (a header that does not follow dotenvx's naming), so it is proven by decrypting one
    value of the file with the key files alone: no OS store, no key from the environment."""
    try:
        entries = parse_env_entries(read_text(env_path))
    except (IOError, OSError):
        return False
    key = next((k for k, v, _ in entries if v.startswith(ENCRYPTED_PREFIX)), None)
    if key is None:
        return False
    environment = dict((name, "") for name in os.environ if name.startswith("DOTENV_PRIVATE_KEY"))
    environment["DOTENVX_NO_NATIVE"] = "true"
    value, _reason = decrypt_env_value(dotenvx, env_path, key, plan.root, args, extra_env=environment,
                                       extra_keys_files=[keys_file])
    return value is not None


def quarantine_records(plan):
    """The quarantine's index.json records, or [] when there is none that can be read."""
    if not plan.quarantine:
        return []
    try:
        records = json.loads(read_text(os.path.join(plan.quarantine, QUARANTINE_INDEX)))
    except (IOError, OSError, ValueError):
        return []
    return records if isinstance(records, list) else []


def plaintext_quarantine_records(records, plan):
    """The records of files the quarantine holds as they are (moved by an earlier version, or without
    openssl), still there and not restored."""
    found = []
    for record in records:
        if not isinstance(record, dict) or record.get("encrypted") or record.get("restored_at"):
            continue
        stored = record.get("quarantined")
        if stored and os.path.isfile(os.path.join(plan.quarantine, stored.replace(u"/", os.sep))):
            found.append(record)
    return found


def plan_setup_upgrades(plan, env_paths, dotenvx, args):
    """What this run can tighten in a folder dotenvx already manages: a private key sitting in a
    .env.keys file that the OS secret store could hold instead (one entry per key pair), and files
    the quarantine holds as they are. Sets and returns plan.upgrades."""
    upgrades = {"keys": [], "quarantine": []}
    candidates = []
    extra = [plan.store, quarantine_env_path(plan) if plan.quarantine else None]
    for path in list(env_paths) + extra:
        if path and path not in candidates and os.path.isfile(path) and store_public_key(path)[1]:
            candidates.append(path)
    if native_store_wanted(args):
        seen = set()
        for env_path in candidates:
            public = store_public_key(env_path)[1]
            held = keys_file_holding(env_path, discover_keys_files([env_path], plan.root))
            if held and public not in seen and key_file_serves(env_path, held[0], dotenvx, plan, args):
                seen.add(public)
                upgrades["keys"].append((env_path, held[0], held[1]))
    records = quarantine_records(plan)
    plain = plaintext_quarantine_records(records, plan)
    if plain:
        if plan.quarantine_crypto is None and not plan.quarantine_plain_reason:
            prepare_quarantine_crypto(plan, dotenvx, args)
        if plan.quarantine_crypto:
            upgrades["quarantine"] = plain
    plan.upgrades = upgrades
    return upgrades


def upgrades_any(upgrades):
    return bool(upgrades and (upgrades["keys"] or upgrades["quarantine"]))


def upgrade_question(upgrades):
    parts = []
    if upgrades["keys"]:
        parts.append(u"move %d private key(s) into the %s" % (len(upgrades["keys"]), native_store_name()))
    if upgrades["quarantine"]:
        parts.append(u"encrypt %d quarantined file(s)" % len(upgrades["quarantine"]))
    return u"Tighten the setup now (%s)?" % u", ".join(parts)


def print_setup_upgrades(plan, upgrades, args, style):
    if not upgrades_any(upgrades):
        return
    say(u"")
    say(style.bold(u"Setup to tighten") + style.dim(u"  (left as it was by an earlier run or an earlier version)"))
    for env_path, keys_file, _name in upgrades["keys"]:
        say(u"  the private key of %s is in %s; dotenvx can keep it in the %s instead, with nothing on disk"
            % (plan.rel(env_path), plan.rel(keys_file), native_store_name()))
    if upgrades["quarantine"]:
        say(u"  %d file(s) in %s are stored as they are, secrets inside; they can be AES-256 encrypted, their"
            u" passphrases kept by dotenvx" % (len(upgrades["quarantine"]), plan.rel(plan.quarantine)))
    if args.dry_run:
        say(style.dim(u"  A run that asks offers this; --yes does it without asking; --no-native leaves keys in their files."))


def confirm_upgrades(upgrades, args, style):
    if args.yes:
        return True
    while True:
        answer = ask(style.bold(upgrade_question(upgrades) + u" [y/N]: ")).lower()
        if answer in (u"y", u"yes"):
            return True
        if answer in (u"", u"n", u"no", u"q", u"quit"):
            return False
        say(style.warn(u"Please answer y (yes) or n (no)."))


def move_key_to_store(plan, env_path, keys_file, dotenvx, args, style, journal):
    """`dotenvx native up` for one env file: the private key leaves its keys file for the OS secret
    store. Checked by decrypting a value of the file through dotenvx afterwards; `dotenvx native down`
    puts the key back when that fails. Returns True when the key is in the store."""
    store = native_store_name()
    rel, keys_rel = plan.rel(env_path), plan.rel(keys_file)
    if keys_file_holding(env_path, [keys_file]) is None:   # gone already: moved with a file above that shares it
        say(style.dim(u"  [--] %s: its private key is no longer in %s" % (rel, keys_rel)))
        return True
    ok, detail = dotenvx_native(dotenvx, "up", env_path, keys_file, plan.root, args)
    if not ok:
        say(u"  %s %s: the private key stays in %s: %s"
            % (style.warn("[--]"), rel, keys_rel, tidy_tool_line(detail) or u"dotenvx native up failed"))
        plan.upgrade_failures.append(env_path)
        return False
    try:
        key = next((k for k, v, _ in parse_env_entries(read_text(env_path)) if v.startswith(ENCRYPTED_PREFIX)), None)
    except (IOError, OSError):
        key = None
    if key is not None:
        value, reason = decrypt_env_value(dotenvx, env_path, key, plan.root, args)
        if value is None:
            back, detail = dotenvx_native(dotenvx, "down", env_path, keys_file, plan.root, args)
            say(u"  %s %s: the key went to the %s but dotenvx could not decrypt %s with it (%s); %s"
                % (style.bad("[!!]"), rel, store, key, reason,
                   u"it was put back into %s" % keys_rel if back else u"and could not be put back: " + tidy_tool_line(detail)))
            plan.upgrade_failures.append(env_path)
            return False
    if journal is not None:
        journal.add("keymove", env_path, keys_file)
    try:   # the "# -fk" hint on the public key line pointed at a file that no longer holds the key
        data = read_bytes(env_path)
        fixed = set_keys_hint(data, None)
        if fixed != data:
            write_bytes(env_path, fixed)
    except (IOError, OSError):
        pass
    plan.custody[env_path] = ("native", store, u"moved from %s" % keys_rel)
    say(u"  %s %s: private key moved from %s into the %s (nothing on disk)" % (style.ok("[ok]"), rel, keys_rel, store))
    return True


def encrypt_quarantined_record(plan, record, journal):
    """Encrypt one file the quarantine holds as it is, in place: <name> becomes <name>.enc, the record
    says how (key, cipher, derivation, digest, size, mode), and MANIFEST.txt gets a line. The index is
    read again before it is written: the files moved earlier in this run have records in it that the
    planning stage never saw. Returns (new stored name, problems)."""
    stored_rel = record["quarantined"]
    source = os.path.join(plan.quarantine, stored_rel.replace(u"/", os.sep))
    target, counter = source + ENCRYPTED_SUFFIX, 1
    while os.path.exists(target):
        target = u"%s.%d%s" % (source, counter, ENCRYPTED_SUFFIX)
        counter += 1
    try:
        mode = u"%04o" % stat.S_IMODE(os.stat(source).st_mode)
    except (IOError, OSError):
        mode = None
    extras, warnings = encrypt_into_quarantine(plan, source, target, journal)
    new_rel = slash_path(os.path.relpath(target, plan.quarantine))
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    changes = OrderedDict([("quarantined", new_rel)])
    changes.update(extras)
    if mode and not record.get("mode"):
        changes["mode"] = mode
    changes["encrypted_at"] = stamp
    record.update(changes)
    problems = list(warnings)
    records = quarantine_records(plan)
    current = [r for r in records if isinstance(r, dict) and r.get("quarantined") == stored_rel and not r.get("restored_at")]
    if current:
        current[-1].update(changes)
    else:
        records.append(record)
    try:
        write_bytes(os.path.join(plan.quarantine, QUARANTINE_INDEX),
                    (json.dumps(records, indent=2, ensure_ascii=False) + u"\n").encode("utf-8", "replace"))
    except (IOError, OSError, ValueError, TypeError) as exc:
        problems.append(u"%s could not be updated: %s" % (QUARANTINE_INDEX, to_text(str(exc))))
    try:
        with io.open(os.path.join(plan.quarantine, QUARANTINE_MANIFEST), "ab") as fh:
            fh.write((u"%s  encrypted %s -> %s  enc: %s (%s, kdf %s)\n"
                      % (stamp, stored_rel, new_rel, extras["key"], extras["cipher"], extras["kdf"])).encode("utf-8", "replace"))
    except (IOError, OSError) as exc:
        problems.append(u"%s could not be updated: %s" % (QUARANTINE_MANIFEST, to_text(str(exc))))
    return new_rel, problems


def apply_setup_upgrades(plan, upgrades, dotenvx, args, style, journal):
    """Do what the tightening offered: keys into the OS secret store, plaintext quarantined files
    encrypted in place."""
    for env_path, keys_file, _name in upgrades["keys"]:
        move_key_to_store(plan, env_path, keys_file, dotenvx, args, style, journal)
    for record in upgrades["quarantine"]:
        old = record.get("quarantined")
        try:
            new_rel, problems = encrypt_quarantined_record(plan, record, journal)
        except (IOError, OSError, ToolError) as exc:
            say(u"  %s %s/%s: left as it is: %s" % (style.bad("[!!]"), plan.rel(plan.quarantine), old, to_text(str(exc))))
            plan.quarantine_upgrade_failed.append(old)
            continue
        plan.quarantine_upgraded.append((old, new_rel))
        say(u"  %s %s/%s: encrypted in place as %s" % (style.ok("[ok]"), plan.rel(plan.quarantine), old, new_rel))
        for problem in problems:
            say(u"  %s %s: %s" % (style.warn("[--]"), new_rel, problem))


def key_at_hand(env_path, dotenvx, plan, args):
    """Can dotenvx decrypt a value of env_path here, wherever its key is? None when the file has no
    encrypted value to try."""
    try:
        entries = parse_env_entries(read_text(env_path))
    except (IOError, OSError):
        return False
    key = next((k for k, v, _ in entries if v.startswith(ENCRYPTED_PREFIX)), None)
    if key is None:
        return None
    value, _reason = decrypt_env_value(dotenvx, env_path, key, plan.root, args)
    return value is not None


def print_custody_status(plan, env_paths, dotenvx, args, style):
    """For a run with nothing to change: where the private key of each env file dotenvx manages is,
    proven by decrypting a value (a keys file may hold a key of the right name that belongs to another
    file, and a key may be on another machine altogether)."""
    store = native_store_name()
    managed = [path for path in env_paths if store_public_key(path)[1]]
    if not managed:
        return
    say(u"")
    for env_path in managed:
        rel = plan.rel(env_path)
        held = keys_file_holding(env_path, discover_keys_files([env_path], plan.root))
        if held and key_file_serves(env_path, held[0], dotenvx, plan, args):
            say(u"  %s %s: encrypted with dotenvx; its private key is in %s" % (style.ok("[ok]"), rel, plan.rel(held[0])))
            continue
        at_hand = key_at_hand(env_path, dotenvx, plan, args)
        if at_hand:
            say(u"  %s %s: encrypted with dotenvx; its private key is kept by dotenvx, not in a key file here (%s)"
                % (style.ok("[ok]"), rel, u"the %s or a password manager" % store if store else u"a password manager"))
        elif at_hand is None:
            say(u"  %s %s: carries a dotenvx public key but no encrypted value yet" % (style.ok("[ok]"), rel))
        else:
            say(u"  %s %s: encrypted with dotenvx, but its private key is not available on this machine%s"
                % (style.warn("[--]"), rel,
                   u" (%s holds a key of the same name that does not decrypt it)" % plan.rel(held[0]) if held else u""))
    say(style.dim(u"  dotenvx is the tool in use here (dotenvx run, get, set):  https://dotenvx.com/docs"))


def print_dotenvx_pointer(style):
    say(style.dim(u"A real run on a folder with secrets sets dotenvx up (encrypted env files, the private key in the %s or"
                  u" in .env.keys)" % (native_store_name() or u"OS secret store")))
    say(style.dim(u"and ends with a short dotenvx primer; from then on dotenvx, not this tool, is what you use day to day."))


def restore_from_quarantine(args, root, store, dotenvx, style):
    """--restore NAME: put one quarantined file back where it came from, decrypting a *.enc with the
    passphrase dotenvx kept. NAME is the stored name or the original path as MANIFEST.txt lists them."""
    quarantine = fs_text(args.quarantine_dir or QUARANTINE_DEFAULT)
    if not os.path.isabs(quarantine):
        quarantine = os.path.join(root, quarantine)
    quarantine = os.path.normpath(quarantine)
    index_path = os.path.join(quarantine, QUARANTINE_INDEX)
    try:
        records = json.loads(read_text(index_path))
        if not isinstance(records, list):
            raise ValueError("not a list of records")
    except (IOError, OSError, ValueError) as exc:
        say(style.bad(u"[!!] %s cannot be read: %s" % (index_path, to_text(str(exc)))), sys.stderr)
        return 1
    wanted = slash_path(fs_text(args.restore)).strip(u"/")
    names = (wanted, wanted + ENCRYPTED_SUFFIX)   # the stored name, with or without its .enc, or the original path
    hits = [r for r in records if isinstance(r, dict) and not r.get("restored_at")
            and (r.get("quarantined") in names or r.get("original") == wanted)]
    if not hits:
        say(style.bad(u"[!!] %s is not in %s (names are as MANIFEST.txt lists them; a file already restored is not"
                      u" listed again)" % (wanted, index_path)), sys.stderr)
        return 1
    record = hits[-1]
    stored = os.path.join(quarantine, record["quarantined"].replace(u"/", os.sep))
    original = os.path.join(root, record["original"].replace(u"/", os.sep))
    if not os.path.isfile(stored):
        say(style.bad(u"[!!] %s is missing from the quarantine folder" % record["quarantined"]), sys.stderr)
        return 1
    if os.path.exists(original):
        say(style.bad(u"[!!] %s exists; move it out of the way first" % record["original"]), sys.stderr)
        return 1
    source = stored
    if record.get("encrypted"):
        openssl = find_openssl(args)
        info = openssl_setup(openssl) if openssl else {}
        if not openssl or not info.get("kdf"):
            say(style.bad(u"[!!] openssl is needed to decrypt %s and %s" % (
                record["quarantined"], u"was not found" if not openssl else u"could not encrypt a probe file")), sys.stderr)
            return 1
        env_path = os.path.join(quarantine, QUARANTINE_KEYS_ENV)
        public = store_public_key(env_path)[1]
        shared = public is not None and public == store_public_key(store)[1]   # else its own key, next to it
        passphrase, reason = decrypt_env_value(dotenvx, env_path, record.get("key") or u"", root, args,
                                               extra_env=store_private_key_env(store, root) if shared else None,
                                               extra_keys_files=discover_keys_files([store], root) if shared else ())
        if passphrase is None:
            say(style.bad(u"[!!] the passphrase %s could not be read from %s: %s"
                          % (record.get("key"), env_path, reason)), sys.stderr)
            return 1
        source = stored + u".restoring"
        ok, detail = openssl_run(openssl, record.get("kdf") or info["kdf"], stored, source, passphrase, decrypt=True)
        if not ok or (record.get("sha256") and sha256_file(source) != record["sha256"]):
            remove_quietly(source)
            say(style.bad(u"[!!] %s did not decrypt back to the recorded content (%s)"
                          % (record["quarantined"], detail or u"different content")), sys.stderr)
            return 1
    folder = os.path.dirname(original)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder)
    try:
        os.rename(source, original)
    except OSError:
        shutil.move(source, original)
    if source != stored:
        remove_quietly(stored)
        if record.get("mode"):
            try:
                os.chmod(original, int(record["mode"], 8))   # a 0600 credential file comes back as one
            except (IOError, OSError, ValueError):
                pass
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    record["restored_at"] = stamp
    try:
        write_bytes(index_path, (json.dumps(records, indent=2, ensure_ascii=False) + u"\n").encode("utf-8", "replace"))
        with io.open(os.path.join(quarantine, QUARANTINE_MANIFEST), "ab") as fh:
            fh.write((u"%s  restored %s -> %s\n" % (stamp, record["quarantined"], record["original"])).encode("utf-8", "replace"))
    except (IOError, OSError, ValueError, TypeError) as exc:
        say(u"  %s restored, but the quarantine records could not be updated: %s" % (style.warn("[--]"), to_text(str(exc))))
    say(u"  %s restored %s from %s%s" % (style.ok("[ok]"), record["original"], record["quarantined"],
                                         u" (decrypted)" if record.get("encrypted") else u""))
    return 0


def secrets_text(findings, lines=False):
    """'Stripe sk_l...23, AWS AKIA...M2' for a list of findings: each distinct secret counted
    once, and '(x2)' when two different secrets happen to mask to the same text. With lines,
    the line TruffleHog reported each one on, so that a match can be looked at by hand."""
    shown = OrderedDict()
    seen = set()
    for finding in findings:
        if (finding.detector, finding.raw) in seen:
            continue
        seen.add((finding.detector, finding.raw))
        text = u"%s%s %s" % (finding.detector, u" *" if finding.verified else u"", mask(finding.raw))
        if lines and finding.line:
            text += u" (line %d)" % finding.line
        shown[text] = shown.get(text, 0) + 1
    return u", ".join(text if count == 1 else u"%s (x%d)" % (text, count) for text, count in shown.items())


def print_unfixable(plan, args, style):
    """The files whose secrets cannot be fixed in place: why, what is inside (archives), the
    secrets, and what this run does with each: moved whole to quarantine, or left in place."""
    say(u"")
    if plan.quarantine and plan.quarantine_crypto:
        tail = (u"  (a chosen file is moved whole to %s, AES-256 encrypted, its passphrase kept by dotenvx; nothing in it"
                u" is rewritten)" % plan.rel(plan.quarantine))
    elif plan.quarantine and plan.quarantine_plain_reason:
        tail = (u"  (a chosen file is moved whole to %s AS IT IS: %s)" % (plan.rel(plan.quarantine), plan.quarantine_plain_reason))
    elif plan.quarantine:
        tail = (u"  (a chosen file is moved whole to %s; nothing in it is rewritten)" % plan.rel(plan.quarantine))
    else:
        tail = u"  (not rewritten; with --yes, pass --quarantine to move them out of the tree)"
    say(style.bold(u"Files holding secrets that cannot be fixed in place: %d" % len(plan.unfixable)) + style.dim(tail))
    rows = []
    for entry in plan.unfixable.values():
        number = u"%d" % entry.item.number if entry.item is not None else u"-"
        name = plan.rel(entry.path)
        if entry.item is not None:
            action = action_text(entry.item, plan, args)
        elif entry.partial:
            action = u"stays in place: its other secrets are fixed above; handle this one by hand"
        elif entry.in_use:
            action = u"stays in place: secrets from other files are stored in it; handle this one by hand"
        elif entry.why.startswith(u"symbolic link"):
            action = u"stays in place: fix the file it points to"
        elif entry.why.startswith(u"file is gone"):
            action = u"nothing to do: it is gone"
        else:
            action = u"stays in place (pass --quarantine to move it)"
        if entry.kind:
            lines = [(u"%s: %s" % (entry.kind, member), secrets_text(found)) for member, found in entry.inside]
            if entry.unplaced:
                where = u"%s: (not seen inside)" % entry.kind if lines or entry.note else u"%s: (could not look inside)" % entry.kind
                lines.append((where, secrets_text(entry.unplaced)))
        else:   # line numbers for files that are text (a lock file, an example env file, a source file)
            textual = not entry.why.startswith((u"PDF", u"binary file", u"larger than", u"cannot be read",
                                                u"symbolic link", u"file is gone"))
            lines = [(entry.why, secrets_text(entry.findings, lines=textual))]
        for index, (why, secrets) in enumerate(lines):
            first = index == 0
            rows.append((number if first else u"", name if first else u"", why, secrets, action if first else u""))
    for line in table(rows, (u"#", u"File", u"Why / inside", u"Secrets", u"Action")):
        say(line)
    for entry in plan.unfixable.values():
        if entry.note:
            say(style.dim(u"  %s: %s" % (plan.rel(entry.path), entry.note)))
    if plan.quarantine and not plan.quarantine_flagged and any(e.item is not None for e in plan.unfixable.values()):
        say(style.dim(u"  Offered because this run asks first: y moves them too, s lets you leave them in place."
                      u" A --yes run moves files only with --quarantine."))


def compiled_skipped(plan):
    """The compiled files this run left out of the scan, path -> kind: the ones recognised by name while
    walking the tree, and the ones TruffleHog read anyway (no extension, or an old release that takes no
    exclusions) whose findings were set aside."""
    skipped = OrderedDict()
    for path in plan.compiled_by_name:
        skipped[os.path.normpath(path)] = u".%s file" % COMPILED_NAME_RE.search(os.path.basename(path)).group(1).lower()
    for path, kind in plan.compiled_skipped.items():
        skipped.setdefault(os.path.normpath(path), kind)
    return skipped


def print_compiled(plan, args, style):
    """--scan-compiled: the findings TruffleHog reported in programs and libraries, listed and left
    alone, with what surrounds each match as `strings` would show it (on the screen only: the run
    log gets the rows without it)."""
    rows, logged, seen = [], [], set()
    for entry in plan.compiled.values():
        secrets = [to_bytes(c) for finding in entry.findings for c in candidate_secrets(finding) if c]
        for finding in entry.findings:
            if (entry.path, finding.detector, finding.raw) in seen:
                continue
            seen.add((entry.path, finding.detector, finding.raw))
            near = strings_near(entry.path, finding, secrets) or (
                u"(decoded from %s: not in the file as such)" % finding.decoder
                if (finding.decoder or u"PLAIN").upper() != u"PLAIN" else u"(not found in the file as such)")
            row = (plan.rel(entry.path), entry.kind, finding.detector + (u" *" if finding.verified else u""),
                   mask(finding.raw))
            rows.append(row + (near,))
            logged.append(row + (u"(shown on the screen only)",))
    say(u"")
    say(style.bold(u"Findings in compiled code: %d in %d file(s)" % (len(rows), len(plan.compiled)))
        + style.dim(u"  (listed only: never rewritten or moved)"))
    headers = (u"File", u"Kind", u"Type", u"Secret", u"Near")
    for line, log_line in zip(table(rows, headers), table(logged, headers)):
        say(line, log_text=log_line)
    say(style.dim(u"  Matches in compiled code are usually symbol names or random bytes that happen to fit a detector's"))
    say(style.dim(u"  pattern; --verify lets TruffleHog check each one against its service (* = verified live). A real"))
    say(style.dim(u"  credential compiled into a program has to be rotated, and the program rebuilt without it."))


def print_report(plan, args, style, verified_any):
    say(u"")
    secrets = [item for item in plan.items if item.kind != "quarantine"]
    if not secrets:
        if plan.unfixable:
            say(style.ok(u"No plaintext secrets to encrypt in place; the files below hold some."))
        else:
            say(style.ok(u"TruffleHog found no plaintext secrets to encrypt."))
    else:
        files = len(set(item.path for item in secrets))
        say(style.bold(u"Plaintext secrets found: %d in %d file(s)" % (len(secrets), files)))
        rows = []
        for item in secrets:
            where = plan.rel(item.path) + (u":%d" % item.line if item.line else u"")
            kind = item.detector + (u" *" if item.verified else u"")
            rows.append((u"%d" % item.number, kind, item.key or u"-", mask(item.secret), where,
                         action_text(item, plan, args)))
        for line in table(rows, (u"#", u"Type", u"Key / name", u"Secret", u"Where", u"Action")):
            say(line)
        if verified_any:
            say(style.dim(u"  * = TruffleHog verified this credential is live"))
    if plan.unfixable:
        print_unfixable(plan, args, style)
    if plan.compiled:
        print_compiled(plan, args, style)
    skipped = compiled_skipped(plan)
    if skipped:
        kinds = OrderedDict()
        for kind in skipped.values():
            kinds[kind] = kinds.get(kind, 0) + 1
        shown = sorted(kinds.items(), key=lambda pair: -pair[1])
        summary = u", ".join(u"%s %d" % (kind.replace(u" file", u""), count) for kind, count in shown[:4])
        if len(shown) > 4:
            summary += u", ..."
        say(u"")
        say(style.dim(u"Skipped %d compiled file(s) (%s): a secret compiled into a program cannot be fixed by this tool,"
                      u" and moving such a file would break what uses it. --scan-compiled lists what TruffleHog finds in them."
                      % (len(skipped), summary)))
    if plan.hashes:
        say(u"")
        say(style.dim(u"Set aside %d finding(s) that are package integrity hashes (sha512-..., h1:..., sha256:...) or"
                      u" checksums and commit ids in lock files: public identifiers that happen to match a detector's"
                      u" pattern, not secrets.%s" % (plan.hashes, u" Each is named in the run log." if RUN_LOG is not None else u"")))
    if plan.ignored:
        say(u"")
        say(style.dim(u"Ignored %d finding(s) inside excluded folders (.git, node_modules, ...)." % plan.ignored))
    say(u"")
    if plan.encrypted:
        say(style.bold(u"Already encrypted with dotenvx (left as is): %d" % len(plan.encrypted)))
        rows = [(key, u"%s:%d" % (plan.rel(path), line)) for path, key, line in plan.encrypted]
        for line in table(rows, (u"Key", u"Where")):
            say(line)
    else:
        say(style.dim(u"No dotenvx-encrypted keys found in env files yet."))
    unflagged = [(p, k) for p, k, _, _ in plan.plain_env
                 if not any(it.kind == "env" and it.path == p and it.key == k for it in plan.items)]
    if unflagged:
        say(u"")
        if args.env_all:
            say(style.dim(u"(--env-all: all plaintext env keys are included above)"))
        else:
            say(style.bold(u"Other plaintext keys in env files: %d" % len(unflagged))
                + style.dim(u"  (not flagged by TruffleHog; add --env-all to encrypt them too)"))
            grouped = OrderedDict()
            for path, key in unflagged:
                grouped.setdefault(plan.rel(path), []).append(key)
            for path, keys in grouped.items():
                say(u"  %s: %s" % (path, u", ".join(keys)))


def ask(prompt):
    if sys.stdin is None or sys.stdout is None:
        return u""
    try:
        sys.stdout.write(prompt)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        sys.stdout.write(prompt.encode(encoding, "replace").decode(encoding, "replace"))
    sys.stdout.flush()
    try:
        answer = read_line()
    except EOFError:
        say(u"")
        log_only(prompt + u"<end of input>")
        return u""
    log_only(prompt + to_text(answer).strip())
    return to_text(answer).strip()


def confirm(plan, args, style):
    """Interactive y/N/select prompt. Returns the list of items to process."""
    if args.yes:
        return list(plan.items)
    interactive = sys.stdin is not None and hasattr(sys.stdin, "isatty") and sys.stdin.isatty()
    if not interactive:
        say(style.dim(u"(stdin is not a terminal; pass --yes to encrypt without asking)"))
    secrets = len([item for item in plan.items if item.kind != "quarantine"])
    archives = len(plan.items) - secrets
    if archives and secrets:
        question = u"Encrypt %d secret(s) and move %d file(s) to quarantine now?" % (secrets, archives)
    elif archives:
        question = u"Move %d file(s) to quarantine now?" % archives
    else:
        question = u"Encrypt these %d secret(s) now?" % secrets
    while True:
        answer = ask(style.bold(question + u" [y/N/s]  (s = choose which): ")).lower()
        if answer in ("y", "yes"):
            return list(plan.items)
        if answer in ("", "n", "no", "q", "quit"):
            return []
        if answer in ("s", "select", "some"):
            picked = ask(u"Numbers to encrypt (e.g. 1 3 5-7, or 'all'; empty to go back): ")
            if not picked:
                continue
            numbers = parse_selection(picked, len(plan.items))
            if numbers is None:
                say(style.warn(u"Could not understand '%s'." % picked))
                continue
            chosen = [item for item in plan.items if item.number in numbers]
            if not chosen:
                continue
            say(u"Selected: " + u", ".join(u"#%d %s" % (it.number, it.key if it.kind != "quarantine"
                                                           else plan.rel(it.path)) for it in chosen))
            if ask(u"Go ahead with these %d? [Y/n]: " % len(chosen)).lower() in ("", "y", "yes"):
                return chosen
            continue
        say(style.warn(u"Please answer y (yes), n (no) or s (select)."))


# --------------------------------------------------------------------------
# Doing it
# --------------------------------------------------------------------------

def dotenvx_version():
    return tuple(DOTENVX_INFO.get("version") or ())


def version_text(version):
    return u".".join(str(part) for part in version)


def native_store_name():
    """The OS secret store dotenvx uses on this platform, or None."""
    for prefix, name in NATIVE_STORE_NAMES:
        if sys.platform.startswith(prefix):
            return name
    return None


def native_disabled():
    return os.environ.get("DOTENVX_NO_NATIVE", "").lower() == "true"


def native_store_wanted(args):
    """Should a private key go to the OS secret store? Not with --no-native or DOTENVX_NO_NATIVE=true,
    not on CI (an ephemeral runner's store is gone with the runner; dotenvx itself keeps keys in
    files there), not with a dotenvx before 2.3, not on a platform without a store."""
    if getattr(args, "no_native", False) or native_disabled() or os.environ.get("CI"):
        return False
    return native_store_name() is not None and dotenvx_version() >= DOTENVX_NATIVE_SINCE


def tidy_tool_line(text):
    """A dotenvx output line without its leading glyph."""
    return to_text(text).strip().lstrip(u"\u2620\u25cb\u2325\u2714\u25c8\u26c9 \t")


def file_custody_reason(args, detail=u""):
    """Why a private key stays in a .env.keys file rather than the OS store (detail: what
    dotenvx said when the store refused it)."""
    if getattr(args, "no_native", False):
        return u"--no-native"
    if native_disabled():
        return u"DOTENVX_NO_NATIVE is set"
    if os.environ.get("CI"):
        return u"CI is set: keys stay in files there, as dotenvx itself does"
    store = native_store_name()
    if store is None:
        return u"no OS secret store on this platform"
    version = dotenvx_version()
    if not version:
        return u"dotenvx's version is unknown (--no-version-check), so the %s was not tried" % store
    if version < DOTENVX_NATIVE_SINCE:
        return u"dotenvx %s keeps keys in files; %s or later can keep them in the %s" % (
            version_text(version), version_text(DOTENVX_NATIVE_SINCE), store)
    detail = tidy_tool_line(detail) if detail else u""
    return detail or u"the %s is not reachable here" % store


def private_keys_from(keys_files):
    """DOTENV_PRIVATE_KEY* entries of the given keys files, for a dotenvx too old for -fk, which
    reads the private key from the environment instead."""
    found = {}
    for keys_file in keys_files:
        try:
            for key, value, _ in parse_env_entries(read_text(keys_file)):
                if key.startswith("DOTENV_PRIVATE_KEY") and value and key not in found:
                    found[key] = value
        except (IOError, OSError):
            continue
    return found


def dotenvx_native(dotenvx, action, env_path, keys_file, root, args):
    """`dotenvx native up|down -f env -fk keys`: move the private key of env into the OS secret
    store (up) or back into the keys file (down). Returns (ok, last line of dotenvx's output)."""
    cmd = [dotenvx, "native", action, "-f", env_path, "-fk", keys_file]
    log_only(u"$ " + u" ".join(cmd))
    if args.verbose:
        say(u"  $ " + u" ".join(cmd))
    try:
        code, out, err = run_command(cmd, cwd=root, extra_env={"DOTENVX_NO_TELEMETRY": "1"})
    except (OSError, IOError) as exc:
        return False, u"could not run dotenvx: %s" % to_text(str(exc))
    text = (out + u"\n" + err).strip()
    if text:
        log_only(text)
    if args.verbose and text:
        say(style_dim_block(text))
    lines = text.splitlines()
    return code == 0, (lines[-1].strip() if lines else u"status %d" % code)


def dotenvx_encrypt(dotenvx, env_path, keys, root, args, keys_file=None, allow_empty=False):
    """Run `dotenvx encrypt -f env_path -k KEY ...` with the swept folder as cwd; -fk keys_file
    says where a new private key goes (a dotenvx from 1.38). allow_empty lets a file with no
    keys to encrypt be run through dotenvx just for its key pair."""
    if not keys and not allow_empty:  # without -k dotenvx would encrypt every key in the file
        raise ToolError(u"refusing to run dotenvx encrypt without an explicit key list")
    cmd = [dotenvx, "encrypt", "-f", env_path]
    for key in keys:
        cmd.extend(["-k", key])
    if keys_file:
        cmd.extend(["-fk", keys_file])
    log_only(u"$ " + u" ".join(cmd))
    if args.verbose:
        say(u"  $ " + u" ".join(cmd))
    # CI=1 and a non-tty stdin/stderr keep dotenvx 2.x from asking where to keep the
    # private key: it writes .env.keys (in the cwd, i.e. the swept folder) instead.
    code, out, err = run_command(cmd, cwd=root, extra_env={"CI": "1", "DOTENVX_NO_TELEMETRY": "1"})
    if out.strip() or err.strip():
        log_only((out + u"\n" + err).strip())
    if args.verbose and (out.strip() or err.strip()):
        say(style_dim_block(out + "\n" + err))
    if code != 0:
        detail = (err.strip() or out.strip()).splitlines()
        raise ToolError(u"dotenvx exited with status %d: %s" % (code, detail[-1] if detail else u""))


def decrypt_env_value(dotenvx, env_path, key, root, args, extra_env=None, extra_keys_files=()):
    """Ask dotenvx for the stored value of key: (value, u"") or (None, reason).

    --overload makes the file win over a variable of the same name in our own
    environment (dotenvx otherwise prefers the environment, even for `get`), and
    every keys file that may hold the private key is passed with -fk, because on
    its own dotenvx only looks next to the env file. An undecryptable value comes
    back as the ciphertext with exit status 0, so the text is checked, not the code."""
    cmd = [dotenvx, "get", key, "-f", env_path, "--overload"]
    environment = {"DOTENVX_NO_TELEMETRY": "1"}
    keys_files = discover_keys_files([env_path], root)
    for keys_file in extra_keys_files:
        if keys_file not in keys_files:
            keys_files.append(keys_file)
    if dotenvx_version() >= DOTENVX_KEYS_FILE_OPTION_SINCE:
        for keys_file in keys_files:
            cmd.extend(["-fk", keys_file])
    else:   # an older dotenvx ignores -fk; it does read the private key from the environment. Two files
        # both called .env name their keys alike, so the keys file nearest the env file (its -fk hint,
        # then its neighbour, then the root's) has to win: the list goes root first, so it is reversed
        environment.update(private_keys_from(list(reversed(keys_files))))
    environment.update(extra_env or {})
    log_only(u"$ " + u" ".join(cmd) + u"   (output not logged: it is the value)")
    if args.verbose:
        say(u"  $ " + u" ".join(cmd))
    try:
        code, out, err = run_command(cmd, cwd=root, extra_env=environment)
    except (OSError, IOError) as exc:
        return None, u"could not run dotenvx get: %s" % to_text(str(exc))
    if code != 0:
        detail = (err.strip() or out.strip()).splitlines()
        return None, u"dotenvx get %s failed: %s" % (key, detail[-1] if detail else u"status %d" % code)
    value = out
    if value.endswith(u"\n"):
        value = value[:-1]
    if value.endswith(u"\r"):
        value = value[:-1]
    if value.startswith(ENCRYPTED_PREFIX):
        return None, u"no private key for %s is available here" % key
    return value, u""


def make_decryptor(dotenvx, root, args, extra_env=None, extra_keys_files=()):
    """A cached decrypt_env_value(env_path, key) bound to this run's tools. keys_from names the
    file whose private key applies when env_path is a staging copy of it: the key file sits
    next to the real file, not next to the copy."""
    cache = {}

    def decryptor(env_path, key, keys_from=None):
        ident = (env_path, key, keys_from)
        if ident not in cache:
            keys_files = list(extra_keys_files)
            if keys_from and keys_from != env_path:
                keys_files.extend(discover_keys_files([keys_from], root))
            cache[ident] = decrypt_env_value(dotenvx, env_path, key, root, args, extra_env, keys_files)
        return cache[ident]
    return decryptor


def make_staging_dir(root):
    """A scratch folder for the copy dotenvx works on: under the swept root when we
    may (so that a crash leaves it where the next run cleans it up), else in the
    system temp folder."""
    try:
        return tempfile.mkdtemp(prefix=TEMP_PREFIX, dir=root)
    except (IOError, OSError):
        return tempfile.mkdtemp(prefix=TEMP_PREFIX)


def adopt_keys_file(staging, env_path):
    """A new private key lands in the staging folder (dotenvx 1.x writes next to the file it
    encrypts, later ones where -fk says); copy it next to the real env file, merging into a
    keys file already there. Returns that file, or None when nothing is in the staging
    folder (the key went to the OS secret store, or the file already had its key pair). The
    staged copy is left for the verification step and goes with the staging folder."""
    staged = os.path.join(staging, ".env.keys")
    if not os.path.isfile(staged):
        return None
    target = os.path.join(os.path.dirname(os.path.abspath(env_path)), ".env.keys")
    if not os.path.isdir(os.path.dirname(target)):
        os.makedirs(os.path.dirname(target))   # a new env file in a folder that does not exist yet
    new_lines = read_bytes(staged).splitlines()
    if os.path.isfile(target):
        merged = read_bytes(target).splitlines()
        for line in new_lines:
            if line.strip() and not line.lstrip().startswith(b"#") and line not in merged:
                merged.append(line)
    else:
        merged = new_lines
    write_bytes(target, b"\n".join(merged) + b"\n")
    try:
        os.chmod(target, 0o600)
    except (IOError, OSError):
        pass
    return target


KEYS_HINT_LINE_RE = re.compile(br"^([ \t]*DOTENV_PUBLIC_KEY\w*[ \t]*=.*#[ \t]*-fk[ \t]+)(\S+)", re.M)
PUBLIC_KEY_LINE_RE = re.compile(br"^([ \t]*DOTENV_PUBLIC_KEY\w*[ \t]*=[^\r\n#]*?)(?:[ \t]*#[ \t]*-fk[ \t]+[^\r\n]*)?[ \t]*(\r?)$",
                                re.M)


def set_keys_hint(data, hint):
    """dotenvx 2.x writes '# -fk <path>' on the DOTENV_PUBLIC_KEY line, the keys file relative
    to the file it encrypted (the staging copy). Point it at the keys file's real place (hint,
    relative to the env file), or drop it when the key is not in a file at all (None)."""
    def fix(match):
        tail = (u" # -fk %s" % hint).encode("utf-8") if hint else b""
        return match.group(1).rstrip() + tail + match.group(2)
    return PUBLIC_KEY_LINE_RE.sub(fix, data, count=1)


def verify_decrypts(decryptor, env_path, job, keys, before, keys_from=None):
    """Decrypt every key we touched and compare. Returns (problems, unverifiable):
    problems are (key, detail) pairs that must fail the file; unverifiable lists the
    keys for which no private key is at hand (dotenvx can encrypt with a public key
    alone, which is what a teammate's clone has). env_path may be a staging copy of
    keys_from, whose key file is looked for next to the real file."""
    problems, unverifiable = [], []
    written = dict(job["new"])
    for key in keys:
        value, reason = decryptor(env_path, key, keys_from)
        if value is None:
            if reason.startswith(u"no private key"):
                unverifiable.append(key)
            else:
                problems.append((key, reason))
            continue
        if key in written:
            if value != written[key]:
                problems.append((key, u"decrypts to something other than the value we stored"))
            continue
        # A key that was already in the file: the secret TruffleHog found must be in the
        # decrypted value. dotenvx expands $NAME and backslash escapes of the original
        # text on the way out, so such entries can only be checked for being decryptable.
        wanted = [item.secret for item in job["items"] if item.kind == "env" and item.key == key]
        raw = before.get(key, u"")
        if wanted and "$" not in raw and "\\" not in raw and not all(value_holds(value, w) for w in wanted):
            problems.append((key, u"decrypts to something that does not contain the secret TruffleHog found"))
    return problems, unverifiable


def encrypt_env_file(env_path, job, dotenvx, root, args, decryptor=None, journal=None, custody=None, strict=False):
    """Store and encrypt the keys of one env file without ever writing plaintext to it.

    The file (or a fresh header for a new one) is copied into a staging folder
    under the swept root, keeping its exact name because dotenvx derives the
    DOTENV_*_KEY variable names from it; the new entries are appended to the copy;
    dotenvx encrypts the copy; the result is checked (every key is "encrypted:", no
    entry still holds a secret in plaintext, and each value decrypts back to what we
    stored where a private key is at hand); only then is the copy installed over the
    real file in one atomic rename. If anything fails, the real file has not been
    touched. Returns (ok, note, warnings).

    A fresh key pair's private key is dotenvx's to keep: `dotenvx native up` puts it in the
    OS secret store where this dotenvx and platform allow (nothing is left on disk), else it
    is adopted into .env.keys next to the env file. A file that already had a key pair keeps
    its custody. custody, when a dict, records ("native", store, u""), ("file", keys path, why
    not the store) or ("existing", None, u"") under env_path. With strict, a value that cannot be
    decrypted back here (no private key at hand) fails the call instead of leaving a warning.
    """
    warnings = []
    try:
        staging = make_staging_dir(root)
    except (IOError, OSError) as exc:
        return False, u"cannot create a staging folder: %s" % to_text(str(exc)), warnings
    try:
        existed = os.path.isfile(env_path)
        original = read_bytes(env_path) if existed else b""
        copy = os.path.join(staging, os.path.basename(env_path))
        data = original
        if not existed:
            data = (u"# Created by sweep_and_secure.py; values are encrypted with dotenvx "
                    u"(https://dotenvx.com)\n").encode("utf-8")
        if data.startswith(b"\xef\xbb\xbf"):
            # dotenvx reads past a UTF-8 byte order mark, but once it has prepended its public-key
            # header the mark sits in the middle of the file, where other dotenv readers choke on
            # it (the entry behind it is lost). The mark has no business in a .env file: drop it.
            data = data[3:]
            warnings.append(u"removed the UTF-8 byte order mark from the start of the file")
        newline = b"\r\n" if b"\r\n" in data else b"\n"
        if data and not data.endswith(b"\n"):
            data += newline
        for key, value in job["new"]:
            quoted, exact = quote_env_value(value)
            if not exact:  # build_plan keeps these out of the plan; never store a mangled value
                raise ToolError(u"%s cannot be written to a .env file exactly: %s"
                                % (key, inexact_reason(value)))
            data += (u"%s=%s" % (key, quoted)).encode("utf-8") + newline
        with io.open(copy, "wb") as fh:
            fh.write(data)
        before = dict((key, value) for key, value, _ in parse_env_entries(to_text(data)))
        keys = []
        for key in job["keys"]:
            if key not in keys:
                keys.append(key)
        fresh = not re.search(br"^[ \t]*DOTENV_PUBLIC_KEY\w*[ \t]*=", data, re.M)   # no key pair yet
        staged_keys = os.path.join(staging, ".env.keys")   # where a new private key lands, whatever the dotenvx
        version = dotenvx_version()   # unknown (--no-version-check): taken for a current release, which needs -fk
        keys_file_arg = staged_keys if not version or version >= DOTENVX_KEYS_FILE_OPTION_SINCE else None
        dotenvx_encrypt(dotenvx, copy, keys, root, args, keys_file=keys_file_arg, allow_empty=job.get("allow_empty", False))
        where = None
        if fresh and os.path.isfile(staged_keys) and native_store_wanted(args):
            ok, detail = dotenvx_native(dotenvx, "up", copy, staged_keys, root, args)
            if ok and not os.path.isfile(staged_keys):
                where = ("native", native_store_name(), u"")
            else:   # no store reachable here: the file it is, and the report says why
                refused = detail or u"dotenvx native up failed"
        else:
            refused = u""
        adopted = adopt_keys_file(staging, env_path)
        if adopted:
            where = ("file", adopted, refused)
        if fresh and where is None:
            # dotenvx wrote no key file where this tool looks, so it kept the key itself (its store, or a
            # provider it is set up with); say so rather than guess at a file
            where = ("native", native_store_name() or u"dotenvx's own key store", u"")
            warnings.append(u"dotenvx wrote no .env.keys for the new key pair; it keeps the private key itself"
                            u" (dotenvx keypair -f %s shows where)" % env_path)
        if custody is not None and (fresh or env_path not in custody):   # a later call never forgets a fresh key
            custody[env_path] = where if fresh else ("existing", None, u"")
        result = read_bytes(copy)
        entries = {}
        for key, value, _ in parse_env_entries(to_text(result)):
            entries[key] = value
        not_done = [key for key in keys if not entries.get(key, u"").startswith(ENCRYPTED_PREFIX)]
        if not_done:
            raise ToolError(u"dotenvx finished but these keys are still plaintext: " + u", ".join(not_done))
        secrets = [value for _, value in job["new"]] + [item.secret for item in job["items"]]
        leftover = sorted(set(key for key, value in entries.items()
                              if not value.startswith(ENCRYPTED_PREFIX)
                              and any(value_holds(value, secret) for secret in secrets if secret)))
        if leftover:
            raise ToolError(u"dotenvx finished but these entries still hold a secret in plaintext: "
                            + u", ".join(leftover))
        if decryptor is not None:
            problems, unverifiable = verify_decrypts(decryptor, copy, job, keys, before, keys_from=env_path)
            if problems:
                raise ToolError(u"verification failed: " + u"; ".join(u"%s %s" % p for p in problems))
            if unverifiable and strict:
                raise ToolError(u"no private key for %s is available here to check that %s decrypts"
                                % (os.path.basename(env_path), u", ".join(unverifiable)))
            if unverifiable:
                warnings.append(u"could not verify %s: no private key for this file is available here;"
                                u" check the values where it is" % u", ".join(unverifiable))
        if fresh and KEYS_HINT_LINE_RE.search(result):
            # the hint dotenvx wrote points into the staging folder: name the adopted file, or nothing
            hint = None
            if where and where[0] == "file":
                try:
                    hint = slash_path(os.path.relpath(where[1], os.path.dirname(os.path.abspath(env_path))))
                except ValueError:   # another drive on Windows
                    hint = slash_path(where[1])
            result = set_keys_hint(result, hint)
        folder = os.path.dirname(env_path)
        if folder and not os.path.isdir(folder):
            os.makedirs(folder)
        write_bytes(env_path, result)   # atomic, and the only write to the real path
        if journal is not None:
            journal.add("env", env_path, keys)
    except (ToolError, IOError, OSError) as exc:
        return False, to_text(str(exc)), warnings
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return True, u"", warnings


class Journal(object):
    """What this run changed on disk, so that an interrupted or failed run can say so."""

    def __init__(self):
        self.events = []   # (kind, path, detail)

    def add(self, kind, path, detail=None):
        self.events.append((kind, path, detail))

    def paths(self, kind):
        out = []
        for event_kind, path, _ in self.events:
            if event_kind == kind and path not in out:
                out.append(path)
        return out


def rewrite_source(path, items, args):
    data = read_bytes(path)
    total = 0
    for item in sorted(items, key=lambda it: -len(it.secret_bytes)):
        placeholder = args.placeholder.replace("NAME", item.key).encode(item.encoding)
        count = data.count(item.secret_bytes)
        if count == 0:
            item.status, item.note = "skipped", u"text no longer present (covered by another replacement?)"
            continue
        data = data.replace(item.secret_bytes, placeholder)
        item.status, item.replaced = "done", count
        total += count
    if total:
        write_bytes(path, data)
    return total


def execute(plan, chosen, dotenvx, args, style, decryptor=None, journal=None):
    env_jobs = OrderedDict()

    def job_for(path):
        if path not in env_jobs:
            env_jobs[path] = {"keys": [], "new": [], "items": []}
        return env_jobs[path]

    for item in chosen:
        if item.kind == "env":
            job = job_for(item.path)
            job["keys"].append(item.key)
            job["items"].append(item)
        elif item.new_entry:
            job = job_for(item.store)
            job["keys"].append(item.key)
            job["new"].append((item.key, item.secret))
            job["items"].append(item)
    # A placeholder must never point at a key that is missing or still plaintext:
    # when the item that was going to add or encrypt that entry was not selected,
    # take care of it here.
    existing = {}
    for item in chosen:
        if item.kind != "source" or item.new_entry:
            continue
        if item.store not in existing:
            values = {}
            if os.path.isfile(item.store):
                try:
                    for key, value, _ in parse_env_entries(read_text(item.store)):
                        values[key] = value
                except (IOError, OSError):
                    pass
            existing[item.store] = values
        values = existing[item.store]
        if item.store in env_jobs and item.key in env_jobs[item.store]["keys"]:
            continue  # a selected item already adds or encrypts it
        if item.key in values and values[item.key].startswith(ENCRYPTED_PREFIX):
            continue  # already encrypted
        job = job_for(item.store)
        job["keys"].append(item.key)
        if item.key not in values:
            job["new"].append((item.key, item.secret))
        job["items"].append(item)
    for path, keys in plan.extra_env_keys.items():
        if any(item.store == path for item in chosen):
            job_for(path)["keys"].extend(keys)

    say(u"")
    say(style.bold(u"Encrypting ..."))
    failed_stores = set()
    for env_path, job in env_jobs.items():
        keys = []
        for key in job["keys"]:
            if key not in keys:
                keys.append(key)
        if not keys:
            continue
        ok, note, warnings = encrypt_env_file(env_path, job, dotenvx, plan.root, args, decryptor, journal,
                                              custody=plan.custody)
        if ok:
            say(u"  %s %s: encrypted %d key(s): %s" % (style.ok("[ok]"), plan.rel(env_path), len(keys),
                                                      u", ".join(keys)))
            for warning in warnings:
                say(u"  %s %s: %s" % (style.warn("[--]"), plan.rel(env_path), warning))
        else:
            failed_stores.add(env_path)
            say(u"  %s %s: %s" % (style.bad("[!!]"), plan.rel(env_path), note))
        for item in job["items"]:
            if item.kind == "env":
                item.status = "done" if ok else "failed"
                item.note = note

    source_jobs = OrderedDict()
    for item in chosen:
        if item.kind != "source":
            continue
        if item.store in failed_stores:
            item.status, item.note = "failed", u"its value could not be stored encrypted, so the plaintext was left alone"
            continue
        if args.no_rewrite:
            item.status = "stored"
            continue
        source_jobs.setdefault(item.path, []).append(item)
    for path, items in source_jobs.items():
        try:
            total = rewrite_source(path, items, args)
        except (IOError, OSError) as exc:
            for item in items:
                item.status, item.note = "failed", to_text(str(exc))
            say(u"  %s %s: %s" % (style.bad("[!!]"), plan.rel(path), to_text(str(exc))))
            continue
        names = u", ".join(sorted(set(item.key for item in items if item.status == "done")))
        if total and journal is not None:
            journal.add("source", path, names)
        say(u"  %s %s: replaced %d occurrence(s) of %d secret(s) with placeholders (%s)"
            % (style.ok("[ok]"), plan.rel(path), total,
               len([it for it in items if it.status == "done"]), names))
    for item in chosen:
        if item.status in ("failed", "skipped") and item.kind == "source":
            badge = style.bad("[!!]") if item.status == "failed" else style.warn("[--]")
            say(u"  %s %s: %s: %s" % (badge, plan.rel(item.path), item.key, item.note))
    for item in chosen:
        if item.kind != "quarantine":
            continue
        try:
            moved, warning = move_to_quarantine(item, plan, journal)
        except (IOError, OSError) as exc:
            item.status, item.note = "failed", to_text(str(exc))
            say(u"  %s %s: could not move to quarantine: %s" % (style.bad("[!!]"), plan.rel(item.path), item.note))
            continue
        item.status = "done"
        say(u"  %s %s: moved to %s%s" % (style.ok("[ok]"), plan.rel(item.path), plan.rel(moved),
                                       u" (encrypted)" if plan.quarantine_crypto else u""))
        if warning:
            say(u"  %s %s: %s" % (style.warn("[--]"), plan.rel(moved), warning))
    return [item for item in chosen if item.status == "failed"]


# --------------------------------------------------------------------------
# Afterwards: keys files, .gitignore, advice
# --------------------------------------------------------------------------

def find_git_root(start):
    path = start
    while True:
        if os.path.exists(os.path.join(path, ".git")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def discover_keys_files(env_paths, root):
    candidates = [os.path.join(root, ".env.keys")]
    for env_path in env_paths:
        folder = os.path.dirname(env_path)
        candidates.append(os.path.join(folder, ".env.keys"))
        try:
            match = KEYS_HINT_RE.search(read_text(env_path))
        except (IOError, OSError):
            match = None
        if match:
            candidates.append(os.path.normpath(os.path.join(folder, match.group(1))))
    # One entry per file, whatever path leads to it: the -fk hint dotenvx writes may spell the
    # folder through a symlink (/private/var for /var on macOS), unlike the paths we build.
    found, seen = [], set()
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        identity = os.path.realpath(candidate)
        if identity in seen:
            continue
        seen.add(identity)
        found.append(candidate)
    return found


def env_paths_with_keys(plan, chosen, keys_files):
    """The env files this run wrote whose private key sits in one of keys_files, in plan order."""
    paths = []
    for item in chosen:
        for path in ((item.path if item.kind == "env" else None), item.store):
            if path and path not in paths and (plan.custody.get(path) or ("file",))[0] == "file":
                paths.append(path)
    return paths


def keys_file_for(env_path, keys_files):
    """The keys file holding the private key of env_path: dotenvx names the key after
    the env file (DOTENV_PRIVATE_KEY_PRODUCTION for .env.production), so look for the
    name that matches the public key the env file carries."""
    if not keys_files:
        return None
    try:
        match = re.search(r"^\s*DOTENV_PUBLIC_KEY(\w*)\s*=", read_text(env_path), re.M)
    except (IOError, OSError):
        match = None
    if match:
        wanted = u"DOTENV_PRIVATE_KEY" + match.group(1)
        for keys_file in keys_files:
            try:
                if re.search(r"^\s*%s\s*=" % re.escape(wanted), read_text(keys_file), re.M):
                    return keys_file
            except (IOError, OSError):
                continue
    return keys_files[0]


def git_ignores(git_root, path):
    """Ask git whether path is ignored: True / False, or None when git cannot tell."""
    git = which("git")
    if not git:
        return None
    try:
        code, _, _ = run_command([git, "check-ignore", "-q", "--no-index", "--", path], cwd=git_root)
    except (OSError, IOError):
        return None
    if code in (0, 1):
        return code == 0
    return None


def ensure_gitignore(git_root, paths, pattern=".env.keys*",
                     why="dotenvx private decryption keys - never commit"):
    """Make sure git ignores the given paths, adding `pattern` to the root .gitignore if
    it does not. Returns (changed, message).

    Asks git itself (`git check-ignore`) so nested .gitignore files and negated
    rules are honoured; without git, falls back to looking for a matching line.
    The paths need not exist yet: this runs before dotenvx writes them.
    """
    ignore_path = os.path.join(git_root, ".gitignore")
    if os.path.islink(ignore_path):
        ignore_path = os.path.realpath(ignore_path)
    existing = read_bytes(ignore_path) if os.path.isfile(ignore_path) else b""
    names = []
    for path in paths:
        try:
            name = slash_path(os.path.relpath(path, git_root))
        except ValueError:
            name = slash_path(path)
        if name not in names:
            names.append(name)
    verdicts = [git_ignores(git_root, path) for path in paths]
    if verdicts and all(verdict is True for verdict in verdicts):
        return False, u"git already ignores %s" % u", ".join(names)
    if any(verdict is None for verdict in verdicts):
        lines = set(line.strip() for line in to_text(existing).splitlines())
        known = set([pattern])
        if pattern == ".env.keys*":
            known |= set([".env.keys", ".env*", ".env.*", "*.keys", "/.env.keys", "**/.env.keys"])
        if lines & known:
            return False, u".gitignore already ignores %s" % pattern
    newline = b"\r\n" if b"\r\n" in existing else b"\n"
    data = existing
    if data and not data.endswith(b"\n"):
        data += newline
    # Appended last, so it wins over any earlier negated rule in this file.
    data += newline + to_bytes(u"# %s (added by sweep_and_secure.py)" % why) + newline
    data += to_bytes(pattern) + newline
    write_bytes(ignore_path, data)
    still_visible = [name for name, path in zip(names, paths) if git_ignores(git_root, path) is False]
    if still_visible:
        return True, (u"added %s to %s, but git STILL does not ignore %s - look for a negated"
                      u" rule in a nested .gitignore" % (pattern, ignore_path, u", ".join(still_visible)))
    return True, u"added %s to %s" % (pattern, ignore_path)


def git_tracked(git_root, path):
    git = which("git")
    if not git:
        return False
    try:
        code, _, _ = run_command([git, "ls-files", "--error-unmatch", "--", path], cwd=git_root)
    except (OSError, IOError):
        return False
    return code == 0


def prog_name():
    return os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "sweep-and-secure"


def print_next_steps(plan, chosen, keys_files, args, style):
    env_touched = []
    for item in chosen:
        if item.status in ("done", "stored") and item.store and item.store not in env_touched:
            env_touched.append(item.store)
    source_done = [item for item in chosen if item.kind == "source" and item.status == "done"]
    stored_only = [item for item in chosen if item.kind == "source" and item.status == "stored"]
    say(u"")
    say(style.bold(u"Next steps"))
    step = [0]

    def bullet(text):
        step[0] += 1
        say(u"  %d. %s" % (step[0], text))

    if source_done:
        placeholder = args.placeholder.replace("NAME", source_done[0].key)
        bullet(u"Your files now contain placeholders such as %s where secrets used to be. Change the code to"
               % placeholder)
        say(u"     read them from the environment instead (os.environ[\"%s\"], process.env.%s, ...)."
            % (source_done[0].key, source_done[0].key))
    if stored_only:
        bullet(u"--no-rewrite left the plaintext in %d file(s). Remove it yourself and read the values from"
               u" the environment." % len(set(item.path for item in stored_only)))
    if env_touched:
        bullet(u"Run your app through dotenvx so the values are decrypted at run time:")
        needs_fk = False
        for env_path in env_touched:
            rel = plan.rel(env_path)
            command = u"dotenvx run" if rel == ".env" else u"dotenvx run -f %s" % rel
            keys_file = keys_file_for(env_path, keys_files)
            if keys_file and (os.path.realpath(os.path.dirname(keys_file))
                              != os.path.realpath(os.path.dirname(env_path))):
                command += u" -fk %s" % plan.rel(keys_file)
                needs_fk = True
            say(u"       %s -- <your command>" % command)
        if needs_fk:
            say(u"     (dotenvx only looks for .env.keys next to the env file; -fk points it at the one it wrote)")
    quarantined = [item for item in chosen if item.kind == "quarantine" and item.status == "done"]
    if quarantined and plan.quarantine_crypto:
        bullet(u"%d file(s) holding secrets were moved to %s, AES-256 encrypted; the passphrase of each is kept in"
               % (len(quarantined), plan.rel(plan.quarantine)))
        say(u"     %s/%s, encrypted by dotenvx%s. %s and %s map each file to where it came from."
            % (plan.rel(plan.quarantine), QUARANTINE_KEYS_ENV,
               u" with the key pair of %s" % plan.rel(plan.store) if quarantine_shares_store(plan) else u"",
               QUARANTINE_MANIFEST, QUARANTINE_INDEX))
        say(u"     Put one back with  %s --restore <stored name>  once it no longer has to hold the secret, or delete it;"
            % prog_name())
        say(u"     never commit that folder. If a file was tracked by git, commit its removal.")
    elif plan.quarantine_upgraded:
        bullet(u"%d file(s) an earlier run had moved to %s as they were are now AES-256 encrypted; the passphrase of each"
               % (len(plan.quarantine_upgraded), plan.rel(plan.quarantine)))
        say(u"     is kept in %s/%s, encrypted by dotenvx%s. Put one back with  %s --restore <stored name>."
            % (plan.rel(plan.quarantine), QUARANTINE_KEYS_ENV,
               u" with the key pair of %s" % plan.rel(plan.store) if quarantine_shares_store(plan) else u"", prog_name()))
    elif quarantined:
        bullet(u"%d file(s) holding secrets were moved to %s%s; its %s and %s map each one to where it came from."
               % (len(quarantined), plan.rel(plan.quarantine),
                  u" AS THEY ARE (%s)" % plan.quarantine_plain_reason if plan.quarantine_plain_reason else u"",
                  QUARANTINE_MANIFEST, QUARANTINE_INDEX))
        say(u"     Nothing reads them from there. Fix or rebuild them without the secrets and move them back, or")
        say(u"     delete them; never commit that folder. If a file was tracked by git, commit its removal.")
    if plan.compiled:
        bullet(u"The findings in compiled code were listed and left alone. Check each with  strings <file> |"
               u" grep -n <start of the value>;  a real credential there has to be rotated, and the program rebuilt without it.")
    native = [(path, where) for path, (kind, where, _) in plan.custody.items() if kind == "native"]
    if native:
        store = native[0][1]
        files = u", ".join(plan.rel(path) for path, _ in native)
        bullet(u"The private key of %s is in the %s, kept by dotenvx: there is no key file to back up." % (files, store))
        say(u"     The encrypted env files themselves are safe to commit. Another machine or CI gets the key as the")
        say(u"     DOTENV_PRIVATE_KEY variable (a CI secret);  dotenvx keypair DOTENV_PRIVATE_KEY -f %s  prints it."
            % plan.rel(native[0][0]))
    if keys_files:
        bullet(u"The private decryption key lives in %s." % u", ".join(plan.rel(k) for k in keys_files))
        say(u"     NEVER commit it. Share it through a password manager or your CI's secret store")
        say(u"     (the DOTENV_PRIVATE_KEY* variables). The encrypted env files themselves are safe to commit.")
    handled = [item for item in chosen if item.status in ("done", "stored")]
    if not handled:
        print_dotenvx_primer(plan, chosen, keys_files, args, style)
        return
    bullet(u"These secrets sat in plaintext, so treat them as exposed and rotate them.")
    guides = OrderedDict()
    for item in chosen:
        if item.status not in ("done", "stored"):
            continue
        guide = item.extra.get("rotation_guide") if isinstance(item.extra, dict) else None
        if guide or item.detector not in guides:
            guides[item.detector] = guide
    with_guide = [(d, g) for d, g in guides.items() if g]
    without = [d for d, g in guides.items() if not g]
    if with_guide:
        say(u"     How-to guides:")
        for detector, guide in with_guide:
            say(u"       %-18s %s" % (detector, guide))
    if without:
        say(u"     Rotate through the provider's console: %s" % u", ".join(without))
    git_root = find_git_root(plan.root)
    if git_root:
        bullet(u"Git history still holds the old plaintext. Check it with:  trufflehog git file://%s"
               % plan.rel(git_root))
    print_dotenvx_primer(plan, chosen, keys_files, args, style)


def print_dotenvx_primer(plan, chosen, keys_files, args, style):
    """From here on dotenvx is the tool in use, so a run that set up a key pair for the first time
    ends with the few commands and rules a first-time user needs; a run that only added to files
    dotenvx already managed gets one line."""
    fresh = [path for path, (kind, _, _) in plan.custody.items() if kind in ("native", "file")]
    env_touched = []
    for item in chosen:
        if item.status in ("done", "stored") and item.store and item.store not in env_touched:
            env_touched.append(item.store)
        if item.kind == "env" and item.status == "done" and item.path not in env_touched:
            env_touched.append(item.path)
    say(u"")
    if not fresh:
        say(style.dim(u"dotenvx is the tool in use from here on (dotenvx run, get, set):  https://dotenvx.com/docs"))
        return
    say(style.bold(u"dotenvx from here on"))
    say(u"  This tool has done its part: the secrets are encrypted in your env files, and the private key that")
    native = [(path, where) for path, (kind, where, _) in plan.custody.items() if kind == "native"]
    if native and not keys_files:
        say(u"  decrypts them is in the %s, kept by dotenvx. Day to day you use dotenvx itself, not this tool:"
            % native[0][1])
    elif native:
        say(u"  decrypts them is in the %s, or in .env.keys next to the env file (see above). Day to day you use"
            % native[0][1])
        say(u"  dotenvx itself, not this tool:")
    else:
        say(u"  decrypts them is in .env.keys next to each env file. Day to day you use dotenvx itself, not this tool:")
    def file_flag(path):
        rel = plan.rel(path)
        return u"" if rel == u".env" else u" -f %s" % rel

    app_flag = file_flag(env_touched[0]) if env_touched else u""   # the app's env file; .env when none was touched
    key_env = fresh[0]            # the file whose key pair is new: the store, or the quarantine's own .env
    key_flag = file_flag(key_env)
    rows = [
        (u"dotenvx run%s -- <your command>" % app_flag, u"runs a program with the decrypted values in its environment"),
        (u"dotenvx get%s KEY" % app_flag, u"prints one decrypted value; without KEY, all of them"),
        (u"dotenvx set%s KEY \"value\"" % app_flag,
         u"adds or changes a value, encrypted on the way in: the file never holds plaintext"),
        (u"dotenvx keypair%s%s" % (key_flag, u" DOTENV_PRIVATE_KEY" if not key_flag else u""),
         u"prints the %s, to give another machine or CI as the DOTENV_PRIVATE_KEY variable"
         % (u"private key" if not key_flag else u"key pair")),
    ]
    store = native_store_name()
    key_in_file = plan.custody.get(key_env, (None,))[0] == "file"
    if key_in_file and store and dotenvx_version() >= DOTENVX_NATIVE_SINCE and not getattr(args, "no_native", False):
        rows.append((u"dotenvx native up%s" % key_flag,
                     u"moves the private key from .env.keys into the %s, so that nothing is left on disk" % store))
    if plan.quarantine and plan.quarantine_crypto and (plan.quarantine_upgraded or any(
            item.kind == "quarantine" and item.status == "done" for item in chosen)):
        rows.append((u"%s --restore <stored name>" % prog_name(),
                     u"puts a quarantined file back, decrypted (its passphrase is in %s/%s)"
                     % (plan.rel(plan.quarantine), QUARANTINE_KEYS_ENV)))
    width = max(len(command) for command, _ in rows)
    for command, what in rows:
        say(u"    %-*s   %s" % (width, command, what))
    say(u"  dotenvx looks for the private key in the DOTENV_PRIVATE_KEY* variables of the environment, then in .env.keys")
    say(u"  next to the env file%s. To add a secret found later, run this tool again or use dotenvx set."
        % (u", then in the %s" % store if store else u""))
    say(u"  Docs: https://dotenvx.com/docs")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def parse_args(argv):
    prog = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else "sweep-and-secure"
    parser = argparse.ArgumentParser(
        prog=prog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Scan a folder tree for API keys and secrets with TruffleHog, list what was found\n"
            "(and what is already encrypted), then -- after you confirm -- encrypt them with dotenvx.\n"
            "\n"
            "  secrets in dotenv files   -> encrypted in place        (KEY=\"encrypted:...\")\n"
            "  secrets in other files    -> moved into the project's .env, encrypted, and the\n"
            "                               plaintext replaced by a placeholder like ${KEY}"),
        epilog=(
            "exit codes: 0 done (or nothing to do), 1 missing tool / scan incomplete or failed / encryption failed,\n"
            "            2 you said no or gave no answer (stdin not a terminal, nothing piped, no --yes), 130 interrupted\n"
            "\n"
            "A log of every run is kept in " + default_log_dir() + "\n"
            "(--log-dir to change, --no-log to skip); it holds what was printed, the prompts and the tool\n"
            "commands, never secret values.\n"
            "\n"
            "TruffleHog: https://trufflesecurity.com/trufflehog     dotenvx: https://dotenvx.com"),
    )
    parser.add_argument("path", nargs="?", default=".", help="folder to sweep (default: current folder)")
    parser.add_argument("-n", "--dry-run", "--list", dest="dry_run", action="store_true",
                        help="scan and list only; change nothing")
    parser.add_argument("-y", "--yes", action="store_true", help="encrypt everything found without asking")
    parser.add_argument("--env-file", default=".env", metavar="PATH",
                        help="dotenv file that receives secrets moved out of other files "
                             "(default: .env inside the swept folder)")
    parser.add_argument("--env-all", action="store_true",
                        help="also encrypt every other plaintext key in dotenv files, "
                             "not only the ones TruffleHog flagged")
    parser.add_argument("--no-rewrite", action="store_true",
                        help="store secrets encrypted but leave the source files untouched")
    parser.add_argument("--quarantine", action="store_true",
                        help="with --yes, also move every file that holds a secret and cannot be fixed in place "
                             "(archives, binaries, PDFs, lock files, example env files, ...) out of the tree into "
                             "the quarantine folder, keeping relative paths (interactive runs offer this anyway)")
    parser.add_argument("--quarantine-dir", metavar="DIR", default=None,
                        help="the quarantine folder (default: %s inside the swept folder); implies --quarantine"
                             % QUARANTINE_DEFAULT)
    parser.add_argument("--no-native", action="store_true",
                        help="keep new private keys in .env.keys files instead of letting dotenvx put them in the "
                             "OS secret store (macOS Keychain, Windows Credential Manager, Linux Secret Service)")
    parser.add_argument("--placeholder", default="${NAME}", metavar="TEMPLATE",
                        help="text that replaces a secret in source files; NAME becomes the key "
                             "(default: ${NAME})")
    parser.add_argument("--verify", action="store_true",
                        help="let TruffleHog verify each secret against its service (needs network access)")
    parser.add_argument("--exclude", action="append", default=[], metavar="REGEX",
                        help="skip paths matching this regular expression (repeatable)")
    parser.add_argument("--no-default-excludes", action="store_true",
                        help="also scan .git, node_modules, virtualenvs and friends "
                             "(.env.keys and staging files stay excluded)")
    parser.add_argument("--scan-compiled", action="store_true",
                        help="also scan compiled code (.so, .dll, .exe, .pyc, .class, ... and files whose first bytes say "
                             "ELF, PE, Mach-O or WebAssembly) and list what TruffleHog finds there; such files are never "
                             "rewritten or moved. Skipped by default: TruffleHog 3.75 and later skip them anyway, and "
                             "older releases match symbol names in them")
    parser.add_argument("--min-length", type=int, default=8, metavar="N",
                        help="ignore secrets shorter than N characters (default: 8)")
    parser.add_argument("--restore", metavar="FILE",
                        help="put FILE back from the quarantine folder of PATH, decrypting it (FILE is the stored name "
                             "or the original path as MANIFEST.txt lists them); nothing is scanned")
    parser.add_argument("--openssl", metavar="PATH",
                        help="openssl executable that encrypts quarantined files (default: search PATH, and on Windows "
                             "Git's copy)")
    parser.add_argument("--trufflehog", metavar="PATH", help="trufflehog executable (default: search PATH)")
    parser.add_argument("--dotenvx", metavar="PATH", help="dotenvx executable (default: search PATH)")
    parser.add_argument("--no-version-check", action="store_true",
                        help="use a tool even if its --version could not be read")
    parser.add_argument("--log-dir", metavar="DIR",
                        help="where this run's log goes (default: the user's state folder, see --help's notes; "
                             "SWEEP_AND_SECURE_LOG_DIR overrides it)")
    parser.add_argument("--no-log", action="store_true", help="do not write a run log")
    parser.add_argument("-v", "--verbose", action="store_true", help="show the commands run and tool output")
    parser.add_argument("--no-color", action="store_true", help="plain output")
    parser.add_argument("--check-setup", action="store_true",
                        help="check that Python, TruffleHog and dotenvx are in place and run both tools in a "
                             "scratch folder; exit 0 if a real run would work, 1 otherwise; nothing is scanned")
    parser.add_argument("--version", action="version", version="sweep-and-secure " + __version__)
    args = parser.parse_args(argv)
    if "NAME" not in args.placeholder:
        parser.error("--placeholder must contain NAME (it is replaced by the key name)")
    if args.min_length < 1:
        parser.error("--min-length must be at least 1")
    return args


def protect_keys_files_early(git_root, root, chosen, style, plan=None, quarantine_too=False):
    """Before anything is encrypted or moved: make sure git will ignore the private key
    files dotenvx is about to write, and the quarantine folder archives are about to be
    moved into, so that a crash half way cannot leave them exposed."""
    candidates = [os.path.join(root, ".env.keys")]
    for item in chosen:
        if item.store:
            candidate = os.path.join(os.path.dirname(item.store), ".env.keys")
            if candidate not in candidates:
                candidates.append(candidate)
    jobs = [(candidates, ".env.keys*", "dotenvx private decryption keys - never commit")]
    if plan is not None and plan.quarantine and (quarantine_too or any(item.kind == "quarantine" for item in chosen)):
        try:
            rel = slash_path(os.path.relpath(plan.quarantine, git_root))
        except ValueError:
            rel = None
        if rel and not rel.startswith(".."):
            # ask git about a file inside the folder: a "dir/" pattern cannot match a folder that
            # does not exist yet, but it does match the paths beneath it
            inside = os.path.join(plan.quarantine, QUARANTINE_MANIFEST)
            jobs.append(([inside], u"/%s/" % rel, "files with secrets moved to quarantine - never commit"))
    for paths, pattern, why in jobs:
        try:
            changed, message = ensure_gitignore(git_root, paths, pattern, why)
        except (IOError, OSError) as exc:
            say(u"  %s could not update .gitignore: %s" % (style.warn("[--]"), to_text(str(exc))))
            continue
        say(u"  %s %s" % (style.ok("[ok]") if changed else style.dim("[--]"), message))


def wrap_up(plan, chosen, journal, root, git_root, args, style, failed, error, scan_incomplete):
    """After execute(), however it ended: protect the private key files, then say what
    the state of the tree is - the normal summary and next steps, or exactly what an
    interrupted or failed run left behind."""
    env_paths = journal.paths("env")
    for item in chosen:
        if item.store and item.status in ("done", "stored") and item.store not in env_paths:
            env_paths.append(item.store)
    keys_files = discover_keys_files(env_paths, root)
    native = [(path, where, note) for path, (kind, where, note) in plan.custody.items() if kind == "native"]
    existing = [path for path, (kind, where, _) in plan.custody.items() if kind == "existing"]
    if native or existing or keys_files:
        say(u"")
    for env_path, store, note in native:
        say(u"  %s private key of %s: %s the %s, kept by dotenvx (nothing on disk)"
            % (style.ok("[ok]"), plan.rel(env_path), (note + u" into") if note.startswith(u"moved") else u"in", store))
    for env_path in existing:
        if plan.quarantine and env_path == quarantine_env_path(plan) and quarantine_shares_store(plan):
            say(u"  %s %s holds the quarantine's passphrases, encrypted to the key pair of %s"
                % (style.ok("[ok]"), plan.rel(env_path), plan.rel(plan.store)))
            continue
        say(u"  %s %s already had its dotenvx key pair; its private key stays where it was"
            % (style.ok("[ok]"), plan.rel(env_path)))
    if keys_files:
        fresh_files = dict((os.path.realpath(where), note) for path, (kind, where, note) in plan.custody.items()
                           if kind == "file")
        for keys_file in keys_files:
            identity = os.path.realpath(keys_file)
            why = (u"  (file custody: %s)" % file_custody_reason(args, fresh_files[identity])
                   if identity in fresh_files else u"")
            say(u"  %s private key file: %s%s" % (style.ok("[ok]"), plan.rel(keys_file), style.dim(why)))
            if git_root and git_tracked(git_root, keys_file):
                say(u"  %s %s is TRACKED BY GIT. Remove it from the index now:  git rm --cached %s"
                    % (style.bad("[!!]"), plan.rel(keys_file), plan.rel(keys_file)))
        if git_root:
            try:
                changed, message = ensure_gitignore(git_root, keys_files)
                if changed or u"STILL" in message:
                    say(u"  %s %s" % (style.warn("[!!]") if u"STILL" in message else style.ok("[ok]"), message))
            except (IOError, OSError) as exc:
                say(u"  %s could not update .gitignore: %s" % (style.warn("[--]"), to_text(str(exc))))
        else:
            say(u"  %s not a git repository: keep .env.keys out of any backups or shares you make."
                % style.warn("[--]"))

    if error is not None:
        env_written = journal.paths("env")
        source_written = journal.paths("source")
        say(u"")
        say(style.bad(u"Stopped early (%s). State of the tree:" % error))
        if not env_written and not source_written:
            say(u"  nothing was changed.")
        for path in env_written:
            say(u"  encrypted and saved:   %s" % plan.rel(path))
        for path in source_written:
            say(u"  placeholders written:  %s" % plan.rel(path))
        for kind, path, detail in journal.events:
            if kind == "quarantine":
                say(u"  moved to quarantine:   %s  ->  %s" % (plan.rel(path), plan.rel(detail) if detail else u"?"))
        pending = OrderedDict()
        for item in chosen:
            if item.kind == "source" and item.status == "planned" and item.store in env_written:
                pending.setdefault(plan.rel(item.path), []).append(item.key)
        for path, keys in pending.items():
            say(u"  still plaintext:       %s (%s; the value is already stored encrypted)"
                % (path, u", ".join(sorted(set(keys)))))
        if pending:
            say(u"  Run again to finish: stored values are recognised and reused, not duplicated.")
        return

    stored = set((item.store, item.key) for item in chosen
                 if item.status in ("done", "stored") and item.kind != "quarantine")
    moved = [item for item in chosen if item.kind == "quarantine" and item.status == "done"]
    sources = [item for item in chosen if item.kind == "source"]
    removed = sum(item.replaced for item in sources if item.status == "done")
    removed_files = len(set(item.path for item in sources if item.status == "done"))
    skipped = [item for item in sources if item.status == "skipped"]
    parts = [u"%d secret(s) stored encrypted" % len(stored)]
    if sources and not args.no_rewrite:
        parts.append(u"%d plaintext occurrence(s) removed from %d file(s)" % (removed, removed_files))
    if moved:
        parts.append(u"%d file(s) moved to %s%s" % (len(moved), plan.rel(plan.quarantine),
                                                   u" (encrypted)" if plan.quarantine_crypto else u""))
    moved_keys = [path for path, (kind, _, note) in plan.custody.items() if kind == "native" and note.startswith(u"moved")]
    if moved_keys:
        parts.append(u"%d private key(s) moved into the %s" % (len(moved_keys), native_store_name()))
    if plan.quarantine_upgraded:
        parts.append(u"%d quarantined file(s) encrypted in place" % len(plan.quarantine_upgraded))
    if failed:
        parts.append(u"%d failed" % len(failed))
    if plan.upgrade_failures or plan.quarantine_upgrade_failed:
        parts.append(u"%d could not be tightened (see above)" % (len(plan.upgrade_failures) + len(plan.quarantine_upgrade_failed)))
    if skipped:
        parts.append(u"%d rewrite(s) skipped (text no longer present)" % len(skipped))
    attention = [entry for entry in plan.unfixable.values()
                 if entry.item is None or entry.item.status != "done" or entry.item not in chosen]
    if attention:
        parts.append(u"%d file(s) need manual attention (see above)" % len(attention))
    if moved and plan.quarantine_plain_reason:
        say(u"")
        say(u"  %s %d file(s) were moved to %s AS THEY ARE, secrets inside: %s"
            % (style.warn("[--]"), len(moved), plan.rel(plan.quarantine), plan.quarantine_plain_reason))
    summary = u"Done: " + u"; ".join(parts)
    if scan_incomplete:
        summary += u"; the TruffleHog scan was incomplete, run again"
    say(u"")
    say(style.bold(summary))
    if any(item.status in ("done", "stored") for item in chosen) or moved_keys or plan.quarantine_upgraded:
        print_next_steps(plan, chosen, keys_files, args, style)


def main(argv=None):
    args = parse_args(argv)
    style = Style(colour_wanted(args.no_color))
    configure_streams()
    root = os.path.abspath(fs_text(args.path))
    if not os.path.isdir(root):
        say(style.bad(u"[!!] %s is not a folder." % root), sys.stderr)
        return 1
    store = fs_text(args.env_file)
    if not os.path.isabs(store):
        store = os.path.join(root, store)
    store = os.path.normpath(store)
    if os.path.islink(store):
        store = os.path.realpath(store)
    reserved = [re.compile(pattern) for pattern in ALWAYS_EXCLUDES]
    if os.path.basename(store).startswith(TEMP_PREFIX) or is_excluded(store, reserved):
        say(style.bad(u"[!!] --env-file %s: that name is reserved. dotenvx key files (.env.keys*), vault files"
                      u" (.env.vault) and this script's staging files (.sweep-and-secure-*) are never scanned or"
                      u" rewritten, so secrets stored there would be lost; use a name like .env or config/secrets.env."
                      % store), sys.stderr)
        return 1

    global RUN_LOG
    RUN_LOG, log_note = open_run_log(args, root)
    if RUN_LOG is not None:
        RUN_LOG.write(u"sweep-and-secure %s | %s | python %s | %s | cwd %s | args %s"
                      % (__version__, time.strftime("%Y-%m-%d %H:%M:%S %Z"), platform.python_version(),
                         platform.platform(), fs_text(os.getcwd()), u" ".join(fs_text(a) for a in sys.argv[1:])), u"| ")
    say(style.bold(u"sweep-and-secure %s" % __version__) + style.dim(u"  (TruffleHog + dotenvx)"))
    if RUN_LOG is not None:
        say(style.dim(u"Log: %s" % RUN_LOG.path))
    elif log_note:
        say(style.dim(u"(%s)" % log_note))
    if args.check_setup:
        return check_setup(args, root, style)
    say(u"Folder: %s" % root)
    if args.restore:
        tools = locate_tools(args, root, style, names=("dotenvx",))
        return restore_from_quarantine(args, root, store, tools["dotenvx"]["path"], style)
    if args.dry_run:
        last = u"This is a dry run: nothing is changed."
    elif args.yes:
        last = u"--yes was given: it will not ask before changing them."
    else:
        last = u"Nothing is changed before you confirm."
    say(style.warn(u"  Note: this is a security tool that changes files on purpose: it encrypts env files, rewrites"))
    say(style.warn(u"  source files and moves files to quarantine. The changes are deliberate and it cannot undo them;"))
    say(style.warn(u"  commit or back up first. %s" % last))
    tools = locate_tools(args, root, style)

    # Archives holding secrets are offered for quarantine whenever the run asks before
    # acting; a --yes run (scripts, CI) moves them only when told to with --quarantine.
    quarantine_flagged = bool(args.quarantine or args.quarantine_dir)
    quarantine = None
    if quarantine_flagged or not args.yes:
        quarantine = fs_text(args.quarantine_dir or QUARANTINE_DEFAULT)
        if not os.path.isabs(quarantine):
            quarantine = os.path.join(root, quarantine)
        quarantine = os.path.normpath(quarantine)
        name = os.path.basename(quarantine)
        reserved_name = name.startswith(TEMP_PREFIX) or (is_excluded(quarantine, reserved) and name != QUARANTINE_DEFAULT)
        if reserved_name or quarantine == root:
            say(style.bad(u"[!!] --quarantine-dir %s: that folder cannot be used (reserved name, or the swept folder"
                          u" itself)." % quarantine), sys.stderr)
            return 1
    exclude_patterns = list(ALWAYS_EXCLUDES)
    if quarantine and os.path.basename(quarantine) != QUARANTINE_DEFAULT:
        # a custom quarantine folder inside the tree must not be scanned or rewritten either
        exclude_patterns.append(u"^" + re.escape(quarantine).replace(re.escape(os.sep), u"[/\\\\]") + u"([/\\\\]|$)")
    if not args.no_default_excludes:
        exclude_patterns.extend(DEFAULT_EXCLUDES)
    exclude_patterns.extend(args.exclude)
    exclude_res = []
    for pattern in exclude_patterns:
        try:
            exclude_res.append(re.compile(pattern))
        except re.error as exc:
            say(style.bad(u"[!!] bad --exclude pattern %r: %s" % (pattern, exc)), sys.stderr)
            return 1

    scan_excludes = list(exclude_patterns)
    if not args.scan_compiled:
        scan_excludes.append(COMPILED_NAME_PATTERN)   # programs and libraries: by name here, by first bytes below
    say(u"Scanning with TruffleHog (this can take a while on big trees) ...")
    try:
        findings, code, notes = run_trufflehog(tools["trufflehog"]["path"], root, scan_excludes, args,
                                               ScanProgress(sys.stdout))
    except ToolError as exc:
        say(style.bad(u"[!!] %s" % to_text(str(exc))), sys.stderr)
        return 1
    for note in notes:
        say(style.dim(u"  %s" % note))
    version = tools["trufflehog"].get("version")
    if args.scan_compiled and version and version >= TRUFFLEHOG_SKIPS_COMPILED:
        say(style.dim(u"  --scan-compiled: this TruffleHog (%s) skips compiled files itself, as every release from %s does;"
                      u" only the ones it still reads can be listed"
                      % (u".".join(str(v) for v in version), u".".join(str(v) for v in TRUFFLEHOG_SKIPS_COMPILED))))
    completed = complete_aws_pairs(findings)
    if completed:
        say(style.dim(u"  this TruffleHog reported %d AWS key id(s) without the secret access key beside them; the"
                      u" 40-character secret found next to each is included" % completed))
    scan_incomplete = code != 0
    if scan_incomplete:
        say(style.bad(u"[!!] trufflehog exited with status %d after reporting some results, so the scan is"
                      u" probably INCOMPLETE. What it did report is handled below; the exit code will be 1."
                      % code))

    compiled_by_name = []
    encrypted, plaintext, stale = inventory_env_files(root, exclude_res, protect=(store,),
                                                      compiled=None if args.scan_compiled else compiled_by_name)
    if stale:
        names = u", ".join(slash_path(os.path.relpath(path, root)) for path in stale)
        if args.dry_run:
            say(style.dim(u"Leftover staging file(s) from an interrupted run would be removed: %s" % names))
        else:
            removed = remove_stale(stale)
            say(style.dim(u"Removed %d leftover staging file(s) from an interrupted run: %s" % (len(removed), names)))
    decryptor = make_decryptor(tools["dotenvx"]["path"], root, args)
    plan = build_plan(findings, root, store, args, plaintext, exclude_res, decryptor, quarantine)
    plan.compiled_by_name = compiled_by_name
    if plan.quarantine and any(item.kind == "quarantine" for item in plan.items):
        prepare_quarantine_crypto(plan, tools["dotenvx"]["path"], args)
    plan.encrypted = encrypted
    plan.plain_env = plaintext
    plan.quarantine_flagged = quarantine_flagged
    managed_env = []
    for path, _key, _line in encrypted:
        if path not in managed_env:
            managed_env.append(path)
    upgrades = plan_setup_upgrades(plan, managed_env, tools["dotenvx"]["path"], args)
    print_report(plan, args, style, any(f.verified for f in findings))
    print_setup_upgrades(plan, upgrades, args, style)

    if not plan.items and not upgrades_any(upgrades):
        say(u"")
        say(u"Nothing to encrypt.")
        if managed_env:
            print_custody_status(plan, managed_env, tools["dotenvx"]["path"], args, style)
        else:
            print_dotenvx_pointer(style)
        return 1 if scan_incomplete else 0
    if args.dry_run:
        say(u"")
        say(style.dim(u"Dry run: nothing was changed."))
        if not plan.encrypted:
            print_dotenvx_pointer(style)
        return 1 if scan_incomplete else 0

    say(u"")
    chosen = []
    if plan.items:
        chosen = confirm(plan, args, style)
        if not chosen:
            say(u"Nothing encrypted.")
            return 2
    tighten = upgrades_any(upgrades) and confirm_upgrades(upgrades, args, style)
    if not chosen and not tighten:
        say(u"Nothing changed.")
        return 2

    journal = Journal()
    git_root = find_git_root(root)
    if git_root:
        protect_keys_files_early(git_root, root, chosen, style, plan, quarantine_too=tighten and bool(upgrades["quarantine"]))
    failed, error = [], None
    try:
        if chosen:
            failed = execute(plan, chosen, tools["dotenvx"]["path"], args, style, decryptor, journal)
        if tighten:
            say(u"")
            say(style.bold(u"Tightening the setup ..."))
            apply_setup_upgrades(plan, upgrades, tools["dotenvx"]["path"], args, style, journal)
    except KeyboardInterrupt:
        error = u"interrupted"
        raise
    except Exception as exc:  # a bug or an unforeseen failure must not end in a bare traceback
        error = u"unexpected error: %s" % to_text(repr(exc))
        say(style.bad(u"[!!] %s" % error), sys.stderr)
        traceback.print_exc()
    finally:
        wrap_up(plan, chosen, journal, root, git_root, args, style, failed, error, scan_incomplete)
    if error is not None:
        return 1
    return 1 if (failed or scan_incomplete or plan.quarantine_upgrade_failed) else 0


def cli(argv=None):
    """Entry point of the `sweep-and-secure` command: main()'s exit code, 130 on Ctrl-C."""
    global RUN_LOG
    code = 1
    try:
        code = main(argv)
        return code
    except KeyboardInterrupt:
        say(u"\nInterrupted.", sys.stderr)
        code = 130
        return code
    finally:
        if RUN_LOG is not None:
            RUN_LOG.write(u"exit code %s" % code, u"| ")
            RUN_LOG.close()
            RUN_LOG = None


if __name__ == "__main__":
    sys.exit(cli())
