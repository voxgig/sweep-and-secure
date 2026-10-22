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
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import OrderedDict, deque

__version__ = "1.1.0"

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


def say(text=u"", stream=None):
    """print() that never dies: odd terminal encodings, a closed pipe or a missing
    stdout (pythonw) must not take the run down half way through a rewrite."""
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
        "min_version": (3, 0, 0),
        "why_version": "TruffleHog 3.x is needed (the 'filesystem' scanner and --json output).",
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
        "min_version": (1, 0, 0),
        "why_version": "dotenvx 1.0 or newer is needed (per-value 'encrypted:' .env files).",
    }),
])

# Paths TruffleHog should not bother with, and we should never rewrite. Regular
# expressions matched against the full path; TruffleHog sees the path as the OS
# spells it (backslashes on Windows), so both separators are accepted.
# Never scanned and never rewritten, whatever the options say:
QUARANTINE_DEFAULT = ".secrets-quarantine"   # where --quarantine puts archives, unless told otherwise
QUARANTINE_MANIFEST = "MANIFEST.txt"

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


def locate_tools(args, root, style):
    found = {}
    problems = 0
    for name, info in TOOLS.items():
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
        say(u"  %s %-11s %-10s %s" % (style.ok("[ok]"), name,
                                      ".".join(str(v) for v in version) if version else "?",
                                      style.dim(path)))
    if problems:
        say(style.bad(u"Cannot continue: %d required tool(s) missing. Install them and run me again."
                      % problems), sys.stderr)
        sys.exit(1)
    return found


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
        return cls(
            path=os.path.normpath(path),
            line=line,
            detector=to_text(obj.get("DetectorName") or "Unknown"),
            raw=to_text(obj.get("Raw") or ""),
            raw_v2=to_text(obj.get("RawV2") or ""),
            verified=bool(obj.get("Verified")),
            decoder=to_text(obj.get("DecoderName") or "PLAIN"),
            extra=extra if isinstance(extra, dict) else {},
        )


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
        return u"  scanning ... %d file(s), %d finding(s) so far, %s" % (self.files, self.findings, self.elapsed())

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


def run_trufflehog(binary, root, exclude_patterns, args, progress=None):
    # --log-level=3 makes TruffleHog log every file it scans to stderr: that is the
    # progress signal; results stay on stdout as JSON lines.
    cmd = [binary, "filesystem", root, "--json", "--no-update", "--log-level=3"]
    if not args.verify:
        cmd.append("--no-verification")
    exclude_file = None
    if exclude_patterns:
        handle, exclude_file = tempfile.mkstemp(prefix="sweep-and-secure-", suffix=".txt")
        with io.open(handle, "w", encoding="utf-8") as fh:
            fh.write(u"\n".join(to_text(p) for p in exclude_patterns) + u"\n")
        cmd.extend(["--exclude-paths", exclude_file])
    if args.verbose:
        say(u"  $ " + u" ".join(cmd))
    if progress is None:
        progress = ScanProgress(stream=None)
    try:
        try:
            code, out_lines, err_lines = run_streaming(cmd, root, progress.saw_stdout, progress.saw_stderr,
                                                      progress.tick)
        except (OSError, IOError) as exc:
            raise ToolError(u"could not run %s: %s" % (binary, to_text(str(exc))))
    finally:
        progress.finish()
        if exclude_file:
            try:
                os.remove(exclude_file)
            except OSError:
                pass
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
    if code != 0 and not findings:
        tail = u"\n".join(err.strip().splitlines()[-8:])
        raise ToolError(u"trufflehog exited with status %d:\n%s" % (code, tail))
    say(u"  Scanned %d file(s) in %s; TruffleHog reported %d finding(s)."
        % (progress.files, progress.elapsed(), len(findings)))
    if args.verbose and err.strip():
        say(style_dim_block(err))
    return findings, code


def style_dim_block(text):
    return u"\n".join(u"    | " + line for line in text.strip().splitlines()[-12:])


# --------------------------------------------------------------------------
# What is already in the env files
# --------------------------------------------------------------------------

def inventory_env_files(root, exclude_res, protect=()):
    """Return (encrypted, plaintext, stale) over all dotenv files: lists of
    (path, key, line) / (path, key, line, value), and the staging files or folders
    an earlier interrupted run left behind. Paths in protect (the store) are never
    reported as stale, whatever they are called."""
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
        self.items = []
        self.skipped = []            # (path, detector, reason)
        self.encrypted = []          # (path, key, line) already encrypted
        self.plain_env = []          # (path, key, line, value) unflagged plaintext env keys
        self.extra_env_keys = {}     # env path -> [keys] that must be encrypted as well
        self.ignored = 0             # findings inside excluded folders (TruffleHog on Windows)

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
        result = (None, u"symbolic link - fix the target file instead")
    elif not os.path.isfile(path):
        result = (None, u"file not found (moved or deleted during the scan)")
    elif is_example_env_file(name):
        result = (None, u"example/template env file - replace the value with a placeholder by hand")
    elif is_lockfile(name):
        result = (None, u"generated lock file - regenerate it without the secret")
    elif name.lower().endswith(".pdf"):
        result = (None, u"PDF - rewriting bytes would corrupt it; rebuild it without the secret")
    else:
        try:
            size = os.path.getsize(path)
            if size > MAX_FILE_BYTES:
                result = (None, u"file is larger than %d MB" % (MAX_FILE_BYTES // (1024 * 1024)))
            else:
                data = read_bytes(path)
                if b"\x00" in data and data[:2] not in UTF16_BOMS:
                    kind = archive_kind(path)
                    if kind:
                        result = (None, u"%s archive with a secret inside - pass --quarantine to move it out of"
                                        u" the tree, or rebuild it without the secret" % kind)
                    else:
                        result = (None, u"binary file - delete it or rebuild it without the secret")
                else:
                    result = (data, u"")
        except (IOError, OSError) as exc:
            result = (None, u"cannot read: %s" % to_text(str(exc)))
    cache[path] = result
    return result


def build_plan(findings, root, store, args, env_plaintext, exclude_res=(), decryptor=None, quarantine=None):
    plan = Plan(root, store, quarantine)
    cache = {}
    seen = {}
    archives = OrderedDict()   # path -> quarantine item (one per archive, whatever it holds)
    ordered = sorted(findings, key=lambda f: (f.path, f.line, f.raw))
    for finding in ordered:
        if exclude_res and is_excluded(finding.path, exclude_res):
            plan.ignored += 1   # TruffleHog did not honour the exclude (Windows paths); we do
            continue
        data, reason = load_for_edit(finding.path, cache)
        if data is None:
            kind = archive_kind(finding.path) if (quarantine and u"archive" in reason) else None
            if kind:
                item = archives.get(finding.path)
                if item is None:
                    item = Item(finding.path, 0, 0, finding.detector, finding.verified, finding.raw, b"",
                                "utf-8", finding.extra)
                    item.kind, item.key, item.note = "quarantine", u"-", kind
                    archives[finding.path] = item
                    plan.items.append(item)
                elif finding.detector not in item.detector.split(u", "):
                    item.detector += u", " + finding.detector
                continue
            plan.skipped.append((finding.path, finding.detector, reason))
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
                reason = u"secret shorter than --min-length %d" % args.min_length
            else:
                reason = (u"secret text not found verbatim in the file (TruffleHog decoder: %s)"
                          % finding.decoder)
            plan.skipped.append((finding.path, finding.detector, reason))

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
    # the only one left. Hand those over for manual attention instead.
    keep = []
    for item in plan.items:
        if item.kind == "source" and item.new_entry and not quote_env_value(item.secret)[1]:
            plan.skipped.append((item.path, item.detector,
                                 u"dotenvx cannot store this value exactly (%s) - move it into %s by hand"
                                 % (inexact_reason(item.secret), plan.rel(plan.store))))
            continue
        keep.append(item)
    plan.items = keep
    for number, item in enumerate(plan.items, 1):
        item.number = number
    return plan


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
        return u"move to %s" % plan.rel(quarantine_target(item, plan))
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


def quarantine_target(item, plan):
    """Where --quarantine puts this archive: the same relative path under the quarantine folder."""
    try:
        rel = os.path.relpath(item.path, plan.root)
    except ValueError:
        rel = os.path.basename(item.path)
    if rel.startswith(".."):
        rel = os.path.basename(item.path)
    return os.path.join(plan.quarantine, rel)


def move_to_quarantine(item, plan, journal=None):
    """Move one archive out of the tree. Rename when possible; copy then delete across
    file systems. Appends a line to the quarantine's MANIFEST.txt. Returns the new path."""
    target = quarantine_target(item, plan)
    folder = os.path.dirname(target)
    if not os.path.isdir(folder):
        os.makedirs(folder)
    candidate, counter = target, 1
    while os.path.exists(candidate):
        candidate = u"%s.%d" % (target, counter)
        counter += 1
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
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        os.remove(item.path)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = u"%s  %s  <- %s  (%s)\n" % (stamp, slash_path(os.path.relpath(candidate, plan.quarantine)),
                                        plan.rel(item.path), item.detector)
    manifest = os.path.join(plan.quarantine, QUARANTINE_MANIFEST)
    with io.open(manifest, "ab") as fh:
        fh.write(line.encode("utf-8"))
    if journal is not None:
        journal.add("quarantine", item.path, candidate)
    return candidate


def print_report(plan, args, style, verified_any):
    say(u"")
    if not plan.items:
        say(style.ok(u"TruffleHog found no plaintext secrets to encrypt."))
    else:
        files = len(set(item.path for item in plan.items))
        say(style.bold(u"Plaintext secrets found: %d in %d file(s)" % (len(plan.items), files)))
        rows = []
        for item in plan.items:
            where = plan.rel(item.path) + (u":%d" % item.line if item.line else u"")
            kind = item.detector + (u" *" if item.verified else u"")
            rows.append((u"%d" % item.number, kind, item.key or u"-", mask(item.secret), where,
                         action_text(item, plan, args)))
        for line in table(rows, (u"#", u"Type", u"Key / name", u"Secret", u"Where", u"Action")):
            say(line)
        if verified_any:
            say(style.dim(u"  * = TruffleHog verified this credential is live"))
    if plan.skipped:
        say(u"")
        say(style.warn(u"Found but cannot fix automatically: %d" % len(plan.skipped)))
        for path, detector, reason in plan.skipped:
            say(u"  %-18s %s" % (detector, plan.rel(path)))
            say(u"  %-18s %s" % (u"", style.dim(reason)))
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
        return u""
    return to_text(answer).strip()


def confirm(plan, args, style):
    """Interactive y/N/select prompt. Returns the list of items to process."""
    if args.yes:
        return list(plan.items)
    interactive = sys.stdin is not None and hasattr(sys.stdin, "isatty") and sys.stdin.isatty()
    if not interactive:
        say(style.dim(u"(stdin is not a terminal; pass --yes to encrypt without asking)"))
    while True:
        answer = ask(style.bold(u"Encrypt these %d secret(s) now? [y/N/s]  (s = choose which): "
                                % len(plan.items))).lower()
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
            say(u"Selected: " + u", ".join(u"#%d %s" % (it.number, it.key) for it in chosen))
            if ask(u"Encrypt these %d? [Y/n]: " % len(chosen)).lower() in ("", "y", "yes"):
                return chosen
            continue
        say(style.warn(u"Please answer y (yes), n (no) or s (select)."))


# --------------------------------------------------------------------------
# Doing it
# --------------------------------------------------------------------------

def dotenvx_encrypt(dotenvx, env_path, keys, root, args):
    """Run `dotenvx encrypt -f env_path -k KEY ...` with the swept folder as cwd."""
    if not keys:  # without -k dotenvx would encrypt every key in the file
        raise ToolError(u"refusing to run dotenvx encrypt without an explicit key list")
    cmd = [dotenvx, "encrypt", "-f", env_path]
    for key in keys:
        cmd.extend(["-k", key])
    if args.verbose:
        say(u"  $ " + u" ".join(cmd))
    # CI=1 and a non-tty stdin/stderr keep dotenvx 2.x from asking where to keep the
    # private key: it writes .env.keys (in the cwd, i.e. the swept folder) instead.
    code, out, err = run_command(cmd, cwd=root, extra_env={"CI": "1", "DOTENVX_NO_TELEMETRY": "1"})
    if args.verbose and (out.strip() or err.strip()):
        say(style_dim_block(out + "\n" + err))
    if code != 0:
        detail = (err.strip() or out.strip()).splitlines()
        raise ToolError(u"dotenvx exited with status %d: %s" % (code, detail[-1] if detail else u""))


def decrypt_env_value(dotenvx, env_path, key, root, args):
    """Ask dotenvx for the stored value of key: (value, u"") or (None, reason).

    --overload makes the file win over a variable of the same name in our own
    environment (dotenvx otherwise prefers the environment, even for `get`), and
    every keys file that may hold the private key is passed with -fk, because on
    its own dotenvx only looks next to the env file. An undecryptable value comes
    back as the ciphertext with exit status 0, so the text is checked, not the code."""
    cmd = [dotenvx, "get", key, "-f", env_path, "--overload"]
    for keys_file in discover_keys_files([env_path], root):
        cmd.extend(["-fk", keys_file])
    if args.verbose:
        say(u"  $ " + u" ".join(cmd))
    try:
        code, out, err = run_command(cmd, cwd=root, extra_env={"DOTENVX_NO_TELEMETRY": "1"})
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


def make_decryptor(dotenvx, root, args):
    """A cached decrypt_env_value(env_path, key) bound to this run's tools."""
    cache = {}

    def decryptor(env_path, key):
        ident = (env_path, key)
        if ident not in cache:
            cache[ident] = decrypt_env_value(dotenvx, env_path, key, root, args)
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
    """dotenvx 1.x writes .env.keys next to the file it encrypts, i.e. into the
    staging folder; move those keys next to the real env file, merging them into
    a keys file that is already there. Returns that file, or None if nothing was
    written into the staging folder (dotenvx 2.x writes to the cwd instead)."""
    staged = os.path.join(staging, ".env.keys")
    if not os.path.isfile(staged):
        return None
    target = os.path.join(os.path.dirname(os.path.abspath(env_path)), ".env.keys")
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


def fix_keys_hint(data, staged_dir, env_dir):
    """dotenvx writes '# -fk <path to .env.keys>' relative to the file it encrypted,
    i.e. to the staging folder; re-point it at the same keys file from the real
    location of the env file."""
    def fix(match):
        hint = to_text(match.group(2))
        if os.path.isabs(hint):
            return match.group(0)
        target = os.path.normpath(os.path.join(staged_dir, hint))
        try:
            new_hint = slash_path(os.path.relpath(target, env_dir))
        except ValueError:  # different drive on Windows
            new_hint = slash_path(target)
        return match.group(1) + to_bytes(new_hint)
    return KEYS_HINT_LINE_RE.sub(fix, data)


def verify_decrypts(decryptor, env_path, job, keys, before):
    """Decrypt every key we touched and compare. Returns (problems, unverifiable):
    problems are (key, detail) pairs that must fail the file; unverifiable lists the
    keys for which no private key is at hand (dotenvx can encrypt with a public key
    alone, which is what a teammate's clone has)."""
    problems, unverifiable = [], []
    written = dict(job["new"])
    for key in keys:
        value, reason = decryptor(env_path, key)
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


def encrypt_env_file(env_path, job, dotenvx, root, args, decryptor=None, journal=None):
    """Store and encrypt the keys of one env file without ever writing plaintext to it.

    The file (or a fresh header for a new one) is copied into a staging folder
    under the swept root, keeping its exact name because dotenvx derives the
    DOTENV_*_KEY variable names from it; the new entries are appended to the copy;
    dotenvx encrypts the copy; the result is checked (every key is "encrypted:", no
    entry still holds a secret in plaintext, and each value decrypts back to what we
    stored where a private key is at hand); only then is the copy installed over the
    real file in one atomic rename. If anything fails, the real file has not been
    touched. Returns (ok, note, warnings).
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
        dotenvx_encrypt(dotenvx, copy, keys, root, args)
        adopt_keys_file(staging, env_path)
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
            problems, unverifiable = verify_decrypts(decryptor, copy, job, keys, before)
            if problems:
                raise ToolError(u"verification failed: " + u"; ".join(u"%s %s" % p for p in problems))
            if unverifiable:
                warnings.append(u"could not verify %s: no private key for this file is available here;"
                                u" check the values where it is" % u", ".join(unverifiable))
        result = fix_keys_hint(result, staging, os.path.dirname(os.path.abspath(env_path)))
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
        ok, note, warnings = encrypt_env_file(env_path, job, dotenvx, plan.root, args, decryptor, journal)
        if ok:
            say(u"  %s %s: encrypted %d key(s): %s" % (style.ok("[ok]"), plan.rel(env_path), len(keys),
                                                      u", ".join(keys)))
            for warning in warnings:
                say(u"  %s %s: %s" % (style.warn("[!!]"), plan.rel(env_path), warning))
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
            moved = move_to_quarantine(item, plan, journal)
        except (IOError, OSError) as exc:
            item.status, item.note = "failed", to_text(str(exc))
            say(u"  %s %s: could not move to quarantine: %s" % (style.bad("[!!]"), plan.rel(item.path), item.note))
            continue
        item.status = "done"
        say(u"  %s %s: moved to %s" % (style.ok("[ok]"), plan.rel(item.path), plan.rel(moved)))
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
    found = []
    for candidate in candidates:
        if os.path.isfile(candidate) and candidate not in found:
            found.append(candidate)
    return found


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
            if keys_file and os.path.dirname(keys_file) != os.path.dirname(env_path):
                command += u" -fk %s" % plan.rel(keys_file)
                needs_fk = True
            say(u"       %s -- <your command>" % command)
        if needs_fk:
            say(u"     (dotenvx only looks for .env.keys next to the env file; -fk points it at the one it wrote)")
    quarantined = [item for item in chosen if item.kind == "quarantine" and item.status == "done"]
    if quarantined:
        bullet(u"%d archive(s) holding secrets were moved to %s (see its %s for where each came from)."
               % (len(quarantined), plan.rel(plan.quarantine), QUARANTINE_MANIFEST))
        say(u"     Nothing reads them from there. Inspect them, rebuild them without the secrets, or delete")
        say(u"     them; never commit that folder. If an archive was tracked by git, commit its removal.")
    if keys_files:
        bullet(u"The private decryption key lives in %s." % u", ".join(plan.rel(k) for k in keys_files))
        say(u"     NEVER commit it. Share it through a password manager or your CI's secret store")
        say(u"     (the DOTENV_PRIVATE_KEY* variables). The encrypted .env files themselves are safe to commit.")
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
                        help="move archives (zip, tar, gz ...) that hold secrets out of the tree into the "
                             "quarantine folder, keeping their relative paths")
    parser.add_argument("--quarantine-dir", metavar="DIR", default=None,
                        help="the quarantine folder (default: %s inside the swept folder); implies --quarantine"
                             % QUARANTINE_DEFAULT)
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
    parser.add_argument("--min-length", type=int, default=8, metavar="N",
                        help="ignore secrets shorter than N characters (default: 8)")
    parser.add_argument("--trufflehog", metavar="PATH", help="trufflehog executable (default: search PATH)")
    parser.add_argument("--dotenvx", metavar="PATH", help="dotenvx executable (default: search PATH)")
    parser.add_argument("--no-version-check", action="store_true",
                        help="use a tool even if its --version could not be read")
    parser.add_argument("-v", "--verbose", action="store_true", help="show the commands run and tool output")
    parser.add_argument("--no-color", action="store_true", help="plain output")
    parser.add_argument("--version", action="version", version="sweep-and-secure " + __version__)
    args = parser.parse_args(argv)
    if "NAME" not in args.placeholder:
        parser.error("--placeholder must contain NAME (it is replaced by the key name)")
    if args.min_length < 1:
        parser.error("--min-length must be at least 1")
    return args


def protect_keys_files_early(git_root, root, chosen, style, plan=None):
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
    if plan is not None and plan.quarantine and any(item.kind == "quarantine" for item in chosen):
        try:
            rel = slash_path(os.path.relpath(plan.quarantine, git_root))
        except ValueError:
            rel = None
        if rel and not rel.startswith(".."):
            # ask git about a file inside the folder: a "dir/" pattern cannot match a folder that
            # does not exist yet, but it does match the paths beneath it
            inside = os.path.join(plan.quarantine, QUARANTINE_MANIFEST)
            jobs.append(([inside], u"/%s/" % rel, "archives with secrets, moved by --quarantine - never commit"))
    for paths, pattern, why in jobs:
        try:
            changed, message = ensure_gitignore(git_root, paths, pattern, why)
        except (IOError, OSError) as exc:
            say(u"  %s could not update .gitignore: %s" % (style.warn("[!!]"), to_text(str(exc))))
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
    if keys_files:
        say(u"")
        for keys_file in keys_files:
            say(u"  %s private key file: %s" % (style.ok("[ok]"), plan.rel(keys_file)))
            if git_root and git_tracked(git_root, keys_file):
                say(u"  %s %s is TRACKED BY GIT. Remove it from the index now:  git rm --cached %s"
                    % (style.bad("[!!]"), plan.rel(keys_file), plan.rel(keys_file)))
        if git_root:
            try:
                changed, message = ensure_gitignore(git_root, keys_files)
                if changed or u"STILL" in message:
                    say(u"  %s %s" % (style.warn("[!!]") if u"STILL" in message else style.ok("[ok]"), message))
            except (IOError, OSError) as exc:
                say(u"  %s could not update .gitignore: %s" % (style.warn("[!!]"), to_text(str(exc))))
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
        for path in journal.paths("quarantine"):
            say(u"  moved to quarantine:   %s" % plan.rel(path))
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
        parts.append(u"%d archive(s) moved to %s" % (len(moved), plan.rel(plan.quarantine)))
    if failed:
        parts.append(u"%d failed" % len(failed))
    if skipped:
        parts.append(u"%d rewrite(s) skipped (text no longer present)" % len(skipped))
    if plan.skipped:
        parts.append(u"%d need manual attention (see above)" % len(plan.skipped))
    summary = u"Done: " + u"; ".join(parts)
    if scan_incomplete:
        summary += u"; the TruffleHog scan was incomplete, run again"
    say(u"")
    say(style.bold(summary))
    if any(item.status in ("done", "stored") for item in chosen):
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

    say(style.bold(u"sweep-and-secure %s" % __version__) + style.dim(u"  (TruffleHog + dotenvx)"))
    say(u"Folder: %s" % root)
    tools = locate_tools(args, root, style)

    quarantine = None
    if args.quarantine or args.quarantine_dir:
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

    say(u"Scanning with TruffleHog (this can take a while on big trees) ...")
    try:
        findings, code = run_trufflehog(tools["trufflehog"]["path"], root, exclude_patterns, args,
                                        ScanProgress(sys.stdout))
    except ToolError as exc:
        say(style.bad(u"[!!] %s" % to_text(str(exc))), sys.stderr)
        return 1
    scan_incomplete = code != 0
    if scan_incomplete:
        say(style.bad(u"[!!] trufflehog exited with status %d after reporting some results, so the scan is"
                      u" probably INCOMPLETE. What it did report is handled below; the exit code will be 1."
                      % code))

    encrypted, plaintext, stale = inventory_env_files(root, exclude_res, protect=(store,))
    if stale:
        names = u", ".join(slash_path(os.path.relpath(path, root)) for path in stale)
        if args.dry_run:
            say(style.dim(u"Leftover staging file(s) from an interrupted run would be removed: %s" % names))
        else:
            removed = remove_stale(stale)
            say(style.dim(u"Removed %d leftover staging file(s) from an interrupted run: %s" % (len(removed), names)))
    decryptor = make_decryptor(tools["dotenvx"]["path"], root, args)
    plan = build_plan(findings, root, store, args, plaintext, exclude_res, decryptor, quarantine)
    plan.encrypted = encrypted
    plan.plain_env = plaintext
    print_report(plan, args, style, any(f.verified for f in findings))

    if not plan.items:
        say(u"")
        say(u"Nothing to encrypt.")
        return 1 if scan_incomplete else 0
    if args.dry_run:
        say(u"")
        say(style.dim(u"Dry run: nothing was changed."))
        return 1 if scan_incomplete else 0

    say(u"")
    chosen = confirm(plan, args, style)
    if not chosen:
        say(u"Nothing encrypted.")
        return 2

    journal = Journal()
    git_root = find_git_root(root)
    if git_root:
        protect_keys_files_early(git_root, root, chosen, style, plan)
    failed, error = [], None
    try:
        failed = execute(plan, chosen, tools["dotenvx"]["path"], args, style, decryptor, journal)
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
    return 1 if (failed or scan_incomplete) else 0


def cli(argv=None):
    """Entry point of the `sweep-and-secure` command: main()'s exit code, 130 on Ctrl-C."""
    try:
        return main(argv)
    except KeyboardInterrupt:
        say(u"\nInterrupted.", sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(cli())
