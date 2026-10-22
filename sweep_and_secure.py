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
import subprocess
import sys
import tempfile
from collections import OrderedDict

__version__ = "1.0.0"

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
    """print() that never dies on odd terminal encodings (Python 2 included)."""
    stream = stream or sys.stdout
    if PY2 and isinstance(text, text_type):  # pragma: no cover
        text = text.encode(getattr(stream, "encoding", None) or "utf-8", "replace")
    stream.write(text)
    stream.write("\n")
    stream.flush()


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

# Paths TruffleHog should not bother with, and we should never rewrite.
# Regular expressions, matched against the full (forward-slash) path.
DEFAULT_EXCLUDES = [
    r"(^|/)\.git(/|$)",
    r"(^|/)\.hg(/|$)",
    r"(^|/)\.svn(/|$)",
    r"(^|/)node_modules(/|$)",
    r"(^|/)__pycache__(/|$)",
    r"(^|/)\.venv(/|$)",
    r"(^|/)venv(/|$)",
    r"(^|/)\.tox(/|$)",
    r"(^|/)\.env\.keys",      # dotenvx private keys: never scan, never touch
    r"(^|/)\.env\.vault$",    # legacy dotenvx vault files
]

ENV_ENTRY_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=(.*)$")
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
MAX_FILE_BYTES = 64 * 1024 * 1024


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
    """Run cmd, feed it stdin_text, return (exit code, stdout text, stderr text)."""
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    if PY2:  # pragma: no cover - Popen wants byte strings on Python 2
        cmd = [a.encode(FS_ENCODING) if isinstance(a, text_type) else a for a in cmd]
        cwd = cwd.encode(FS_ENCODING) if isinstance(cwd, text_type) else cwd
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(to_bytes(stdin_text))
    return proc.returncode, to_text(out), to_text(err)


def read_bytes(path):
    with io.open(path, "rb") as fh:
        return fh.read()


def write_bytes(path, data):
    with io.open(path, "wb") as fh:
        fh.write(data)


def read_text(path):
    return to_text(read_bytes(path))


def slash_path(path):
    return path.replace(os.sep, "/") if os.sep != "/" else path


def is_excluded(path, exclude_res, is_dir=False):
    probe = slash_path(path) + ("/" if is_dir else "")
    for rx in exclude_res:
        if rx.search(probe):
            return True
    return False


def is_env_file(name):
    """Is this file name a dotenv file dotenvx can encrypt?"""
    if name.startswith(".env.keys") or name in (".env.vault", ".envrc"):
        return False
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


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

    Single quotes are fully literal in dotenvx (no $VAR expansion, no escapes),
    so they are the first choice. Returns (quoted_text, exact).
    """
    if "'" not in value:
        return "'" + value + "'", True
    if "`" not in value and "$" not in value:
        return "`" + value + "`", True
    if '"' not in value and "$" not in value and "\\" not in value:
        return '"' + value + '"', True
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"', False


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
        found = which(candidate)
        if found:
            return fs_text(found)
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


def run_trufflehog(binary, root, exclude_patterns, args):
    cmd = [binary, "filesystem", root, "--json", "--no-update"]
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
    try:
        code, out, err = run_command(cmd, cwd=root)
    finally:
        if exclude_file:
            try:
                os.remove(exclude_file)
            except OSError:
                pass
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        finding = Finding.from_json(obj, root)
        if finding is not None:
            findings.append(finding)
    if code != 0 and not findings:
        tail = u"\n".join(err.strip().splitlines()[-8:])
        raise ToolError(u"trufflehog exited with status %d:\n%s" % (code, tail))
    if args.verbose and err.strip():
        say(style_dim_block(err))
    return findings, code


def style_dim_block(text):
    return u"\n".join(u"    | " + line for line in text.strip().splitlines()[-12:])


# --------------------------------------------------------------------------
# What is already in the env files
# --------------------------------------------------------------------------

def inventory_env_files(root, exclude_res):
    """Return (encrypted, plaintext) lists of (path, key, line) over all dotenv files."""
    encrypted, plaintext = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        keep = []
        for name in dirnames:
            if not is_excluded(os.path.join(dirpath, name), exclude_res, is_dir=True):
                keep.append(name)
        dirnames[:] = sorted(keep)
        for name in sorted(filenames):
            if not is_env_file(name):
                continue
            path = os.path.join(dirpath, name)
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
    return encrypted, plaintext


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
        self.secret = secret
        self.secret_bytes = secret_bytes
        self.encoding = encoding
        self.extra = extra or {}
        self.context = None       # identifier guessed from the surrounding line
        self.kind = None          # "env": encrypt KEY in place   "source": move + placeholder
        self.key = None           # env var name holding the value
        self.store = None         # env file that holds (or will hold) the value
        self.new_entry = False    # must we append KEY=value to self.store?
        self.number = 0           # 1-based number shown in the listing
        self.status = "planned"   # planned | done | stored | skipped | failed
        self.note = u""
        self.replaced = 0


class Plan(object):
    def __init__(self, root, store):
        self.root = root
        self.store = store
        self.items = []
        self.skipped = []            # (path, detector, reason)
        self.encrypted = []          # (path, key, line) already encrypted
        self.plain_env = []          # (path, key, line, value) unflagged plaintext env keys
        self.extra_env_keys = {}     # env path -> [keys] that must be encrypted as well

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
        for fragment in (before, after):
            fragment = fragment.strip(" \t\r\n:;,/|=&?")
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


def locate(data, secret, decoder):
    """Find every occurrence of secret in data. Returns [(token_bytes, encoding, offset)]."""
    encodings = ["utf-8"]
    if "UTF16" in (decoder or "").upper():
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
            found = [(m.group(0), encoding, m.start()) for m in pattern.finditer(data)]
            if found:
                return found
    return []


def load_for_edit(path, cache):
    """Read a file we may rewrite. Returns (bytes or None, reason when None)."""
    if path in cache:
        return cache[path]
    result = (None, u"")
    if os.path.islink(path):
        result = (None, u"symbolic link - fix the target file instead")
    elif not os.path.isfile(path):
        result = (None, u"file not found (moved or deleted during the scan)")
    else:
        try:
            size = os.path.getsize(path)
            if size > MAX_FILE_BYTES:
                result = (None, u"file is larger than %d MB" % (MAX_FILE_BYTES // (1024 * 1024)))
            else:
                data = read_bytes(path)
                if b"\x00" in data:
                    result = (None, u"binary or archive file - delete it or rebuild it without the secret")
                else:
                    result = (data, u"")
        except (IOError, OSError) as exc:
            result = (None, u"cannot read: %s" % to_text(str(exc)))
    cache[path] = result
    return result


def build_plan(findings, root, store, args, env_plaintext):
    plan = Plan(root, store)
    cache = {}
    seen = {}
    ordered = sorted(findings, key=lambda f: (f.path, f.line, f.raw))
    for finding in ordered:
        data, reason = load_for_edit(finding.path, cache)
        if data is None:
            plan.skipped.append((finding.path, finding.detector, reason))
            continue
        located = False
        too_short = False
        for candidate in candidate_secrets(finding):
            if len(candidate) < args.min_length:
                too_short = True
                continue
            for token_bytes, encoding, offset in locate(data, candidate, finding.decoder):
                located = True
                ident = (finding.path, token_bytes)
                if ident in seen:
                    continue
                line = data.count(b"\n", 0, offset) + 1
                line_start = data.rfind(b"\n", 0, offset) + 1
                prefix = data[line_start:offset].decode(encoding, "replace")
                item = Item(finding.path, offset, line, finding.detector, finding.verified,
                            token_bytes.decode(encoding, "replace"), token_bytes, encoding,
                            finding.extra)
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

    # Secrets found inside env files: is the secret the value of KEY=... ?
    text_cache = {}
    for item in plan.items:
        if not is_env_file(os.path.basename(item.path)):
            item.kind = "source"
            continue
        if item.path not in text_cache:
            text_cache[item.path] = list(parse_env_entries(to_text(cache[item.path][0])))
        for key, value, line in text_cache[item.path]:
            if value_holds(value, item.secret) and not value.startswith(ENCRYPTED_PREFIX):
                item.kind, item.key, item.store, item.line = "env", key, item.path, line
                break
        if item.kind is None:
            item.kind = "source"   # e.g. a secret in a comment of the .env file

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
    assign_names(plan)
    for number, item in enumerate(plan.items, 1):
        item.number = number
    return plan


def assign_names(plan):
    """Decide the env var name and storage file for every 'source' item."""
    taken = {}        # name -> secret it holds
    by_secret = {}    # secret -> (name, env file)
    store_entries = []
    if os.path.isfile(plan.store):
        try:
            store_entries = list(parse_env_entries(read_text(plan.store)))
        except (IOError, OSError):
            store_entries = []
    for key, value, _ in store_entries:
        taken.setdefault(key, value)
    for item in plan.items:
        if item.kind == "env":
            taken[item.key] = item.secret
            by_secret.setdefault(item.secret, (item.key, item.path))
    for item in plan.items:
        if item.kind != "source":
            continue
        if item.secret in by_secret:
            item.key, item.store = by_secret[item.secret]
            continue
        same_value = [key for key, value, _ in store_entries if value == item.secret]
        if same_value:
            item.key, item.store = same_value[0], plan.store
            plan.extra_env_keys.setdefault(plan.store, []).append(same_value[0])
        else:
            contexts = [other.context for other in plan.items
                        if other.secret == item.secret and other.context]
            base = choose_name(item.detector, contexts[0] if contexts else None, item.secret)
            name, counter = base, 2
            while name in taken and taken[name] != item.secret:
                name = u"%s_%d" % (base, counter)
                counter += 1
            taken[name] = item.secret
            item.key, item.store, item.new_entry = name, plan.store, True
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
    store = plan.rel(item.store)
    if item.kind == "env":
        return u"encrypt in place"
    placeholder = args.placeholder.replace("NAME", item.key)
    if args.no_rewrite:
        return u"store encrypted in %s (file left as is)" % store
    if item.new_entry:
        return u"move to %s, replace with %s" % (store, placeholder)
    return u"replace with %s (value already in %s)" % (placeholder, store)


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
            rows.append((u"%d" % item.number, kind, item.key, mask(item.secret), where,
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
    sys.stdout.write(prompt)
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
    if not sys.stdin.isatty():
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


def encrypt_env_file(env_path, job, dotenvx, root, args):
    """Append new entries (if any), encrypt the keys, verify. Restores the file on failure."""
    existed = os.path.isfile(env_path)
    original = read_bytes(env_path) if existed else None
    inexact = []
    try:
        if job["new"]:
            data = original if original is not None else b""
            if not existed:
                folder = os.path.dirname(env_path)
                if folder and not os.path.isdir(folder):
                    os.makedirs(folder)
                data = (u"# Created by sweep_and_secure.py; values are encrypted with dotenvx "
                        u"(https://dotenvx.com)\n").encode("utf-8")
            newline = b"\r\n" if b"\r\n" in data else b"\n"
            if data and not data.endswith(b"\n"):
                data += newline
            for key, value in job["new"]:
                quoted, exact = quote_env_value(value)
                if not exact:
                    inexact.append(key)
                data += (u"%s=%s" % (key, quoted)).encode("utf-8") + newline
            write_bytes(env_path, data)
        keys = []
        for key in job["keys"]:
            if key not in keys:
                keys.append(key)
        dotenvx_encrypt(dotenvx, env_path, keys, root, args)
        entries = {}
        for key, value, _ in parse_env_entries(read_text(env_path)):
            entries[key] = value
        not_done = [key for key in keys if not entries.get(key, u"").startswith(ENCRYPTED_PREFIX)]
        if not_done:
            raise ToolError(u"dotenvx finished but these keys are still plaintext: " + u", ".join(not_done))
    except (ToolError, IOError, OSError) as exc:
        if original is not None:
            write_bytes(env_path, original)
        elif os.path.isfile(env_path):
            try:
                os.remove(env_path)
            except OSError:
                pass
        return False, to_text(str(exc)), inexact
    return True, u"", inexact


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


def execute(plan, chosen, dotenvx, args, style):
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
    # A placeholder must never point at a key that does not exist: when the item
    # that was going to add the entry was not selected, add it here instead.
    existing_keys = {}
    for item in chosen:
        if item.kind != "source" or item.new_entry:
            continue
        if item.store not in existing_keys:
            keys_in_file = set()
            if os.path.isfile(item.store):
                try:
                    keys_in_file = set(key for key, _, _ in parse_env_entries(read_text(item.store)))
                except (IOError, OSError):
                    pass
            existing_keys[item.store] = keys_in_file
        if item.key in existing_keys[item.store] or (item.store in env_jobs
                                                      and item.key in env_jobs[item.store]["keys"]):
            continue
        job = job_for(item.store)
        job["keys"].append(item.key)
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
        ok, note, inexact = encrypt_env_file(env_path, job, dotenvx, plan.root, args)
        if ok:
            say(u"  %s %s: encrypted %d key(s): %s" % (style.ok("[ok]"), plan.rel(env_path), len(keys),
                                                      u", ".join(keys)))
            for key in inexact:
                say(u"  %s %s: %s contains quotes and $ signs; check it with: dotenvx get %s -f %s"
                    % (style.warn("[!!]"), plan.rel(env_path), key, key, plan.rel(env_path)))
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
        say(u"  %s %s: replaced %d occurrence(s) of %d secret(s) with placeholders (%s)"
            % (style.ok("[ok]"), plan.rel(path), total,
               len([it for it in items if it.status == "done"]), names))
    for item in chosen:
        if item.status in ("failed", "skipped") and item.kind == "source":
            badge = style.bad("[!!]") if item.status == "failed" else style.warn("[--]")
            say(u"  %s %s: %s: %s" % (badge, plan.rel(item.path), item.key, item.note))
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


def ensure_gitignore(git_root):
    """Make sure .env.keys* is ignored. Returns (changed, message)."""
    ignore_path = os.path.join(git_root, ".gitignore")
    existing = read_text(ignore_path) if os.path.isfile(ignore_path) else u""
    patterns = set(line.strip() for line in existing.splitlines())
    if patterns & set([".env.keys", ".env.keys*", ".env*", ".env.*", "*.keys", "/.env.keys", "**/.env.keys"]):
        return False, u".gitignore already ignores .env.keys"
    data = to_bytes(existing)
    if data and not data.endswith(b"\n"):
        data += b"\n"
    data += b"\n# dotenvx private decryption keys - never commit (added by sweep_and_secure.py)\n.env.keys*\n"
    write_bytes(ignore_path, data)
    return True, u"added .env.keys* to %s" % ignore_path


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
        for env_path in env_touched:
            rel = plan.rel(env_path)
            if rel == ".env":
                say(u"       dotenvx run -- <your command>")
            else:
                say(u"       dotenvx run -f %s -- <your command>" % rel)
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
    parser = argparse.ArgumentParser(
        prog="sweep_and_secure.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Scan a folder tree for API keys and secrets with TruffleHog, list what was found\n"
            "(and what is already encrypted), then -- after you confirm -- encrypt them with dotenvx.\n"
            "\n"
            "  secrets in dotenv files   -> encrypted in place        (KEY=\"encrypted:...\")\n"
            "  secrets in other files    -> moved into the project's .env, encrypted, and the\n"
            "                               plaintext replaced by a placeholder like ${KEY}"),
        epilog=(
            "exit codes: 0 done (or nothing to do), 1 missing tool / scan or encryption failed,\n"
            "            2 you said no (or no --yes while not interactive)\n"
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
    parser.add_argument("--placeholder", default="${NAME}", metavar="TEMPLATE",
                        help="text that replaces a secret in source files; NAME becomes the key "
                             "(default: ${NAME})")
    parser.add_argument("--verify", action="store_true",
                        help="let TruffleHog verify each secret against its service (needs network access)")
    parser.add_argument("--exclude", action="append", default=[], metavar="REGEX",
                        help="skip paths matching this regular expression (repeatable)")
    parser.add_argument("--no-default-excludes", action="store_true",
                        help="also scan .git, node_modules, virtualenvs and friends")
    parser.add_argument("--min-length", type=int, default=8, metavar="N",
                        help="ignore secrets shorter than N characters (default: 8)")
    parser.add_argument("--trufflehog", metavar="PATH", help="trufflehog executable (default: search PATH)")
    parser.add_argument("--dotenvx", metavar="PATH", help="dotenvx executable (default: search PATH)")
    parser.add_argument("-v", "--verbose", action="store_true", help="show the commands run and tool output")
    parser.add_argument("--no-color", action="store_true", help="plain output")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args(argv)
    if "NAME" not in args.placeholder:
        parser.error("--placeholder must contain NAME (it is replaced by the key name)")
    if args.min_length < 1:
        parser.error("--min-length must be at least 1")
    return args


def main(argv=None):
    args = parse_args(argv)
    style = Style(colour_wanted(args.no_color))
    root = os.path.abspath(fs_text(args.path))
    if not os.path.isdir(root):
        say(style.bad(u"[!!] %s is not a folder." % root), sys.stderr)
        return 1
    store = fs_text(args.env_file)
    if not os.path.isabs(store):
        store = os.path.join(root, store)
    store = os.path.normpath(store)

    say(style.bold(u"sweep-and-secure %s" % __version__) + style.dim(u"  (TruffleHog + dotenvx)"))
    say(u"Folder: %s" % root)
    tools = locate_tools(args, root, style)

    exclude_patterns = [] if args.no_default_excludes else list(DEFAULT_EXCLUDES)
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
        findings, code = run_trufflehog(tools["trufflehog"]["path"], root, exclude_patterns, args)
    except ToolError as exc:
        say(style.bad(u"[!!] %s" % to_text(str(exc))), sys.stderr)
        return 1
    if code != 0:
        say(style.warn(u"[--] trufflehog exited with status %d but produced results; continuing." % code))

    encrypted, plaintext = inventory_env_files(root, exclude_res)
    plan = build_plan(findings, root, store, args, plaintext)
    plan.encrypted = encrypted
    plan.plain_env = plaintext
    print_report(plan, args, style, any(f.verified for f in findings))

    if not plan.items:
        say(u"")
        say(u"Nothing to encrypt.")
        return 0
    if args.dry_run:
        say(u"")
        say(style.dim(u"Dry run: nothing was changed."))
        return 0

    say(u"")
    chosen = confirm(plan, args, style)
    if not chosen:
        say(u"Nothing encrypted.")
        return 2

    failed = execute(plan, chosen, tools["dotenvx"]["path"], args, style)

    env_paths = []
    for item in chosen:
        if item.status in ("done", "stored") and item.store and item.store not in env_paths:
            env_paths.append(item.store)
    keys_files = discover_keys_files(env_paths, root)
    git_root = find_git_root(root)
    if keys_files:
        say(u"")
        for keys_file in keys_files:
            say(u"  %s private key file: %s" % (style.ok("[ok]"), plan.rel(keys_file)))
            if git_root and git_tracked(git_root, keys_file):
                say(u"  %s %s is TRACKED BY GIT. Remove it from the index now:  git rm --cached %s"
                    % (style.bad("[!!]"), plan.rel(keys_file), plan.rel(keys_file)))
        if git_root:
            try:
                changed, message = ensure_gitignore(git_root)
                say(u"  %s %s" % (style.ok("[ok]") if changed else style.dim("[--]"), message))
            except (IOError, OSError) as exc:
                say(u"  %s could not update .gitignore: %s" % (style.warn("[!!]"), to_text(str(exc))))
        else:
            say(u"  %s not a git repository: keep .env.keys out of any backups or shares you make."
                % style.warn("[--]"))

    done = [item for item in chosen if item.status in ("done", "stored")]
    say(u"")
    summary = u"Done: %d secret(s) encrypted" % len(done)
    if failed:
        summary += u", %d failed" % len(failed)
    if plan.skipped:
        summary += u", %d need manual attention (see above)" % len(plan.skipped)
    say(style.bold(summary))
    if done:
        print_next_steps(plan, chosen, keys_files, args, style)
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        say(u"\nInterrupted; nothing further was changed.", sys.stderr)
        sys.exit(130)
