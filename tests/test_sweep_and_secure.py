# -*- coding: utf-8 -*-
"""Tests for sweep_and_secure.py.

The end-to-end tests run the script as a subprocess against a throw-away project
tree, with the stand-ins for trufflehog and dotenvx from tests/fakebin on the
PATH, so neither real tool is needed. Works on Python 2.7 and 3.x:

    python -m unittest discover -s tests -v

Set SWEEP_TEST_REAL_TOOLS=1 with the real trufflehog and dotenvx on your PATH to
also run the tier that exercises the real tools (RealToolsTests).
"""
from __future__ import absolute_import, print_function

import bz2
import gzip
import lzma
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import atexit
import base64
import struct
import tempfile
import unittest
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCRIPT = os.path.join(REPO, "sweep_and_secure.py")
FAKEBIN = os.path.join(HERE, "fakebin")
FAKE_DOTENVX = os.path.join(FAKEBIN, "dotenvx")

sys.path.insert(0, REPO)
import sweep_and_secure as sas  # noqa: E402

try:
    from StringIO import StringIO  # Python 2
except ImportError:
    from io import StringIO

# Realistic-looking but entirely made-up credentials. They are assembled from
# fragments at run time so that this file itself never contains a secret-shaped
# string: neither GitHub's push protection nor a TruffleHog sweep of this very
# repository should trip over the test-suite.
GITHUB_TOKEN = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dcXYZ123"
STRIPE_KEY_2 = "sk_live_" + "9zY8xW7vU6tS5rQ4pO3nM2lK1jI0hGfE"
AWS_ID = "AKIA" + "QYLPMN5HHHFPZAM2"
AWS_SECRET = "1tUm636uS1yOEcfP5pvfqJ/" + "ml36mF7AkyHsEU0IU"
SLACK = "https://hooks.slack.com/" + "services/T0A1B2C3D4/B0E5F6G7H8/aBcDeFgHiJkLmNoPqRsTuVwX"
PG_URL = "postgres://" + "admin:SuperSecretPassw0rd@db-prod.acme-corp.io:5432/app"
PEM = ("-----BEGIN " + "PRIVATE KEY-----\n"
       "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n"
       "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
       "-----END " + "PRIVATE KEY-----")
# The key appears bare in docs/deploy_key.pem (no name to derive) and as "private_key"
# in config/service_account.json; the context from any occurrence names the variable.
PEM_KEY = "PRIVATE_KEY"
PEM_FALLBACK_KEY = "PRIVATE_KEY_" + hashlib.sha256(PEM.encode("utf-8")).hexdigest()[:6].upper()
# Values the fake "Password" detector flags; they probe dotenvx's quoting rules.
PWD_APOS_DOLLAR = "PWD-" + "it's$ecret123"         # apostrophe and $: storable in backticks with \$
PWD_APOS_BACKSLASH = "PWD-" + "it's\\path12345"    # apostrophe and backslash: not storable exactly

FILES = {
    ".env": "PORT=3000\nSTRIPE_SECRET_KEY=%s\nAPP_NAME=demo\n" % STRIPE_KEY,
    ".gitignore": "node_modules/\n",
    "config/.env.production": 'DOTENV_PUBLIC_KEY="02abc"\nDB_PASSWORD="encrypted:QUJD"\nLOG_LEVEL=info\n',
    "config/app.json": '{\n  "name": "demo",\n  "slack_webhook": "%s"\n}\n' % SLACK,
    # the same PEM key as docs/deploy_key.pem, but JSON-escaped on one line
    "config/service_account.json": ('{\n  "type": "service_account",\n  "private_key": "%s"\n}\n'
                                    % PEM.replace("\n", "\\n")),
    # URLs in prose, followed by punctuation that is not part of the URL
    "docs/db.md": "Connect with %s. Read replica: [%s]\n" % (PG_URL, PG_URL),
    "src/settings.py": ('DEBUG = True\nAWS_ACCESS_KEY_ID = "%s"\nAWS_SECRET_ACCESS_KEY = "%s"\n'
                        'DATABASE_URL = "%s"\n' % (AWS_ID, AWS_SECRET, PG_URL)),
    "src/client.js": "const token = '%s';\nconst stripe = require('stripe')('%s');\n" % (GITHUB_TOKEN, STRIPE_KEY),
    "docs/notes.md": "# Notes\n\nAlerts go to %s for now.\n" % SLACK,
    "docs/deploy_key.pem": PEM + "\n",
    "node_modules/pkg/.env": "TOKEN=%s\n" % GITHUB_TOKEN,
}
ENCRYPTED_LINE = r'^%s=[\'"`]?encrypted:'   # dotenvx keeps the quote style of the line it rewrites

B64_FILL = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+/" * 2
DIGEST_SHAPES = {"sha1": (27, "="), "sha256": (43, "="), "sha384": (64, ""), "sha512": (86, "=="), "h1": (43, "=")}


def openssh_key_text(cipher, kdf):
    """A private key file in the OpenSSH format whose header names cipher and kdf (none/none without a
    passphrase, aes256-ctr/bcrypt with one); the rest of the blob is filler, which is all the script
    reads. The fake TruffleHog flags any BEGIN ... PRIVATE KEY block."""
    blob = (b"openssh-key-v1\x00" + struct.pack(">I", len(cipher)) + cipher + struct.pack(">I", len(kdf)) + kdf
            + struct.pack(">I", 0) + struct.pack(">I", 1) + b"\x00" * 64)
    body = base64.b64encode(blob).decode("ascii")
    lines = [body[i:i + 70] for i in range(0, len(body), 70)]
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n" % "\n".join(lines)


LEGACY_PEM_BARE = ("-----BEGIN RSA PRIVATE KEY-----\n" + B64_FILL[:64] + "\n" + B64_FILL[:64] + "\n" + B64_FILL[:32] + "\n"
                   "-----END RSA PRIVATE KEY-----\n")
LEGACY_PEM_PROTECTED = ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B2C3D4E5F60718293A4B5C6D7E8F9\n\n"
                        + B64_FILL[:64] + "\n" + B64_FILL[:64] + "\n-----END RSA PRIVATE KEY-----\n")
PKCS8_PROTECTED = ("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + B64_FILL[:64] + "\n" + B64_FILL[:40] + "\n"
                   "-----END ENCRYPTED PRIVATE KEY-----\n")
CERT_BLOCK = "-----BEGIN CERTIFICATE-----\n" + B64_FILL[:64] + "\n" + B64_FILL[:48] + "\n-----END CERTIFICATE-----\n"


def integrity_hash(algo, token, extra=0):
    """A package integrity hash as package-lock.json, yarn.lock and go.sum hold them, of the
    algorithm's exact base64 length (extra lengthens or shortens it) with token inside it."""
    length, padding = DIGEST_SHAPES[algo]
    body = (token + "/" + B64_FILL)[:length + extra]
    return "%s%s%s%s" % (algo, ":" if algo == "h1" else "-", body, padding)


def encrypted(key, text):
    return re.search(ENCRYPTED_LINE % re.escape(key), text, re.M) is not None


class ProjectTree(object):
    """A temporary project folder seeded with planted secrets."""

    def __init__(self, files=FILES, git=True):
        self.root = tempfile.mkdtemp(prefix="sweep-test-")
        if git:
            os.mkdir(os.path.join(self.root, ".git"))
        for rel, content in files.items():
            self.write(rel, content.encode("utf-8"))
        os.mkdir(os.path.join(self.root, "build"))
        with gzip.open(os.path.join(self.root, "build", "blob.txt.gz"), "wb") as fh:
            fh.write(("token %s inside an archive\n" % GITHUB_TOKEN).encode("utf-8"))
        with zipfile.ZipFile(os.path.join(self.root, "build", "keys.zip"), "w") as archive:
            archive.writestr("config/prod.env", "STRIPE_SECRET_KEY=%s\n" % STRIPE_KEY)
            archive.writestr("readme.txt", "nothing here\n")

    def path(self, rel):
        return os.path.join(self.root, rel.replace("/", os.sep))

    def write(self, rel, data):
        path = self.path(rel)
        folder = os.path.dirname(path)
        if not os.path.isdir(folder):
            os.makedirs(folder)
        with io.open(path, "wb") as fh:
            fh.write(data)

    def read(self, rel):
        with io.open(self.path(rel), "rb") as fh:
            return fh.read().decode("utf-8")

    def read_bytes(self, rel):
        with io.open(self.path(rel), "rb") as fh:
            return fh.read()

    def snapshot(self):
        files = {}
        for dirpath, _, filenames in os.walk(self.root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    files[os.path.relpath(path, self.root)] = os.readlink(path)
                    continue
                with io.open(path, "rb") as fh:
                    files[os.path.relpath(path, self.root)] = fh.read()
        return files

    def leftovers(self):
        found = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            found.extend(n for n in dirnames + filenames if n.startswith(sas.TEMP_PREFIX))
        return found

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


FAKE_KNOBS = ("TRUFFLEHOG_BIN", "DOTENVX_BIN", "FAKE_DOTENVX_FAIL", "FAKE_DOTENVX_NOOP", "FAKE_DOTENVX_CORRUPT",
              "FAKE_TRUFFLEHOG_FAIL", "FAKE_TRUFFLEHOG_PARTIAL", "FAKE_DOTENVX_VERSION", "FAKE_TRUFFLEHOG_VINTAGE",
              "FAKE_DOTENVX_STORE", "FAKE_OPENSSL_NO_PBKDF2", "FAKE_DOTENVX_NO_KEYS_FILE")
FAKE_OPENSSL = os.path.join(FAKEBIN, "openssl")


LOG_TMP = tempfile.mkdtemp(prefix="sweep-logs-")   # run logs of the tests, removed at exit
atexit.register(shutil.rmtree, LOG_TMP, True)


def clean_env(extra_env=None, path=None):
    env = dict(os.environ)
    env["PATH"] = (FAKEBIN + os.pathsep + env.get("PATH", "")) if path is None else path
    env["NO_COLOR"] = "1"
    env["SWEEP_AND_SECURE_LOG_DIR"] = LOG_TMP
    for name in FAKE_KNOBS:
        env.pop(name, None)
    env.pop("CI", None)   # a CI runner keeps keys in files; the tests want a developer's machine unless they say so
    if extra_env:
        env.update(extra_env)
    return env


def run_script(root, args, stdin_text="", extra_env=None, path=None):
    env = clean_env(extra_env, path)
    proc = subprocess.Popen([sys.executable, SCRIPT, root] + list(args), cwd=root, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(stdin_text.encode("utf-8"))
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def dotenvx_get(root, key, env_file=".env", keys_file=None, binary=None, extra_env=None):
    """What dotenvx (the stand-in by default) decrypts for key; --overload makes the
    file win over our own environment, as the script does when it verifies."""
    cmd = [sys.executable, FAKE_DOTENVX] if binary is None else [binary]
    cmd += ["get", key, "-f", env_file, "--overload"]
    if keys_file:
        cmd += ["-fk", keys_file]
    env = dict(os.environ)
    env.update(extra_env or {})
    proc = subprocess.Popen(cmd, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate()
    out = out.decode("utf-8")
    return out[:-1] if out.endswith("\n") else out


def read_file(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def quarantine_record(tree, rel, folder=".secrets-quarantine"):
    """The index.json record of the quarantined copy of rel that is still in the quarantine."""
    records = [r for r in json.loads(tree.read(folder + "/index.json"))
               if r["original"] == rel and not r.get("restored_at")]
    if not records:
        raise AssertionError("no quarantine record for %s" % rel)
    return records[-1]


def quarantined_bytes(tree, rel, folder=".secrets-quarantine", keys_file=None, extra_env=None):
    """The content of the quarantined copy of rel. A *.enc is decrypted the way MANIFEST.txt
    says: dotenvx (the stand-in) gives up the passphrase kept in the quarantine's .env, and
    openssl (the stand-in) decrypts the file with it."""
    record = quarantine_record(tree, rel, folder)
    stored = tree.path(folder + "/" + record["quarantined"])
    if not record.get("encrypted"):
        with io.open(stored, "rb") as fh:
            return fh.read()
    if keys_file is None and os.path.isfile(tree.path(".env.keys")):
        keys_file = ".env.keys"      # the quarantine shares the store's key pair; its own sits next to its .env
    passphrase = dotenvx_get(tree.root, record["key"], folder + "/.env", keys_file, extra_env=extra_env)
    if not re.match(r"^[0-9a-f]{64}$", passphrase):
        raise AssertionError("no passphrase for %s: dotenvx said %r" % (rel, passphrase))
    plain = stored + ".test-plain"
    cmd = [sys.executable, FAKE_OPENSSL, "enc", "-d", "-" + record["cipher"]]
    if record["kdf"] == "pbkdf2":
        cmd.append("-pbkdf2")
    cmd += ["-pass", "stdin", "-in", stored, "-out", plain]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err = proc.communicate((passphrase + "\n").encode("ascii"))
    if proc.returncode != 0:
        raise AssertionError("the stand-in openssl could not decrypt %s: %s"
                             % (record["quarantined"], err.decode("utf-8", "replace")))
    try:
        with io.open(plain, "rb") as fh:
            return fh.read()
    finally:
        os.remove(plain)


def item_number(listing, detector, key, where=None):
    """The '#' of the listed item for detector/key (optionally restricted to a location)."""
    for line in listing.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)", line)
        if match and match.group(2) == detector and match.group(3) == key:
            if where is None or where in match.group(4):
                return match.group(1)
    raise AssertionError("no listed item for %s %s in:\n%s" % (detector, key, listing))


class InProcess(object):
    """Run sas.main() in this process with the fake tools on PATH, capturing output,
    so that a test can monkeypatch a function to fail half way."""

    def __init__(self, root, args, patches=None):
        self.root, self.args, self.patches = root, list(args), patches or {}
        self.out = self.err = u""
        self.code = None
        self.exception = None

    def run(self):
        saved = {name: getattr(sas, name) for name in self.patches}
        saved_env = dict(os.environ)
        saved_streams = sys.stdout, sys.stderr
        os.environ.update(clean_env())
        out, err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        try:
            for name, value in self.patches.items():
                setattr(sas, name, value)
            try:
                self.code = sas.main([self.root] + self.args + ["--no-color"])
            except BaseException as exc:  # noqa: B902 - the test wants to see KeyboardInterrupt
                self.exception = exc
        finally:
            sys.stdout, sys.stderr = saved_streams
            for name, value in saved.items():
                setattr(sas, name, value)
            os.environ.clear()
            os.environ.update(saved_env)
        self.out, self.err = out.getvalue(), err.getvalue()
        return self


class EndToEndTests(unittest.TestCase):

    def setUp(self):
        self.tree = ProjectTree()
        self.before = self.tree.snapshot()

    def tearDown(self):
        self.tree.cleanup()

    def assertUnchanged(self, *rels):
        after = self.tree.snapshot()
        for rel in rels or self.before.keys():
            self.assertEqual(after.get(rel.replace("/", os.sep)), self.before[rel.replace("/", os.sep)], rel)

    def assertNoLeftovers(self):
        self.assertEqual(self.tree.leftovers(), [])

    def test_missing_tools_are_reported_with_links(self):
        empty = tempfile.mkdtemp(prefix="sweep-empty-")
        try:
            code, out, err = run_script(self.tree.root, ["--dry-run"], path=empty)
        finally:
            shutil.rmtree(empty, ignore_errors=True)
        self.assertEqual(code, 1)
        for needle in ("trufflehog is not installed", "dotenvx is not installed",
                       "https://trufflesecurity.com/trufflehog", "https://github.com/trufflesecurity/trufflehog",
                       "https://dotenvx.com", "Cannot continue"):
            self.assertIn(needle, err)
        self.assertUnchanged()

    def test_check_setup_reports_the_tools_and_runs_them_without_touching_the_tree(self):
        scratch_before = set(name for name in os.listdir(tempfile.gettempdir())
                             if name.startswith("sweep-and-secure-check-"))
        code, out, err = run_script(self.tree.root, ["--check-setup"])
        self.assertEqual(code, 0, out + err)
        for needle in ("Python %d.%d" % sys.version_info[:2], "[ok] trufflehog  3.99.0", "[ok] dotenvx     2.0.0",
                       "[ok] openssl     3.0.13", "(optional: encrypts quarantined files; key derivation pbkdf2)",
                       "trufflehog  ran in a scratch folder: exit status 0, 1 file(s) scanned, no findings",
                       "dotenvx     ran in a scratch folder: encrypted a value, decrypted it back; the private key went to .env.keys",
                       "Setup looks good. Nothing was changed."):
            self.assertIn(needle, out)
        # openssl is optional: without it the check still passes, and says what that means
        missing = os.path.join(self.tree.root, "no-such-openssl")
        code, out, err = run_script(self.tree.root, ["--check-setup", "--openssl", missing])
        self.assertEqual(code, 0, out + err)
        self.assertIn("[--] openssl     --openssl %s is not a file  (optional: quarantined files would be moved as they are)"
                      % missing, out)
        code, out, err = run_script(self.tree.root, ["--check-setup"], extra_env={"FAKE_OPENSSL_NO_PBKDF2": "1"})
        self.assertEqual(code, 0, out + err)
        self.assertIn("key derivation legacy", out)
        code, out, err = run_script(self.tree.root, ["--check-setup", "--openssl", sys.executable])
        self.assertEqual(code, 0, out + err)
        self.assertIn("[--] openssl     %s could not encrypt a probe file" % sys.executable, out)
        self.assertNotIn("Scanning with TruffleHog", out)   # the tree itself is never scanned
        self.assertNotIn("Plaintext secrets", out)
        self.assertUnchanged()
        self.assertNoLeftovers()
        self.assertFalse(os.path.exists(self.tree.path(".env.keys")))
        scratch_after = set(name for name in os.listdir(tempfile.gettempdir())
                            if name.startswith("sweep-and-secure-check-"))
        self.assertEqual(scratch_after - scratch_before, set())   # the scratch folder was removed

    def test_check_setup_reports_every_problem_and_exits_1(self):
        empty = tempfile.mkdtemp(prefix="sweep-empty-")
        try:
            code, out, err = run_script(self.tree.root, ["--check-setup"], path=empty)
        finally:
            shutil.rmtree(empty, ignore_errors=True)
        self.assertEqual(code, 1, out + err)
        self.assertIn("trufflehog is not installed", err)
        self.assertIn("dotenvx is not installed", err)        # both are reported, not just the first
        self.assertIn("https://dotenvx.com", err)
        self.assertIn("Setup check failed: 2 problem(s)", out)
        self.assertNotIn("Cannot continue", err)
        # a tool that is found but fails its scratch run is a problem too; the other tool is still checked
        code, out, err = run_script(self.tree.root, ["--check-setup"], extra_env={"FAKE_TRUFFLEHOG_FAIL": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("trufflehog could not scan a scratch folder", err)
        self.assertIn("dotenvx     ran in a scratch folder", out)
        self.assertIn("Setup check failed: 1 problem(s)", out)
        code, out, err = run_script(self.tree.root, ["--check-setup"], extra_env={"FAKE_DOTENVX_FAIL": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("dotenvx could not encrypt a value in a scratch folder", err)
        self.assertIn("trufflehog  ran in a scratch folder", out)
        self.assertUnchanged()
        self.assertNoLeftovers()

    def test_old_trufflehog_releases_are_used_as_they_are(self):
        # 3.20: no --log-level, no --exclude-paths, and the folder must come as --directory
        old = {"FAKE_TRUFFLEHOG_VINTAGE": "3.20"}
        code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env=old)
        self.assertEqual(code, 0, out + err)
        self.assertIn("[ok] trufflehog  3.20.0", out)
        self.assertIn("an old release, used as it is; 3.75.0 and later skip compiled files themselves", out)
        self.assertIn("Scan took ", out)
        self.assertNotIn("Scanned ", out)
        self.assertIn("no --log-level", out)
        self.assertIn("no --exclude-paths", out)
        self.assertIn("Ignored 1 finding(s) inside excluded folders", out)   # node_modules was scanned; dropped here
        self.assertNotIn("node_modules/pkg/.env", out)
        for needle in ("STRIPE_SECRET_KEY", "AWS_SECRET_ACCESS_KEY", "move to .secrets-quarantine/build/keys.zip"):
            self.assertIn(needle, out)
        # 3.40: only --log-level is missing
        code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env={"FAKE_TRUFFLEHOG_VINTAGE": "3.40"})
        self.assertEqual(code, 0, out + err)
        self.assertIn("no --log-level", out)
        self.assertNotIn("no --exclude-paths", out)
        self.assertNotIn("Ignored", out)
        self.assertIn("an old release", out)
        code, out, err = run_script(self.tree.root, ["--dry-run"])   # the stand-in is 3.99 by default: no note
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("an old release", out)
        # a real run works the same, quarantine included, and the quarantine folder stays out of later listings
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"], extra_env=old)
        self.assertEqual(code, 0, out + err)
        self.assertTrue(encrypted("STRIPE_SECRET_KEY", self.tree.read(".env")))
        self.assertTrue(os.path.isfile(self.tree.path(".secrets-quarantine/build/keys.zip.enc")))
        code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env=old)
        self.assertEqual(code, 0, out + err)
        self.assertNotIn(".secrets-quarantine/build", out)
        self.assertNoLeftovers()

    def test_oldest_trufflehog_json_is_decoded_and_aws_pairs_completed(self):
        # 3.6 to 3.12: Raw is base64 of the bytes, and an AWS key pair is reported as its id alone
        code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env={"FAKE_TRUFFLEHOG_VINTAGE": "3.12"})
        self.assertEqual(code, 0, out + err)
        for needle in ("STRIPE_SECRET_KEY", "SLACK_WEBHOOK", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
            self.assertIn(needle, out)
        self.assertIn("1 AWS key id(s) without the secret access key", out)
        self.assertNotIn("not found verbatim", out)
        code, out, err = run_script(self.tree.root, ["--yes"], extra_env={"FAKE_TRUFFLEHOG_VINTAGE": "3.12"})
        self.assertEqual(code, 0, out + err)
        self.assertNotIn(AWS_SECRET, self.tree.read("src/settings.py"))
        self.assertEqual(dotenvx_get(self.tree.root, "AWS_SECRET_ACCESS_KEY"), AWS_SECRET)

    def test_check_setup_with_an_old_trufflehog(self):
        code, out, err = run_script(self.tree.root, ["--check-setup"], extra_env={"FAKE_TRUFFLEHOG_VINTAGE": "3.20"})
        self.assertEqual(code, 0, out + err)
        self.assertIn("an older TruffleHog, used as it is", out)
        self.assertIn("no --log-level", out)
        self.assertIn("Setup looks good", out)

    def test_too_old_dotenvx_is_rejected(self):
        code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env={"FAKE_DOTENVX_VERSION": "1.0.0"})
        self.assertEqual(code, 1)
        self.assertIn("too old", err)
        self.assertIn("1.4 or newer", err)
        self.assertIn("https://dotenvx.com", err)
        code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env={"FAKE_TRUFFLEHOG_VINTAGE": "3.4"})
        self.assertEqual(code, 1)
        self.assertIn("too old", err)
        self.assertIn("3.6 or newer", err)

    def test_tool_that_cannot_report_a_version_is_refused_unless_asked(self):
        code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env={"FAKE_DOTENVX_VERSION": "nonsense"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("did not report a usable version", err)
        self.assertIn("--no-version-check", err)
        code, out, err = run_script(self.tree.root, ["--dry-run", "--no-version-check"],
                                    extra_env={"FAKE_DOTENVX_VERSION": "nonsense"})
        self.assertEqual(code, 0, out + err)
        self.assertIn("Dry run", out)

    def test_dry_run_lists_findings_with_types_and_already_encrypted_keys(self):
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        for needle in ("Stripe", "STRIPE_SECRET_KEY", "encrypt in place",
                       "AWS", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                       "Postgres", "DATABASE_URL", "SlackWebhook", "SLACK_WEBHOOK",
                       "PrivateKey", PEM_KEY, "Github", "GITHUB_TOKEN", "src/settings.py:2",
                       "config/service_account.json:3", "docs/db.md:1"):
            self.assertIn(needle, out)
        self.assertIn("Already encrypted with dotenvx", out)
        self.assertIn("DB_PASSWORD", out)
        self.assertIn("config/.env.production", out)
        # archives get their own section: which files inside hold which secrets, and the action.
        # An interactive run offers to quarantine them, and a dry run previews that.
        self.assertIn("Plaintext secrets found: 10 in 7 file(s)", out)   # archives and the key file are not counted here
        self.assertIn("Files holding secrets that cannot be fixed in place: 2", out)
        self.assertIn("Private key files: 1", out)
        self.assertRegex(out, r"\d+\s+docs[/\\]deploy_key\.pem\s+none \(PKCS#8\)\s+move to \.secrets-quarantine[/\\]docs[/\\]deploy_key\.pem\.enc")
        self.assertIn("Why / inside", out)
        self.assertIn("zip: config/prod.env", out)
        self.assertIn("config/prod.env", out)        # the member that holds the Stripe key
        self.assertIn("Stripe sk_l", out)
        self.assertIn("gzip: blob.txt", out)
        self.assertIn("blob.txt ", out)              # gzip: the original file name from the header
        self.assertIn("Github ghp_", out)
        self.assertIn("move to .secrets-quarantine/build/blob.txt.gz", out)
        self.assertIn("move to .secrets-quarantine/build/keys.zip", out)
        self.assertIn("Offered because this run asks first", out)
        # a --yes run leaves them alone unless --quarantine is given, and the preview says so
        code, out, err = run_script(self.tree.root, ["--dry-run", "--yes"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Plaintext secrets found: 10 in 7 file(s)", out)
        self.assertIn("Files holding secrets that cannot be fixed in place: 2", out)
        self.assertRegex(out, r"-\s+docs[/\\]deploy_key\.pem\s+none \(PKCS#8\)\s+stays in place \(pass --quarantine to move it\)")
        self.assertRegex(out, r"ssh-keygen -p -o -a 100 -f docs[/\\]deploy_key\.pem")
        self.assertIn("config/prod.env", out)
        self.assertIn("stays in place (pass --quarantine to move it)", out)
        self.assertNotIn("move to .secrets-quarantine", out)
        self.assertNotIn("Offered because", out)
        self.assertTrue(re.search(r"Scanned \d+ file\(s\) in \d+:\d\d; TruffleHog reported \d+ finding\(s\)", out), out)
        self.assertNotIn("node_modules/pkg/.env", out)   # excluded by default
        self.assertIn("Other plaintext keys", out)       # PORT, APP_NAME, LOG_LEVEL
        self.assertIn("PORT", out)
        self.assertIn("Dry run", out)
        for secret in (STRIPE_KEY, AWS_SECRET, AWS_ID, GITHUB_TOKEN, SLACK):
            self.assertNotIn(secret, out)                # never echo secrets
        self.assertUnchanged()

    def test_answering_no_changes_nothing(self):
        code, out, err = run_script(self.tree.root, [], stdin_text="n\n")
        self.assertEqual(code, 2, out + err)
        self.assertIn("Encrypt 10 secret(s) and move 3 file(s) to quarantine now?", out)
        self.assertIn("Nothing encrypted", out)
        self.assertUnchanged()

    def test_interactive_yes_also_quarantines_archives_without_the_flag(self):
        code, out, err = run_script(self.tree.root, [], stdin_text="y\n")
        self.assertEqual(code, 0, out + err)
        for rel in ("build/keys.zip", "build/blob.txt.gz", "docs/deploy_key.pem"):
            self.assertFalse(os.path.exists(self.tree.path(rel)), rel)
            self.assertTrue(os.path.isfile(self.tree.path(".secrets-quarantine/" + rel + ".enc")), rel)
            self.assertEqual(quarantined_bytes(self.tree, rel), self.before[rel.replace("/", os.sep)], rel)
        self.assertIn("3 file(s) moved to .secrets-quarantine (encrypted)", out)
        self.assertIn("/.secrets-quarantine/", self.tree.read(".gitignore"))
        self.assertTrue(encrypted("STRIPE_SECRET_KEY", self.tree.read(".env")))

    def test_selecting_leaves_unpicked_archives_in_place(self):
        _, listing, _ = run_script(self.tree.root, ["--dry-run"])
        number = item_number(listing, "AWS", "AWS_SECRET_ACCESS_KEY")
        code, out, err = run_script(self.tree.root, [], stdin_text="s\n%s\ny\n" % number)
        self.assertEqual(code, 0, out + err)
        self.assertTrue(os.path.isfile(self.tree.path("build/keys.zip")))
        self.assertFalse(os.path.exists(self.tree.path(".secrets-quarantine")))
        self.assertIn("${AWS_SECRET_ACCESS_KEY}", self.tree.read("src/settings.py"))

    def test_yes_encrypts_env_files_in_place_and_moves_other_secrets(self):
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        env = self.tree.read(".env")
        self.assertNotIn(STRIPE_KEY, env)
        self.assertIn("PORT=3000", env)                  # unflagged key left alone
        self.assertIn("DOTENV_PUBLIC_KEY=", env)
        for key in ("STRIPE_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                    "DATABASE_URL", "SLACK_WEBHOOK", "GITHUB_TOKEN", PEM_KEY):
            self.assertTrue(encrypted(key, env), key + "\n" + env)
        settings = self.tree.read("src/settings.py")
        self.assertIn('AWS_ACCESS_KEY_ID = "${AWS_ACCESS_KEY_ID}"', settings)
        self.assertIn('AWS_SECRET_ACCESS_KEY = "${AWS_SECRET_ACCESS_KEY}"', settings)
        self.assertIn('DATABASE_URL = "${DATABASE_URL}"', settings)
        self.assertNotIn(AWS_SECRET, settings)
        client = self.tree.read("src/client.js")
        self.assertIn("'${GITHUB_TOKEN}'", client)
        self.assertIn("('${STRIPE_SECRET_KEY}')", client)
        self.assertIn("${SLACK_WEBHOOK}", self.tree.read("docs/notes.md"))
        self.assertIn('"${SLACK_WEBHOOK}"', self.tree.read("config/app.json"))
        self.assertEqual(self.tree.read("docs/deploy_key.pem"), PEM + "\n")   # a key file: never rewritten, --yes alone leaves it
        # the escaped copy of the key is replaced too, and the punctuation around URLs survives
        self.assertIn('"private_key": "${%s}"' % PEM_KEY, self.tree.read("config/service_account.json"))
        self.assertEqual(self.tree.read("docs/db.md"), "Connect with ${DATABASE_URL}. Read replica: [${DATABASE_URL}]\n")
        # decrypt round trip through the stand-in, including the multi-line and extended values
        self.assertEqual(dotenvx_get(self.tree.root, "AWS_SECRET_ACCESS_KEY"), AWS_SECRET)
        self.assertEqual(dotenvx_get(self.tree.root, "DATABASE_URL"), PG_URL)
        self.assertEqual(dotenvx_get(self.tree.root, PEM_KEY), PEM)   # real newlines, not "\n" text
        self.assertEqual(dotenvx_get(self.tree.root, "STRIPE_SECRET_KEY"), STRIPE_KEY)
        self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
        self.assertIn(".env.keys*", self.tree.read(".gitignore"))
        self.assertUnchanged("node_modules/pkg/.env", "build/blob.txt.gz", "build/keys.zip", "config/.env.production")
        self.assertIn("Done: 7 secret(s) stored encrypted; 10 plaintext occurrence(s) removed from 6 file(s);"
                      " 3 file(s) need manual attention", out)
        self.assertIn("Next steps", out)
        self.assertIn("dotenvx run -- <your command>", out)
        self.assertNotIn(" -fk ", out)                   # .env and .env.keys share a folder
        self.assertEqual(out.count("private key file:"), 1)   # one keys file, however its path is spelled
        self.assertIn("howtorotate.com/docs/tutorials/stripe/", out)
        self.assertNoLeftovers()

    def test_select_a_single_item(self):
        _, listing, _ = run_script(self.tree.root, ["--dry-run"])
        number = item_number(listing, "AWS", "AWS_SECRET_ACCESS_KEY")
        code, out, err = run_script(self.tree.root, [], stdin_text="s\n%s\ny\n" % number)
        self.assertEqual(code, 0, out + err)
        settings = self.tree.read("src/settings.py")
        self.assertIn("${AWS_SECRET_ACCESS_KEY}", settings)
        self.assertIn(AWS_ID, settings)                  # not selected: left in place
        env = self.tree.read(".env")
        self.assertTrue(encrypted("AWS_SECRET_ACCESS_KEY", env), env)
        self.assertNotIn("AWS_ACCESS_KEY_ID", env)
        self.assertIn("STRIPE_SECRET_KEY=%s" % STRIPE_KEY, env)   # in-place item not selected
        self.assertUnchanged("src/client.js", "docs/notes.md", "config/app.json")

    def test_selecting_only_a_reused_secret_still_stores_its_value(self):
        # The webhook sits in config/app.json (listed as "move to .env") and docs/notes.md
        # (listed as reusing that value). Selecting only the notes.md item must still store it.
        _, listing, _ = run_script(self.tree.root, ["--dry-run"])
        number = item_number(listing, "SlackWebhook", "SLACK_WEBHOOK", where="docs/notes.md")
        code, out, err = run_script(self.tree.root, [], stdin_text="s\n%s\n\n" % number)  # empty = default yes
        self.assertEqual(code, 0, out + err)
        self.assertEqual(dotenvx_get(self.tree.root, "SLACK_WEBHOOK"), SLACK)
        self.assertIn("${SLACK_WEBHOOK}", self.tree.read("docs/notes.md"))
        self.assertUnchanged("config/app.json", "src/settings.py")

    def test_selecting_only_a_source_copy_also_encrypts_the_plaintext_env_key(self):
        # The Stripe key sits in .env (plaintext) and in src/client.js. Choosing only the
        # client.js item must still encrypt the .env entry its placeholder points at.
        _, listing, _ = run_script(self.tree.root, ["--dry-run"])
        number = item_number(listing, "Stripe", "STRIPE_SECRET_KEY", where="src/client.js")
        code, out, err = run_script(self.tree.root, [], stdin_text="s\n%s\ny\n" % number)
        self.assertEqual(code, 0, out + err)
        self.assertIn("('${STRIPE_SECRET_KEY}')", self.tree.read("src/client.js"))
        env = self.tree.read(".env")
        self.assertNotIn(STRIPE_KEY, env)
        self.assertTrue(encrypted("STRIPE_SECRET_KEY", env), env)
        self.assertEqual(dotenvx_get(self.tree.root, "STRIPE_SECRET_KEY"), STRIPE_KEY)
        self.assertUnchanged("src/settings.py", "config/app.json")

    def test_partial_trufflehog_failure_is_handled_but_fails_the_run(self):
        code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env={"FAKE_TRUFFLEHOG_PARTIAL": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("INCOMPLETE", out)
        self.assertIn("Plaintext secrets found", out)
        self.assertUnchanged()
        code, out, err = run_script(self.tree.root, ["--yes"], extra_env={"FAKE_TRUFFLEHOG_PARTIAL": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("scan was incomplete", out)
        self.assertTrue(encrypted("STRIPE_SECRET_KEY", self.tree.read(".env")))  # what was found is fixed

    def test_bad_selection_input_is_rejected(self):
        code, out, err = run_script(self.tree.root, [], stdin_text="maybe\ns\n0 99\n\nn\n")
        self.assertEqual(code, 2, out + err)
        self.assertIn("Please answer y (yes), n (no) or s (select)", out)
        self.assertIn("Could not understand", out)
        self.assertUnchanged()

    def test_dotenvx_failure_leaves_every_file_alone(self):
        code, out, err = run_script(self.tree.root, ["--yes"], extra_env={"FAKE_DOTENVX_FAIL": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("simulated failure", out)
        self.assertIn("could not be stored encrypted", out)
        self.assertUnchanged(".env", "src/settings.py", "src/client.js", "docs/notes.md",
                             "config/app.json", "docs/deploy_key.pem")
        self.assertNoLeftovers()                         # the staging folder is gone
        self.assertIn(".env.keys*", self.tree.read(".gitignore"))   # protected before anything ran

    def test_dotenvx_that_changes_nothing_is_caught(self):
        code, out, err = run_script(self.tree.root, ["--yes"], extra_env={"FAKE_DOTENVX_NOOP": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("still plaintext", out)
        self.assertUnchanged(".env", "src/settings.py")
        self.assertNoLeftovers()

    def test_a_value_dotenvx_stored_wrongly_is_caught_before_any_rewrite(self):
        # FAKE_DOTENVX_CORRUPT makes the stand-in store a mangled value, as the real dotenvx
        # does for some quoting; decrypting and comparing must catch it and nothing may change.
        code, out, err = run_script(self.tree.root, ["--yes"], extra_env={"FAKE_DOTENVX_CORRUPT": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("verification failed", out)
        self.assertIn("decrypts to something other than the value we stored", out)
        self.assertUnchanged(".env", "src/settings.py", "src/client.js", "docs/notes.md", "config/app.json")
        self.assertNoLeftovers()

    def test_trufflehog_failure_is_reported(self):
        code, out, err = run_script(self.tree.root, ["--yes"], extra_env={"FAKE_TRUFFLEHOG_FAIL": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("trufflehog exited with status 1", err)
        self.assertIn("simulated failure", err)
        self.assertUnchanged()

    def test_env_all_also_encrypts_unflagged_env_keys(self):
        code, out, err = run_script(self.tree.root, ["--yes", "--env-all"])
        self.assertEqual(code, 0, out + err)
        env = self.tree.read(".env")
        self.assertTrue(encrypted("PORT", env), env)
        self.assertTrue(encrypted("APP_NAME", env), env)
        production = self.tree.read("config/.env.production")
        self.assertTrue(encrypted("LOG_LEVEL", production), production)
        self.assertIn('DB_PASSWORD="encrypted:QUJD"', production)   # already encrypted: untouched
        self.assertEqual(dotenvx_get(self.tree.root, "PORT"), "3000")
        # that file carries someone else's public key: dotenvx can encrypt with it, we cannot check
        self.assertIn("could not verify LOG_LEVEL: no private key", out)

    def test_placeholder_template_and_no_rewrite(self):
        code, out, err = run_script(self.tree.root, ["--yes", "--placeholder", "process.env.NAME"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("('process.env.STRIPE_SECRET_KEY')", self.tree.read("src/client.js"))

        fresh = ProjectTree()
        try:
            code, out, err = run_script(fresh.root, ["--yes", "--no-rewrite"])
            self.assertEqual(code, 0, out + err)
            self.assertEqual(fresh.read("src/settings.py"), FILES["src/settings.py"])
            self.assertTrue(encrypted("AWS_SECRET_ACCESS_KEY", fresh.read(".env")))
            self.assertIn("--no-rewrite left the plaintext", out)
        finally:
            fresh.cleanup()

    def test_rerun_after_no_rewrite_reuses_the_stored_keys(self):
        code, out, err = run_script(self.tree.root, ["--yes", "--no-rewrite"])
        self.assertEqual(code, 0, out + err)
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        env = self.tree.read(".env")
        self.assertNotIn("_2=", env)                     # no AWS_ACCESS_KEY_ID_2 and friends
        self.assertEqual(len(re.findall(r"^AWS_ACCESS_KEY_ID=", env, re.M)), 1)
        self.assertIn("(value already in .env)", out)
        self.assertIn('AWS_ACCESS_KEY_ID = "${AWS_ACCESS_KEY_ID}"', self.tree.read("src/settings.py"))
        self.assertEqual(dotenvx_get(self.tree.root, "AWS_ACCESS_KEY_ID"), AWS_ID)

    def test_a_name_taken_by_a_different_value_gets_a_suffix_and_says_why(self):
        self.tree.write(".env", ("PORT=3000\nSTRIPE_SECRET_KEY=%s\nAWS_ACCESS_KEY_ID=something-else\n"
                                 % STRIPE_KEY).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("AWS_ACCESS_KEY_ID_2", out)
        self.assertIn("AWS_ACCESS_KEY_ID already holds a different value", out)

    def test_custom_env_file_receives_moved_secrets(self):
        code, out, err = run_script(self.tree.root, ["--yes", "--env-file", "config/secrets.env"])
        self.assertEqual(code, 0, out + err)
        secrets = self.tree.read("config/secrets.env")
        self.assertTrue(encrypted("AWS_ACCESS_KEY_ID", secrets), secrets)
        self.assertIn("Created by sweep_and_secure.py", secrets)
        env = self.tree.read(".env")
        self.assertTrue(encrypted("STRIPE_SECRET_KEY", env), env)   # in place, as before
        self.assertNotIn("AWS_ACCESS_KEY_ID", env)
        # the private key of an env file is written next to it, where dotenvx looks on its own
        self.assertIn("dotenvx run -f config/secrets.env -- <your command>", out)
        self.assertNotIn(" -fk ", out)
        self.assertTrue(os.path.isfile(self.tree.path("config/.env.keys")))
        self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
        self.assertIn("# -fk .env.keys", self.tree.read("config/secrets.env"))   # the hint names the adopted file
        self.assertNotIn(sas.TEMP_PREFIX, self.tree.read("config/secrets.env"))   # not the staging folder
        self.assertEqual(dotenvx_get(self.tree.root, "AWS_ACCESS_KEY_ID", "config/secrets.env"), AWS_ID)
        self.assertIn("private key file: config/.env.keys  (file custody: dotenvx 2.0.0 keeps keys in files", out)

    def test_same_secret_under_two_env_keys_encrypts_both(self):
        self.tree.write(".env", ("PORT=3000\nDB_PASSWORD=%s\nPOSTGRES_PASSWORD=%s\nALSO=\"x-%s-y\"\n"
                                 % (STRIPE_KEY_2, STRIPE_KEY_2, STRIPE_KEY_2)).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        env = self.tree.read(".env")
        self.assertNotIn(STRIPE_KEY_2, env)
        for key in ("DB_PASSWORD", "POSTGRES_PASSWORD", "ALSO"):
            self.assertTrue(encrypted(key, env), key + "\n" + env)
        self.assertEqual(dotenvx_get(self.tree.root, "POSTGRES_PASSWORD"), STRIPE_KEY_2)
        self.assertEqual(dotenvx_get(self.tree.root, "ALSO"), "x-%s-y" % STRIPE_KEY_2)
        self.assertIn("encrypt in place", out)

    def test_a_value_dotenvx_cannot_store_exactly_is_left_for_manual_attention(self):
        self.tree.write("docs/pw.md", ("login: %s\nadmin: %s\n" % (PWD_APOS_DOLLAR, PWD_APOS_BACKSLASH)).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("value cannot be stored exactly by dotenvx (it contains both an apostrophe and a backslash)", out)
        self.assertIn("stays in place: its other secrets are fixed above; handle this one by hand", out)
        self.assertNotIn("move to .secrets-quarantine/docs/pw.md", out)
        pw = self.tree.read("docs/pw.md")
        self.assertIn(PWD_APOS_BACKSLASH, pw)            # left alone
        self.assertNotIn(PWD_APOS_DOLLAR, pw)            # moved
        self.assertIn("${LOGIN}", pw)                   # named after its context, "login:"
        self.assertEqual(dotenvx_get(self.tree.root, "LOGIN"), PWD_APOS_DOLLAR)

    def test_bom_env_file_is_encrypted_in_place_and_loses_its_bom(self):
        self.tree.write(".env", b"\xef\xbb\xbfSTRIPE_SECRET_KEY=" + STRIPE_KEY.encode("utf-8") + b"\nPORT=3000\n")
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        self.assertTrue(re.search(r"STRIPE_SECRET_KEY\s+\S+\s+\.env:1\s+encrypt in place", out), out)
        raw = self.tree.read_bytes(".env")
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(STRIPE_KEY, raw.decode("utf-8"))
        self.assertEqual(len(re.findall(r"^STRIPE_SECRET_KEY=", raw.decode("utf-8"), re.M)), 1)
        self.assertIn("removed the UTF-8 byte order mark", out)
        self.assertEqual(dotenvx_get(self.tree.root, "STRIPE_SECRET_KEY"), STRIPE_KEY)

    @unittest.skipUnless(hasattr(os, "symlink") and os.name != "nt", "symlinks")
    def test_symlinked_env_store_is_written_through_not_replaced(self):
        self.tree.write("shared/real.env", b"PORT=1\n")
        os.remove(self.tree.path(".env"))
        os.symlink(os.path.join("shared", "real.env"), self.tree.path(".env"))
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        self.assertTrue(os.path.islink(self.tree.path(".env")))
        self.assertTrue(encrypted("AWS_ACCESS_KEY_ID", self.tree.read("shared/real.env")))

    def test_reserved_env_file_names_are_refused(self):
        for name in (".sweep-and-secure-secrets.env", "config/.env.keys", ".env.vault"):
            code, out, err = run_script(self.tree.root, ["--yes", "--env-file", name])
            self.assertEqual(code, 1, name + "\n" + out + err)
            self.assertIn("that name is reserved", err)
        self.assertUnchanged()

    def test_a_folder_merely_named_like_the_key_file_is_still_scanned(self):
        self.tree.write("backup/.env.keys-project/src/a.py", ("t = '%s'\n" % GITHUB_TOKEN).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("backup/.env.keys-project/src/a.py", out)

    def test_no_default_excludes_still_protects_the_private_key_file(self):
        self.tree.write(".env.keys", ("DOTENV_PRIVATE_KEY=%s\n" % GITHUB_TOKEN).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run", "--no-default-excludes"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("node_modules/pkg/.env", out)     # the vendor folder is scanned now
        self.assertNotIn(".env.keys", out.split("Plaintext secrets found")[1])   # the key file never is

    def test_example_env_files_are_offered_for_quarantine_not_encrypted(self):
        self.tree.write(".env.example", ("STRIPE_SECRET_KEY=%s\nPORT=1\n" % STRIPE_KEY).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run", "--env-all"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("example env file", out)
        self.assertIn("move to .secrets-quarantine/.env.example", out)
        self.assertNotIn(".env.example:1", out)          # not an encrypt-in-place item
        self.assertNotIn(".env.example: PORT", out)      # not in the --env-all inventory either

    def test_every_file_that_cannot_be_fixed_in_place_is_offered_for_quarantine(self):
        self.tree.write("package-lock.json", ('{"resolved": "https://npm.pkg.github.com/x?token=%s"}\n'
                                              % GITHUB_TOKEN).encode("utf-8"))
        self.tree.write("docs/report.pdf", ("%%PDF-1.4 token %s\n" % GITHUB_TOKEN).encode("utf-8"))
        self.tree.write("vendor/thing.bin", b"\x00\x01binary " + SLACK.encode("utf-8") + b"\x00\xff")
        self.tree.write(".secrets-quarantine/build/keys.zip.enc", b"earlier copy")   # a name that is taken
        self.before = self.tree.snapshot()
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Files holding secrets that cannot be fixed in place: 5", out)
        for rel, why in (("package-lock.json", "generated lock file"), ("docs/report.pdf", "PDF"),
                         ("vendor/thing.bin", "binary file"), ("build/keys.zip", "zip: config/prod.env"),
                         ("build/blob.txt.gz", "gzip: blob.txt")):
            self.assertIn("move to .secrets-quarantine/" + rel, out)
            self.assertIn(why, out)
        # --yes alone leaves them; --yes --quarantine moves them, a taken name gets a suffix
        code, out, err = run_script(self.tree.root, ["--dry-run", "--yes"])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(out.count("stays in place (pass --quarantine to move it)"), 6)   # and the key file
        self.assertNotIn("move to .secrets-quarantine", out)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("6 file(s) moved to .secrets-quarantine", out)
        self.assertIn("build/keys.zip: moved to .secrets-quarantine/build/keys.zip.1.enc (encrypted)", out)
        for rel in ("package-lock.json", "docs/report.pdf", "vendor/thing.bin", "build/blob.txt.gz", "build/keys.zip"):
            self.assertFalse(os.path.exists(self.tree.path(rel)), rel)
            self.assertEqual(quarantined_bytes(self.tree, rel), self.before[rel.replace("/", os.sep)], rel)
        self.assertEqual(self.tree.read_bytes(".secrets-quarantine/build/keys.zip.enc"), b"earlier copy")
        manifest = self.tree.read(".secrets-quarantine/MANIFEST.txt")
        self.assertIn("build/keys.zip.1.enc  <- build/keys.zip  (Stripe)  why: zip archive  inside: config/prod.env"
                      "  enc: QUARANTINE_KEY_", manifest)
        self.assertIn("package-lock.json.enc  <- package-lock.json  (Github)  why: generated lock file  enc: QUARANTINE_KEY_",
                      manifest)
        self.assertIn("docs/report.pdf.enc  <- docs/report.pdf  (Github)  why: PDF  enc: QUARANTINE_KEY_", manifest)
        index = json.loads(self.tree.read(".secrets-quarantine/index.json"))
        by_original = dict((r["original"], r) for r in index)
        self.assertEqual(by_original["build/keys.zip"]["quarantined"], "build/keys.zip.1.enc")
        self.assertEqual(by_original["vendor/thing.bin"]["why"], "binary file")
        self.assertEqual(by_original["vendor/thing.bin"]["detectors"], ["SlackWebhook"])
        self.assertTrue(by_original["docs/report.pdf"]["original_absolute"].endswith("docs/report.pdf"))
        self.assertEqual(sorted(r["key"] for r in index), ["QUARANTINE_KEY_%d" % n for n in range(1, 7)])   # and the key file's
        # afterwards nothing is left to offer, and the quarantine folder itself is never listed
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("cannot be fixed in place", out)
        self.assertNotIn(".secrets-quarantine/", out)
        self.assertNoLeftovers()

    def test_quarantine_never_overwrites_its_own_manifest_or_index(self):
        # files in the swept folder named like the quarantine's own records get a suffix
        for name in ("index.json", "MANIFEST.txt"):
            self.tree.write(name, b"\x00binary " + SLACK.encode("utf-8") + b"\x00")
        self.before = self.tree.snapshot()
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("move to .secrets-quarantine/index.json.1", out)
        self.assertIn("move to .secrets-quarantine/MANIFEST.txt.1", out)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("index.json: moved to .secrets-quarantine/index.json.1.enc (encrypted)", out)
        self.assertIn("MANIFEST.txt: moved to .secrets-quarantine/MANIFEST.txt.1.enc (encrypted)", out)
        self.assertEqual(quarantined_bytes(self.tree, "index.json"), self.before["index.json"])
        self.assertEqual(quarantined_bytes(self.tree, "MANIFEST.txt"), self.before["MANIFEST.txt"])
        index = json.loads(self.tree.read(".secrets-quarantine/index.json"))
        by_original = dict((r["original"], r) for r in index)
        self.assertEqual(by_original["index.json"]["quarantined"], "index.json.1.enc")
        self.assertEqual(by_original["MANIFEST.txt"]["quarantined"], "MANIFEST.txt.1.enc")
        manifest = self.tree.read(".secrets-quarantine/MANIFEST.txt")
        self.assertIn("index.json.1.enc  <- index.json  (SlackWebhook)  why: binary file  enc: QUARANTINE_KEY_", manifest)
        self.assertIn("MANIFEST.txt.1.enc  <- MANIFEST.txt  (SlackWebhook)  why: binary file  enc: QUARANTINE_KEY_", manifest)
        self.assertEqual(len(index), 5)   # both, the two archives of the tree and its key file
        self.assertNoLeftovers()

    def test_an_unstorable_value_in_several_files_leaves_every_copy_for_quarantine(self):
        for rel in ("docs/a.md", "docs/b.md"):
            self.tree.write(rel, ("admin: %s\n" % PWD_APOS_BACKSLASH).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(out.count("value cannot be stored exactly by dotenvx"), 2)
        self.assertNotIn("replace with ${ADMIN}", out)   # the second copy must not point at a key never written
        self.assertIn("move to .secrets-quarantine/docs/a.md", out)
        self.assertIn("move to .secrets-quarantine/docs/b.md", out)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("[!!]", out)
        for rel in ("docs/a.md", "docs/b.md"):
            self.assertFalse(os.path.exists(self.tree.path(rel)), rel)
            self.assertNotIn(PWD_APOS_BACKSLASH.encode("utf-8"), self.tree.read_bytes(".secrets-quarantine/" + rel + ".enc"))
            self.assertIn(PWD_APOS_BACKSLASH, quarantined_bytes(self.tree, rel).decode("utf-8"))
        self.assertNoLeftovers()

    def test_the_env_file_receiving_secrets_is_never_quarantined(self):
        # .env holds only a secret that cannot be fixed (too short), yet it is where the secrets
        # moved out of src/app.py go: moving it would leave their placeholders pointing at nothing
        tree = ProjectTree({".env": "PORT=3000\nSHORT=PWD-abcdefgh\n",
                            "src/app.py": 'STRIPE = "%s"\n' % STRIPE_KEY})
        try:
            code, out, err = run_script(tree.root, ["--dry-run", "--yes", "--quarantine", "--min-length", "16"])
            self.assertEqual(code, 0, out + err)
            self.assertIn("secret shorter than 16 characters (--min-length)", out)
            self.assertIn("stays in place: secrets from other files are stored in it; handle this one by hand", out)
            self.assertNotIn("move to .secrets-quarantine/.env", out)
            code, out, err = run_script(tree.root, ["--yes", "--quarantine", "--min-length", "16"])
            self.assertEqual(code, 0, out + err)
            self.assertTrue(os.path.isfile(tree.path(".env")))
            env = tree.read(".env")
            self.assertIn("SHORT=PWD-abcdefgh", env)                    # left for the hand
            self.assertTrue(encrypted("STRIPE", env), env)              # the moved secret landed here
            self.assertIn("${STRIPE}", tree.read("src/app.py"))
            self.assertIn("1 file(s) need manual attention", out)
            index = json.loads(tree.read(".secrets-quarantine/index.json"))      # the archives went, .env did not
            self.assertEqual(sorted(r["original"] for r in index), ["build/blob.txt.gz", "build/keys.zip"])
        finally:
            tree.cleanup()

    def test_compiled_code_is_skipped_by_default_and_only_listed_with_scan_compiled(self):
        tree = ProjectTree({"app/settings.py": 'STRIPE = "%s"\n' % STRIPE_KEY})
        try:
            planted = ("\0AWS_ACCESS_KEY_ID=%s\0AWS_SECRET_ACCESS_KEY=%s\0%s\0" % (AWS_ID, AWS_SECRET, SLACK)).encode("utf-8")
            elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x03\x00\x3e\x00" + planted + b"\x00" * 64
            tree.write("lib/libplanted.so.1", elf)       # compiled by name
            tree.write("bin/tool", elf)                    # compiled by its first bytes only
            tree.write("app/mod.cpython-311.pyc", b"\xa7\r\r\n" + b"\x00" * 12 + ("token %s\0" % GITHUB_TOKEN).encode("utf-8"))
            tree.write("vendor/blob.bin", b"\x00\x01data " + SLACK.encode("utf-8") + b"\x00")   # a data file, not a program
            code, out, err = run_script(tree.root, ["--dry-run"])
            self.assertEqual(code, 0, out + err)
            self.assertIn("Skipped 3 compiled file(s) (.pyc 1, .so 1, ELF binary 1): a secret compiled into a program", out)
            self.assertNotIn("move to .secrets-quarantine/lib", out)
            self.assertNotIn("move to .secrets-quarantine/bin", out)
            self.assertNotIn("move to .secrets-quarantine/app", out)
            self.assertIn("move to .secrets-quarantine/vendor/blob.bin", out)    # data binaries keep the offer
            self.assertIn("Files holding secrets that cannot be fixed in place: 3", out)   # the tree's two archives, and it
            # --scan-compiled lists them read-only, with the surrounding string and every secret masked
            code, out, err = run_script(tree.root, ["--dry-run", "--scan-compiled"])
            self.assertEqual(code, 0, out + err)
            self.assertIn("Findings in compiled code: 5 in 3 file(s)  (listed only: never rewritten or moved)", out)
            self.assertRegex(out, r"lib/libplanted\.so\.1\s+\.so file\s+AWS\s+AKIA\.\.\.M2\s+AWS_ACCESS_KEY_ID=AKIA\.\.\.M2")
            self.assertRegex(out, r"bin/tool\s+ELF binary\s+SlackWebhook\s+http\.\.\.wX\s+http\.\.\.wX")
            self.assertRegex(out, r"app/mod\.cpython-311\.pyc\s+\.pyc file\s+Github\s+ghp_\.\.\.ij\s+token ghp_\.\.\.ij")
            self.assertIn("this TruffleHog (3.99.0) skips compiled files itself", out)   # the stand-in says it is 3.99
            self.assertNotIn("Skipped", out)
            for secret in (AWS_ID, AWS_SECRET, SLACK, GITHUB_TOKEN):
                self.assertNotIn(secret, out)
            log = read_file(re.search(r"^Log: (.*)$", out, re.M).group(1).strip())
            self.assertIn("(shown on the screen only)", log)      # the surroundings stay off the log
            self.assertNotIn("AWS_ACCESS_KEY_ID=", log)
            self.assertNotIn(AWS_ID, log)
            # nothing in compiled code is ever rewritten or moved, whatever the flags
            before = tree.snapshot()
            code, out, err = run_script(tree.root, ["--yes", "--quarantine", "--scan-compiled"])
            self.assertEqual(code, 0, out + err)
            for rel in ("lib/libplanted.so.1", "bin/tool", "app/mod.cpython-311.pyc"):
                self.assertEqual(tree.read_bytes(rel), before[rel.replace("/", os.sep)], rel)
            self.assertFalse(os.path.exists(tree.path("vendor/blob.bin")))   # the data file was moved
            self.assertIn("were listed and left alone", out)
            # an old TruffleHog that takes no exclusions reads them anyway: still set aside, same count
            code, out, err = run_script(tree.root, ["--dry-run"], extra_env={"FAKE_TRUFFLEHOG_VINTAGE": "3.12"})
            self.assertEqual(code, 0, out + err)
            self.assertIn("Skipped 3 compiled file(s) (.pyc 1, .so 1, ELF binary 1)", out)
            self.assertNotIn("libplanted", out)
            code, out, err = run_script(tree.root, ["--dry-run", "--scan-compiled"], extra_env={"FAKE_TRUFFLEHOG_VINTAGE": "3.12"})
            self.assertEqual(code, 0, out + err)
            self.assertIn("Findings in compiled code: 5 in 3 file(s)", out)
            self.assertNotIn("skips compiled files itself", out)   # 3.12 still reads them: no such note
        finally:
            tree.cleanup()

    def test_checksums_and_commit_ids_in_lock_files_are_not_secrets(self):
        # TruffleHog's keyword detectors take the long hex strings next to a package called cloudflare or
        # sentry for tokens: the sha1 URL fragment in yarn.lock, a commit id in package-lock.json, the
        # checksum in mix.lock. Those are public identifiers; a credential in a lock file sits in a URL.
        sha1 = "2e85b818" + "17ebec4241b8f55ef1b62e4f150abcee"
        sha256 = "7452a46f185b7cc1e0a33b7b5bc3ecb9" + "4dc85968268cf63e08314caae3c96e2f"
        self.tree.write("yarn.lock", ('# yarn lockfile v1\n\n\ncloudflare@^1.0.0:\n  version "1.0.0"\n'
                                      '  resolved "https://registry.yarnpkg.com/cloudflare/-/cloudflare-1.0.0.tgz#%s"\n'
                                      '  integrity %s\n' % (sha1, integrity_hash("sha512", "cf"))).encode("utf-8"))
        self.tree.write("mix.lock", ('%%{\n  "sentry": {:hex, :sentry, "10.0.0", "%s", [:mix], [], "hexpm", "%s"},\n}\n'
                                     % (sha256, sha256[::-1])).encode("utf-8"))
        self.tree.write("package-lock.json", json.dumps({"name": "demo", "lockfileVersion": 3, "packages": {
            "node_modules/cf-worker": {"version": "1.0.0",
                                       "resolved": "git+ssh://git@github.com/cloudflare/cf-worker.git#%s" % sha1}}},
            indent=2).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Set aside 3 finding(s) that are package integrity hashes (sha512-..., h1:..., sha256:...) or"
                      " commit ids, checksums and package names that a lock file or manifest vouches for", out)
        for rel in ("yarn.lock", "mix.lock", "package-lock.json"):
            self.assertNotIn(rel, out)
        log = read_file(re.search(r"^Log: (.*)$", out, re.M).group(1).strip())
        self.assertIn("set aside, a checksum, commit id or package name in a lock file: yarn.lock line 6 (CloudflareApiToken)", log)
        self.assertIn("set aside, a checksum, commit id or package name in a lock file: mix.lock line 2 (SentryToken)", log)
        self.assertNotIn(sha1, log)
        # a credential in a lock file is still one (user:secret@host, ?token=...), and the row says where
        self.tree.write("sub/yarn.lock", ('# yarn lockfile v1\n\ncloudflare-sdk@^2.0.0:\n  version "2.0.0"\n'
                                          '  resolved "https://cloudflare:%s@npm.example.com/cloudflare-sdk-2.0.0.tgz"\n'
                                          % sha1).encode("utf-8"))
        self.tree.write("sub/pnpm-lock.yaml", ("lockfileVersion: '9.0'\n\npackages:\n\n  cloudflare@1.0.0:\n"
                                               "    resolution: {tarball: https://npm.example.com/cloudflare-1.0.0.tgz?token=%s}\n"
                                               % sha1).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Set aside 3 finding(s)", out)
        self.assertRegex(out, r"sub/yarn\.lock\s+generated lock file\s+CloudflareApiToken 2e85\.\.\.ee \(line 5, 40 chars, in \"resolved\"\)")
        self.assertRegex(out, r"sub/pnpm-lock\.yaml\s+generated lock file\s+CloudflareApiToken 2e85\.\.\.ee \(line 6, 40 chars, in \"tarball\"\)")
        # --yes --quarantine moves those two; the lock files whose matches were set aside stay
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        for rel in ("yarn.lock", "mix.lock", "package-lock.json"):
            self.assertTrue(os.path.isfile(self.tree.path(rel)), rel)
        for rel in ("sub/yarn.lock", "sub/pnpm-lock.yaml"):
            self.assertFalse(os.path.exists(self.tree.path(rel)), rel)
            self.assertTrue(os.path.isfile(self.tree.path(".secrets-quarantine/" + rel + ".enc")), rel)
        self.assertNoLeftovers()

    def test_commit_ids_in_manifests_are_not_secrets(self):
        # measured: every TruffleHog from 3.6 to 3.99 reports the commit id of a dependency pinned to one as a
        # token of the vendor named just before it ("cloudflare": "github:cloudflare/node-cloudflare#<id>" in
        # package.json), and the same for a gitHead field, an action pin, a rev or ref field, a commit link.
        # Those are public identifiers the file vouches for; a token next to the same word is still a token.
        shas = [hashlib.sha1(("pin %d" % i).encode("utf-8")).hexdigest() for i in range(9)]
        token = "cfT0ken_" + "Qm7xPz2vLw9nRt4yUe6iOa1sZb8kHn3cVf5mJq2w"[:32]
        self.tree.write("package.json", json.dumps({
            "name": "@cloudflare/demo", "gitHead": shas[0], "version": "1.0.0",
            "dependencies": {"cloudflare": "github:cloudflare/node-cloudflare#%s" % shas[1],
                             "wrangler": "git+https://github.com/cloudflare/workers-sdk.git#%s" % shas[2]},
            "config": {"cloudflare_token": token}}, indent=2).encode("utf-8"))
        self.tree.write(".github/workflows/deploy.yml", ("name: deploy\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
                                                        "    steps:\n      - uses: actions/checkout@v4\n"
                                                        "      - uses: cloudflare/wrangler-action@%s # v3\n"
                                                        "        with:\n          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}\n"
                                                        % shas[3]).encode("utf-8"))
        self.tree.write(".pre-commit-config.yaml", ("repos:\n  - repo: https://github.com/cloudflare/pre-commit-hooks\n    rev: %s\n"
                                                   "    hooks: [{ id: trailing-whitespace }]\n" % shas[4]).encode("utf-8"))
        self.tree.write("requirements.txt", ("requests==2.31.0\ngit+https://github.com/cloudflare/python-cloudflare.git@%s#egg=cloudflare\n"
                                             % shas[5]).encode("utf-8"))
        self.tree.write("Cargo.toml", ('[dependencies]\ncloudflare = { git = "https://github.com/cloudflare/cloudflare-rs", rev = "%s" }\n'
                                       % shas[6]).encode("utf-8"))
        self.tree.write("infra/main.tf", ('module "dns" {\n  source = "git::https://github.com/cloudflare/terraform-modules.git?ref=%s"\n}\n'
                                          % shas[7]).encode("utf-8"))
        self.tree.write("CHANGELOG.md", ("# 1.0.1\n\n* cloudflare fix ([abc1234](https://github.com/cloudflare/x/commit/%s))\n"
                                         % shas[8]).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Set aside 9 finding(s) that are package integrity hashes (sha512-..., h1:..., sha256:...) or"
                      " commit ids, checksums and package names that a lock file or manifest vouches for", out)
        for name in ("deploy.yml", ".pre-commit-config.yaml", "requirements.txt", "Cargo.toml", "main.tf", "CHANGELOG.md"):
            self.assertNotIn(name, out)
        # the token in the same file is still listed, and is the only row for it
        self.assertRegex(out, r"CloudflareApiToken\s+\S+\s+cfT0\.\.\.\S\S\s+package\.json:\d+\s+move to \.env")
        self.assertEqual(len(re.findall(r"package\.json:\d+", out)), 1)
        log = read_file(re.search(r"^Log: (.*)$", out, re.M).group(1).strip())
        self.assertIn("set aside, a commit id, checksum or package name the file vouches for: package.json line 3 (CloudflareApiToken)", log)
        self.assertIn("set aside, a commit id, checksum or package name the file vouches for: Cargo.toml line 2 (CloudflareApiToken)", log)
        for sha in shas:
            self.assertNotIn(sha, log)
        # a real run moves the token and leaves every pin as it was
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        package = self.tree.read("package.json")
        self.assertNotIn(token, package)
        self.assertIn('"cloudflare_token": "${', package)
        for rel, sha in (("package.json", shas[0]), ("package.json", shas[1]), ("package.json", shas[2]),
                         (".github/workflows/deploy.yml", shas[3]), (".pre-commit-config.yaml", shas[4]),
                         ("requirements.txt", shas[5]), ("Cargo.toml", shas[6]), ("infra/main.tf", shas[7]),
                         ("CHANGELOG.md", shas[8])):
            self.assertIn(sha, self.tree.read(rel), rel)
        self.assertNoLeftovers()

    def test_private_key_files_are_never_rewritten_and_get_ssh_keygen_lines(self):
        # a key file (nothing but PEM blocks) is read by ssh or a server from its file: a placeholder would break it.
        # Without a passphrase it is offered to the quarantine like any file that cannot be fixed in place, unless it
        # lies in .ssh where ssh needs it; with one it is left alone; and the run prints the ssh-keygen line for each.
        bare, protected = openssh_key_text(b"none", b"none"), openssh_key_text(b"aes256-ctr", b"bcrypt")
        pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA deploy@demo\n"
        self.tree.write("deploy/id_ed25519", bare.encode("utf-8"))
        self.tree.write("deploy/id_ed25519.pub", pub.encode("utf-8"))
        self.tree.write(".ssh/id_ed25519_protected", protected.encode("utf-8"))
        self.tree.write(".ssh/id_rsa_legacy", LEGACY_PEM_PROTECTED.encode("utf-8"))
        self.tree.write(".ssh/id_rsa_bare", LEGACY_PEM_BARE.encode("utf-8"))
        self.tree.write("certs/server.pem", (CERT_BLOCK + LEGACY_PEM_BARE).encode("utf-8"))
        sep = r"[/\\]"
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Private key files: 6", out)   # these five and the fixture's docs/deploy_key.pem
        self.assertRegex(out, r"\d+\s+deploy%sid_ed25519\s+none \(OpenSSH format\)\s+move to \.secrets-quarantine%sdeploy%sid_ed25519\.enc \(encrypted\)"
                         % (sep, sep, sep))
        self.assertRegex(out, r"\d+\s+certs%sserver\.pem\s+none \(PEM\)\s+move to \.secrets-quarantine%scerts%sserver\.pem\.enc" % (sep, sep, sep))
        self.assertRegex(out, r"(?m)-\s+\.ssh%sid_ed25519_protected\s+yes \(OpenSSH format, aes256-ctr, bcrypt\)\s+left as it is\s*$" % sep)
        self.assertRegex(out, r"-\s+\.ssh%sid_rsa_legacy\s+yes, legacy PEM cipher \(AES-128-CBC\)\s+left as it is; upgrade its passphrase" % sep)
        self.assertRegex(out, r"-\s+\.ssh%sid_rsa_bare\s+none \(PEM\)\s+left as it is \(ssh needs it there\): add a passphrase" % sep)
        self.assertIn("Add a passphrase (ssh asks for it when the key is used, or ssh-agent remembers it):", out)
        self.assertRegex(out, r"(?m)^    ssh-keygen -p -a 100 -f deploy%sid_ed25519\s*$" % sep)
        self.assertRegex(out, r"ssh-keygen -p -o -a 100 -f certs%sserver\.pem\s+\(rewrites the key in the OpenSSH format: only for a key ssh uses\)" % sep)
        self.assertRegex(out, r"ssh-keygen -p -o -a 100 -f \.ssh%sid_rsa_bare\s+\(rewrites the key in the OpenSSH format\)" % sep)
        self.assertIn("A key that a server or program reads at start-up cannot take a passphrase", out)
        self.assertIn("Upgrade a passphrase set with the legacy PEM cipher (a single round of MD5 derives its key):", out)
        self.assertRegex(out, r"(?m)^    ssh-keygen -p -o -a 100 -f \.ssh%sid_rsa_legacy\s*$" % sep)
        head = out.split("Private key files:")[0]   # no key file is listed for a placeholder or shown as an archive
        for name in ("id_ed25519", "id_rsa_legacy", "id_rsa_bare", "server.pem", "deploy_key.pem"):
            self.assertNotIn(name, head)
        # --yes alone leaves every key file as it is and says what stays bare
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        kept = (("deploy/id_ed25519", bare), (".ssh/id_ed25519_protected", protected), (".ssh/id_rsa_legacy", LEGACY_PEM_PROTECTED),
                (".ssh/id_rsa_bare", LEGACY_PEM_BARE), ("certs/server.pem", CERT_BLOCK + LEGACY_PEM_BARE), ("docs/deploy_key.pem", PEM + "\n"))
        for rel, content in kept:
            self.assertEqual(self.tree.read(rel), content, rel)
        self.assertIn("4 private key file(s) without a passphrase stay where they are:", out)
        self.assertIn("The ssh-keygen line for each is in", out)
        # --yes --quarantine moves the bare ones outside .ssh, encrypted; the rest stays; --restore brings one back
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        for rel in ("deploy/id_ed25519", "certs/server.pem", "docs/deploy_key.pem"):
            self.assertFalse(os.path.exists(self.tree.path(rel)), rel)
            self.assertTrue(os.path.isfile(self.tree.path(".secrets-quarantine/" + rel + ".enc")), rel)
        for rel, content in kept[1:4]:
            self.assertEqual(self.tree.read(rel), content, rel)
        self.assertEqual(self.tree.read("deploy/id_ed25519.pub"), pub)
        self.assertIn("PrivateKey: make a new key pair (ssh-keygen -t ed25519 -a 100 -f ~/.ssh/<name>), install its .pub where", out)
        code, out, err = run_script(self.tree.root, ["--restore", "deploy/id_ed25519"])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.tree.read("deploy/id_ed25519"), bare)
        self.assertNoLeftovers()

    def test_package_names_in_registry_urls_are_not_secrets(self):
        # measured: TruffleHog releases before the fix for its issue 1517 report "-explode-assignable-expression-7",
        # a 32-character run of @babel/helper-explode-assignable-expression's tarball URL, as a Signable token: the
        # word "assignable" stands just before it. A run of a package archive's file name, or of the path segment
        # that name repeats, is the package's name and version: public, whatever shape a detector saw in it.
        url = ("https://registry.npmjs.org/@babel/helper-explode-assignable-expression/-/"
               "helper-explode-assignable-expression-7.18.6.tgz")
        sha1 = "2e85b818" + "17ebec4241b8f55ef1b62e4f150abcee"
        self.tree.write("package-lock.json", json.dumps({"name": "demo", "lockfileVersion": 3, "packages": {
            "node_modules/@babel/helper-explode-assignable-expression": {
                "version": "7.18.6", "resolved": url, "integrity": integrity_hash("sha512", "x"), "dev": True}}},
            indent=2).encode("utf-8"))
        self.tree.write("yarn.lock", ('# yarn lockfile v1\n\n\n"@babel/helper-explode-assignable-expression@^7.18.6":\n'
                                      '  version "7.18.6"\n  resolved "%s#%s"\n  integrity %s\n'
                                      % (url, sha1, integrity_hash("sha512", "y"))).encode("utf-8"))
        # a credential in a lock file stays one, and its row says where it sits and how long it is
        self.tree.write("sub/package-lock.json", json.dumps({"name": "sub", "lockfileVersion": 3, "packages": {
            "node_modules/cloudflare-sdk": {
                "version": "1.0.0",
                "resolved": "https://npm.example.com/cloudflare-sdk/-/cloudflare-sdk-1.0.0.tgz?token=%s" % sha1}}},
            indent=2).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Set aside 2 finding(s) that are package integrity hashes (sha512-..., h1:..., sha256:...) or"
                      " commit ids, checksums and package names that a lock file or manifest vouches for", out)
        self.assertNotIn("yarn.lock", out)
        self.assertNotRegex(out, r"\d\s+package-lock\.json\s+generated lock file")
        self.assertRegex(out, r"sub/package-lock\.json\s+generated lock file\s+CloudflareApiToken 2e85\.\.\.ee"
                              r" \(line 7, 40 chars, in \"resolved\"\)\s+move to \.secrets-quarantine/sub/package-lock\.json\.enc")
        log = read_file(re.search(r"^Log: (.*)$", out, re.M).group(1).strip())
        self.assertIn("set aside, a checksum, commit id or package name in a lock file: package-lock.json line 7 (Signable)", log)
        self.assertIn("set aside, a checksum, commit id or package name in a lock file: yarn.lock line 6 (Signable)", log)
        self.assertNotIn("explode-assignable", log)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        self.assertTrue(os.path.isfile(self.tree.path("package-lock.json")))
        self.assertTrue(os.path.isfile(self.tree.path("yarn.lock")))
        self.assertFalse(os.path.exists(self.tree.path("sub/package-lock.json")))
        self.assertTrue(os.path.isfile(self.tree.path(".secrets-quarantine/sub/package-lock.json.enc")))
        self.assertNoLeftovers()

    def test_an_old_releases_loose_patterns_are_held_to_the_current_ones(self):
        # measured: TruffleHog 3.5x reports any 20-character run within 40 characters of the letters "pd" as a
        # PagerDuty key (3.60 and later want u+ and 18 characters), and a 32-character run after "assignable" as a
        # Signable token (the detector excludes that word itself now). The fake carries both old patterns; a match
        # inside a base64 blob (a data: URI) is encoded bytes, whatever detector lines up with it.
        token, run = "u+AbCdEfGhIjKlMnOpQr", "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"
        payload = "Q" * 40 + "/" + base64.b64encode(bytes(bytearray(range(120)))).decode("ascii")
        self.tree.write("assets/site.css", b".pd-badge .pager-item-active-xy { color: #333; }\n.pager { display: flex; }\n")
        self.tree.write("assets/inline.css", (".cloudflare{background:url(data:image/png;base64,%s)}\n" % payload).encode("utf-8"))
        self.tree.write("config/alerts.yml", ("pagerduty_token: %s\n" % token).encode("utf-8"))
        self.tree.write("config/signable.ini", ("signable_key = %s\n" % run).encode("utf-8"))
        self.tree.write("src/types.ts", ('export const isAssignable = (x: unknown) => tag === "%s";\n' % run).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Set aside 1 finding(s) that are package integrity hashes (sha512-..., h1:..., sha256:...) or"
                      " commit ids, checksums and package names that a lock file or manifest vouches for", out)
        self.assertIn("or runs inside a base64 blob (a data: URI, an encoded file)", out)
        self.assertIn("Set aside 2 finding(s) that TruffleHog's current detectors would not report: a PagerDuty key is u+ and"
                      " 18 characters (TruffleHog 3.60 and later); the word before a Signable match was assignable or designable"
                      " (TruffleHog's own exclusion). This release's older patterns were held to the current ones; updating"
                      " TruffleHog is still worth doing.", out)
        for name in ("site.css", "inline.css", "types.ts"):
            self.assertNotIn(name, out)
        self.assertRegex(out, r"PagerDutyApiKey\s+PAGERDUTY_TOKEN\s+u\+Ab\.\.\.Qr\s+config/alerts\.yml:1\s+move to \.env")
        self.assertRegex(out, r"Signable\s+SIGNABLE_KEY\s+a0b1\.\.\.d5\s+config/signable\.ini:1\s+move to \.env")
        log = read_file(re.search(r"^Log: (.*)$", out, re.M).group(1).strip())
        self.assertRegex(log, r"set aside, not what the current TruffleHog reports \(a PagerDuty key is u\+ and 18 characters"
                              r" \(TruffleHog 3\.60 and later\)\): assets[/\\]site\.css line 1 \(PagerDutyApiKey\)")
        self.assertRegex(log, r"set aside, not what the current TruffleHog reports \(the word before a Signable match was assignable"
                              r" or designable \(TruffleHog's own exclusion\)\): src[/\\]types\.ts line 1 \(Signable\)")
        self.assertRegex(log, r"set aside, inside a base64 blob: assets[/\\]inline\.css line 1 \(CloudflareApiToken\)")
        for value in ("pager-item-active-xy", run, "Q" * 40, token):
            self.assertNotIn(value, log)
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.tree.read("assets/site.css"), ".pd-badge .pager-item-active-xy { color: #333; }\n.pager { display: flex; }\n")
        self.assertIn(payload, self.tree.read("assets/inline.css"))
        self.assertIn(run, self.tree.read("src/types.ts"))
        self.assertEqual(self.tree.read("config/alerts.yml"), "pagerduty_token: ${PAGERDUTY_TOKEN}\n")
        self.assertEqual(self.tree.read("config/signable.ini"), "signable_key = ${SIGNABLE_KEY}\n")
        self.assertNoLeftovers()

    def test_a_fresh_private_key_goes_to_the_os_store_when_dotenvx_can(self):
        store_dir = tempfile.mkdtemp(prefix="sweep-store-")
        store_file = os.path.join(store_dir, "store.json")
        store = sas.native_store_name() or "Linux Secret Service"
        env = {"FAKE_DOTENVX_VERSION": "2.38.0", "FAKE_DOTENVX_STORE": store_file}
        try:
            code, out, err = run_script(self.tree.root, ["--yes"], extra_env=env)
            self.assertEqual(code, 0, out + err)
            self.assertFalse(os.path.exists(self.tree.path(".env.keys")))            # nothing on disk
            self.assertFalse(os.path.exists(self.tree.path("config/.env.keys")))
            self.assertEqual(self.tree.leftovers(), [])
            with io.open(store_file, encoding="utf-8") as fh:
                stored = json.load(fh)
            self.assertEqual(len(stored), 1)                                           # the .env key pair
            self.assertIn("private key of .env: in the %s, kept by dotenvx (nothing on disk)" % store, out)
            self.assertIn("is in the %s, kept by dotenvx: there is no key file to back up." % store, out)
            self.assertIn("dotenvx keypair DOTENV_PRIVATE_KEY -f .env  prints it", out)
            self.assertIn("decrypts them is in the %s, kept by dotenvx. Day to day you use dotenvx itself, not this tool:" % store, out)
            self.assertNotIn("dotenvx native up", out)   # the key is there already
            self.assertNotIn("private key file:", out)
            self.assertNotIn("-fk", self.tree.read(".env"))                           # no hint at a file that is not there
            self.assertEqual(dotenvx_get(self.tree.root, "STRIPE_SECRET_KEY", extra_env=env), STRIPE_KEY)
            self.assertEqual(dotenvx_get(self.tree.root, "AWS_SECRET_ACCESS_KEY", extra_env=env), AWS_SECRET)
            # a later run respects the custody .env already has, and adds nothing to the store for it
            self.tree.write("src/more.py", ("KEY = '%s'\n" % STRIPE_KEY_2).encode("utf-8"))
            code, out, err = run_script(self.tree.root, ["--yes"], extra_env=env)
            self.assertEqual(code, 0, out + err)
            self.assertIn(".env already had its dotenvx key pair; its private key stays where it was", out)
            self.assertFalse(os.path.exists(self.tree.path(".env.keys")))
            with io.open(store_file, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)), 1)
            name = re.search(r"src/more\.py:1\s+move to \.env, replace with \$\{(\w+)\}", out).group(1)
            self.assertEqual(dotenvx_get(self.tree.root, name, extra_env=env), STRIPE_KEY_2)
            # the setup check puts its scratch key in the store and takes it out again
            code, out, err = run_script(self.tree.root, ["--check-setup"], extra_env=env)
            self.assertEqual(code, 0, out + err)
            self.assertIn("the private key went to the %s and was removed again" % store, out)
            with io.open(store_file, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)), 1)
        finally:
            shutil.rmtree(store_dir, ignore_errors=True)

    def test_without_a_reachable_store_the_key_stays_in_a_file_and_the_run_says_why(self):
        store = sas.native_store_name() or "Linux Secret Service"
        # dotenvx 2.38 but no store reachable (a bare Linux server): the key stays in .env.keys
        code, out, err = run_script(self.tree.root, ["--yes", "--no-rewrite"], extra_env={"FAKE_DOTENVX_VERSION": "2.38.0"})
        self.assertEqual(code, 0, out + err)
        self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
        self.assertNotIn("[--]", out)   # a server without a store is the normal case, not a warning
        self.assertIn("private key file: .env.keys  (file custody: failed to save private key to %s)" % store, out)
        self.assertIn("dotenvx from here on", out)
        self.assertIn("decrypts them is in .env.keys next to each env file. Day to day you use dotenvx itself, not this tool:", out)
        self.assertRegex(out, r"dotenvx native up\s+moves the private key from \.env\.keys into the %s, so that nothing is"
                              r" left on disk" % re.escape(store))
        self.assertRegex(out, r"then in \.env\.keys\s+next to the env file, then in the %s\." % re.escape(store))
        self.assertIn("Docs: https://dotenvx.com/docs", out)
        self.assertIn("# -fk .env.keys", self.tree.read(".env"))
        # a key that exists already is left alone, even with a store at hand
        store_dir = tempfile.mkdtemp(prefix="sweep-store-")
        store_file = os.path.join(store_dir, "store.json")
        try:
            self.tree.write("src/more.py", ("KEY = '%s'\n" % STRIPE_KEY_2).encode("utf-8"))
            code, out, err = run_script(self.tree.root, ["--yes"], extra_env={"FAKE_DOTENVX_VERSION": "2.38.0",
                                                                                 "FAKE_DOTENVX_STORE": store_file})
            self.assertEqual(code, 0, out + err)
            # the new secret went into .env under its existing key pair, and that key, which an earlier run had
            # to leave in .env.keys, was then moved into the store that is reachable now
            self.assertIn("Setup to tighten", out)
            self.assertIn("[ok] private key of .env: moved from .env.keys into the %s, kept by dotenvx (nothing on disk)" % store, out)
            self.assertFalse(os.path.exists(self.tree.path(".env.keys")))
            with io.open(store_file, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)), 1)
            self.assertEqual(dotenvx_get(self.tree.root, "STRIPE_SECRET_KEY",
                                         extra_env={"FAKE_DOTENVX_VERSION": "2.38.0", "FAKE_DOTENVX_STORE": store_file}), STRIPE_KEY)
            # --no-native keeps a fresh key in a file too, and says so
            other = ProjectTree({"app.py": 'TOKEN = "%s"\n' % GITHUB_TOKEN})
            try:
                code, out, err = run_script(other.root, ["--yes", "--no-native"],
                                            extra_env={"FAKE_DOTENVX_VERSION": "2.38.0", "FAKE_DOTENVX_STORE": store_file})
                self.assertEqual(code, 0, out + err)
                self.assertTrue(os.path.isfile(other.path(".env.keys")))
                self.assertIn("(file custody: --no-native)", out)
                self.assertNotIn("dotenvx native up", out)
                with io.open(store_file, encoding="utf-8") as fh:
                    self.assertEqual(len(json.load(fh)), 1)       # nothing added for the --no-native run
            finally:
                other.cleanup()
        finally:
            shutil.rmtree(store_dir, ignore_errors=True)

    def test_integrity_hashes_in_lock_files_are_not_secrets(self):
        # an AWS-looking string inside an npm sha512 integrity hash: a checksum, not a key
        hash_line = '"integrity": "%s"' % integrity_hash("sha512", AWS_ID)
        self.tree.write("package-lock.json", ('{"pkg": {%s}}\n' % hash_line).encode("utf-8"))
        self.tree.write("go.sum", ("example.com/mod v1.0.0 %s\n" % integrity_hash("h1", AWS_ID)).encode("utf-8"))
        # a string of the wrong length for its algorithm is not a checksum, whatever its prefix
        self.tree.write("yarn.lock", ("  integrity %s\n" % integrity_hash("sha512", AWS_ID, 5)).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Set aside 2 finding(s) that are package integrity hashes", out)
        self.assertIn("Each is named in the run log.", out)
        self.assertNotIn("package-lock.json", out)
        self.assertNotIn("go.sum", out)
        self.assertIn("move to .secrets-quarantine/yarn.lock", out)
        log = read_file(re.search(r"^Log: (.*)$", out, re.M).group(1).strip())
        self.assertIn("set aside, inside a package integrity hash: package-lock.json line 1 (AWS)", log)
        self.assertIn("set aside, inside a package integrity hash: go.sum line 1 (AWS)", log)
        self.assertNotIn(AWS_ID, log)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        self.assertTrue(os.path.isfile(self.tree.path("package-lock.json")))   # never moved over a checksum
        self.assertTrue(os.path.isfile(self.tree.path("go.sum")))
        self.assertFalse(os.path.exists(self.tree.path("yarn.lock")))

    def test_a_text_file_with_fixable_and_unfixable_secrets_stays_in_place(self):
        self.tree.write("conf/app.yml", ("stripe: %s\ntoken: PWD-abcdefgh\n" % STRIPE_KEY).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine", "--min-length", "16"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("secret shorter than 16 characters (--min-length)", out)
        self.assertIn("stays in place: its other secrets are fixed above; handle this one by hand", out)
        text = self.tree.read("conf/app.yml")
        self.assertNotIn(STRIPE_KEY, text)                 # the fixable secret was handled
        self.assertIn("PWD-abcdefgh", text)                # the short one is still there, for the hand
        self.assertTrue(os.path.isfile(self.tree.path("conf/app.yml")))   # not moved

    def test_run_warning_names_the_mode_and_the_setup_check_has_none(self):
        notice = "this is a security tool that changes files on purpose"
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertIn(notice, out)
        self.assertIn("This is a dry run: nothing is changed.", out)
        code, out, err = run_script(self.tree.root, ["--yes", "--no-rewrite"])
        self.assertIn("--yes was given: it will not ask before changing them.", out)
        code, out, err = run_script(self.tree.root, [], stdin_text="n\n")
        self.assertIn("Nothing is changed before you confirm.", out)
        code, out, err = run_script(self.tree.root, ["--check-setup"])
        self.assertNotIn(notice, out)

    def test_a_log_of_every_run_is_kept_in_the_common_folder(self):
        logs = tempfile.mkdtemp(prefix="sweep-logtest-")
        try:
            for n in range(101):   # old logs beyond LOG_KEEP are dropped
                with io.open(os.path.join(logs, "2020-01-01T00-00-%02dZ-old-%d.log" % (n % 60, n)), "w") as fh:
                    fh.write(u"old\n")
            foreign = ("1999-app.log", "server.log", "2020-01-01.log", "notes.txt")   # a shared folder: not ours
            for name in foreign:
                with io.open(os.path.join(logs, name), "w") as fh:
                    fh.write(u"someone else's\n")
            code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env={"SWEEP_AND_SECURE_LOG_DIR": logs})
            self.assertEqual(code, 0, out + err)
            for name in foreign:
                self.assertTrue(os.path.isfile(os.path.join(logs, name)), name)
            names = sorted(name for name in os.listdir(logs) if sas.RUN_LOG_NAME_RE.match(name))
            self.assertEqual(len(names), sas.LOG_KEEP)
            newest = os.path.join(logs, names[-1])
            self.assertIn("Log: " + newest, out)
            text = read_file(newest)
            for needle in ("sweep-and-secure %s" % sas.__version__, "| $ ", "trufflehog", "Plaintext secrets found",
                           "Dry run: nothing was changed.", "| exit code 0"):
                self.assertIn(needle, text)
            self.assertNotIn(STRIPE_KEY, text)             # masked previews only, never the values
            self.assertNotIn(AWS_SECRET, text)
            # --log-dir picks the folder, --no-log writes nothing
            other = os.path.join(logs, "elsewhere")
            code, out, err = run_script(self.tree.root, ["--dry-run", "--log-dir", other], extra_env={"SWEEP_AND_SECURE_LOG_DIR": logs})
            self.assertEqual(code, 0, out + err)
            self.assertEqual(len(os.listdir(other)), 1)
            before = set(os.listdir(logs))
            code, out, err = run_script(self.tree.root, ["--dry-run", "--no-log"], extra_env={"SWEEP_AND_SECURE_LOG_DIR": logs})
            self.assertEqual(code, 0, out + err)
            self.assertNotIn("Log: ", out)
            self.assertEqual(set(os.listdir(logs)), before)
            # the prompts and answers are logged too
            code, out, err = run_script(self.tree.root, [], stdin_text="n\n", extra_env={"SWEEP_AND_SECURE_LOG_DIR": logs})
            newest = sorted(name for name in os.listdir(logs) if sas.RUN_LOG_NAME_RE.match(name))[-1]
            text = read_file(os.path.join(logs, newest))
            self.assertIn("(s = choose which): n", text)
            self.assertIn("| exit code 2", text)
        finally:
            shutil.rmtree(logs, ignore_errors=True)

    def test_utf16_source_file_is_rewritten_in_its_own_encoding(self):
        text = u"token = '%s'\r\n" % GITHUB_TOKEN
        self.tree.write("src/legacy.txt", b"\xff\xfe" + text.encode("utf-16-le"))
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        raw = self.tree.read_bytes("src/legacy.txt")
        self.assertEqual(raw[:2], b"\xff\xfe")
        self.assertEqual(raw[2:].decode("utf-16-le"), u"token = '${GITHUB_TOKEN}'\r\n")

    def test_stale_staging_leftovers_are_removed_and_never_scanned(self):
        self.tree.write(".sweep-and-secure-abc123", ("STRIPE_SECRET_KEY=%s\n" % STRIPE_KEY_2).encode("utf-8"))
        self.tree.write(".sweep-and-secure-dir/.env", ("STRIPE_SECRET_KEY=%s\n" % STRIPE_KEY_2).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("would be removed", out)
        self.assertNotIn(".sweep-and-secure-abc123:", out)   # not treated as a source file
        self.assertTrue(os.path.exists(self.tree.path(".sweep-and-secure-abc123")))
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Removed 2 leftover staging file(s)", out)
        self.assertNoLeftovers()

    def test_quarantine_moves_archives_holding_secrets_out_of_the_tree(self):
        # a tar.gz whose member name is not UTF-8: still listed, moved and recorded in the manifest
        with tarfile.open(self.tree.path("build/old.tar.gz"), "w:gz", encoding="latin-1", format=tarfile.USTAR_FORMAT) as tf:
            data = ("key %s\n" % STRIPE_KEY).encode("utf-8")
            info = tarfile.TarInfo(u"caf\u00e9.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        self.before = self.tree.snapshot()
        _, listing, _ = run_script(self.tree.root, ["--dry-run", "--quarantine"])
        self.assertIn(u"build/old.tar.gz", listing)
        # the undecodable byte shows as U+FFFD, or as ? on a console that cannot show that
        self.assertTrue(u"caf\ufffd.txt" in listing or u"caf?.txt" in listing, listing)
        self.assertIn("move to .secrets-quarantine/build/keys.zip", listing)
        self.assertIn("move to .secrets-quarantine/build/blob.txt.gz", listing)
        self.assertTrue(os.path.isfile(self.tree.path("build/keys.zip")))     # a dry run moves nothing
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        for rel in ("build/keys.zip", "build/blob.txt.gz", "build/old.tar.gz"):
            self.assertFalse(os.path.exists(self.tree.path(rel)), rel)
            self.assertEqual(quarantined_bytes(self.tree, rel), self.before[rel.replace("/", os.sep)], rel)
        manifest = self.tree.read(".secrets-quarantine/MANIFEST.txt")
        self.assertIn("build/keys.zip.enc  <- build/keys.zip  (Stripe)  why: zip archive  inside: config/prod.env"
                      "  enc: QUARANTINE_KEY_", manifest)
        self.assertIn("build/blob.txt.gz.enc  <- build/blob.txt.gz  (Github)  why: gzip archive  inside: blob.txt"
                      "  enc: QUARANTINE_KEY_", manifest)
        self.assertIn(u"build/old.tar.gz.enc  <- build/old.tar.gz  (Stripe)  why: tar.gz archive  inside: caf\ufffd.txt"
                      u"  enc: QUARANTINE_KEY_", manifest)
        self.assertTrue(os.path.isfile(self.tree.path(".secrets-quarantine/build/old.tar.gz.enc")))
        index = json.loads(self.tree.read(".secrets-quarantine/index.json"))
        self.assertEqual(sorted((r["original"], r["quarantined"]) for r in index),
                         [("build/blob.txt.gz", "build/blob.txt.gz.enc"), ("build/keys.zip", "build/keys.zip.enc"),
                          ("build/old.tar.gz", "build/old.tar.gz.enc"), ("docs/deploy_key.pem", "docs/deploy_key.pem.enc")])
        self.assertEqual([r["why"] for r in index if r["original"] == "build/keys.zip"], ["zip archive"])
        self.assertEqual([r["inside"] for r in index if r["original"] == "build/keys.zip"], [["config/prod.env"]])
        self.assertIn("4 file(s) moved to .secrets-quarantine (encrypted)", out)
        self.assertIn("/.secrets-quarantine/", self.tree.read(".gitignore"))
        self.assertIn("moved to .secrets-quarantine, AES-256 encrypted; the passphrase of each is kept in", out)
        self.assertIn(".secrets-quarantine/.env, encrypted by dotenvx with the key pair of .env. MANIFEST.txt and index.json"
                      " map each file to where it came from", out)
        # the quarantine folder is never scanned, with or without the flag
        for extra in ([], ["--quarantine"], ["--no-default-excludes"]):
            code, out, err = run_script(self.tree.root, ["--dry-run"] + extra)
            self.assertEqual(code, 0, out + err)
            self.assertNotIn(".secrets-quarantine/build", out)
            self.assertNotIn("keys.zip", out)

    def test_quarantine_into_a_custom_folder_keeps_existing_files(self):
        self.tree.write("q/build/keys.zip.enc", b"earlier copy")
        code, out, err = run_script(self.tree.root, ["--dry-run", "--quarantine-dir", "q"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("move to q/build/keys.zip", out)   # --quarantine-dir alone implies --quarantine
        self.assertNotIn("q/build/keys.zip:", out)       # the custom folder itself is not scanned
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine-dir", "q"])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.tree.read_bytes("q/build/keys.zip.enc"), b"earlier copy")
        self.assertTrue(os.path.isfile(self.tree.path("q/build/keys.zip.1.enc")))
        self.assertEqual(quarantined_bytes(self.tree, "build/keys.zip", "q"), self.before[os.path.join("build", "keys.zip")])
        self.assertTrue(os.path.isfile(self.tree.path("q/.env")))
        self.assertFalse(os.path.exists(self.tree.path("build/keys.zip")))
        self.assertIn("/q/", self.tree.read(".gitignore"))
        code, out, err = run_script(self.tree.root, ["--dry-run", "--quarantine-dir", "q"])
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("q/build", out)                 # still excluded once the files are in there

    def test_quarantined_files_are_encrypted_and_their_passphrases_kept_by_dotenvx(self):
        original = self.before[os.path.join("build", "keys.zip")]
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("build/keys.zip: moved to .secrets-quarantine/build/keys.zip.enc (encrypted)", out)
        self.assertIn("3 file(s) moved to .secrets-quarantine (encrypted)", out)
        self.assertIn(".secrets-quarantine/.env holds the quarantine's passphrases, encrypted to the key pair of .env", out)
        self.assertIn("were moved to .secrets-quarantine, AES-256 encrypted; the passphrase of each is kept in", out)
        self.assertIn(".secrets-quarantine/.env, encrypted by dotenvx with the key pair of .env.", out)
        self.assertIn("--restore <stored name>", out)
        # nothing in the quarantine folder holds a secret in the clear
        for dirpath, _, names in os.walk(self.tree.path(".secrets-quarantine")):
            for name in names:
                with io.open(os.path.join(dirpath, name), "rb") as fh:
                    data = fh.read()
                for secret in (STRIPE_KEY, GITHUB_TOKEN):
                    self.assertNotIn(secret.encode("utf-8"), data, name)
        self.assertEqual(sorted(os.listdir(self.tree.path(".secrets-quarantine"))), [".env", "MANIFEST.txt", "build", "docs", "index.json"])
        self.assertEqual(sorted(os.listdir(self.tree.path(".secrets-quarantine/build"))), ["blob.txt.gz.enc", "keys.zip.enc"])
        # the passphrases are encrypted to the key pair .env got in this run: no second key pair, no second key file
        keys_env = self.tree.read(".secrets-quarantine/.env")
        public = re.search(r'^DOTENV_PUBLIC_KEY="?([0-9A-Za-z]+)', self.tree.read(".env"), re.M).group(1)
        self.assertIn('DOTENV_PUBLIC_KEY="%s"' % public, keys_env)
        self.assertTrue(encrypted("QUARANTINE_KEY_1", keys_env) and encrypted("QUARANTINE_KEY_2", keys_env), keys_env)
        self.assertIn("# Restore a file:  sweep-and-secure --restore <stored name>", keys_env)
        self.assertFalse(os.path.exists(self.tree.path(".secrets-quarantine/.env.keys")))
        # the records say how each file is kept, and MANIFEST.txt's hand recipe gets it back
        manifest = self.tree.read(".secrets-quarantine/MANIFEST.txt")
        self.assertTrue(manifest.startswith("# Files moved here by sweep-and-secure"), manifest)
        self.assertIn("dotenvx get QUARANTINE_KEY_N -f .env | openssl enc -d -aes-256-cbc -pbkdf2 -pass stdin -in NAME.enc"
                      " -out NAME", manifest)
        self.assertRegex(manifest, r"build/keys\.zip\.enc  <- build/keys\.zip  \(Stripe\)  why: zip archive"
                                   r"  inside: config/prod\.env  enc: QUARANTINE_KEY_[12] \(aes-256-cbc, kdf pbkdf2\)")
        record = quarantine_record(self.tree, "build/keys.zip")
        self.assertEqual((record["quarantined"], record["encrypted"], record["cipher"], record["kdf"], record["size"]),
                         ("build/keys.zip.enc", True, "aes-256-cbc", "pbkdf2", len(original)))
        self.assertEqual(record["sha256"], hashlib.sha256(original).hexdigest())
        for rel in ("build/keys.zip", "build/blob.txt.gz"):
            self.assertEqual(quarantined_bytes(self.tree, rel), self.before[rel.replace("/", os.sep)], rel)
        # a later run adds to the same .env, numbering on
        self.tree.write("build/more.zip", original)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        self.assertIn(".secrets-quarantine/.env holds the quarantine's passphrases, encrypted to the key pair of .env", out)
        self.assertEqual(quarantine_record(self.tree, "build/more.zip")["key"], "QUARANTINE_KEY_4")   # after the two archives and the key file
        self.assertEqual(quarantined_bytes(self.tree, "build/more.zip"), original)
        self.assertNoLeftovers()

    def test_restore_puts_a_quarantined_file_back(self):
        original = self.before[os.path.join("build", "keys.zip")]
        posix = os.name != "nt"
        if posix:   # a credential file's tight mode and an executable's bits must come back with it
            os.chmod(self.tree.path("build/keys.zip"), 0o600)
            os.chmod(self.tree.path("build/blob.txt.gz"), 0o755)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        if posix:
            self.assertEqual(quarantine_record(self.tree, "build/keys.zip")["mode"], "0600")
            self.assertEqual(quarantine_record(self.tree, "build/blob.txt.gz")["mode"], "0755")
        code, out, err = run_script(self.tree.root, ["--restore", "build/keys.zip.enc"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("[ok] restored build/keys.zip from build/keys.zip.enc (decrypted)", out)
        self.assertNotIn("Scanning with TruffleHog", out)
        self.assertEqual(self.tree.read_bytes("build/keys.zip"), original)
        if posix:
            self.assertEqual(stat.S_IMODE(os.stat(self.tree.path("build/keys.zip")).st_mode), 0o600)
        self.assertFalse(os.path.exists(self.tree.path(".secrets-quarantine/build/keys.zip.enc")))
        index = json.loads(self.tree.read(".secrets-quarantine/index.json"))
        self.assertEqual([bool(r.get("restored_at")) for r in index if r["original"] == "build/keys.zip"], [True])
        self.assertIn("restored build/keys.zip.enc -> build/keys.zip", self.tree.read(".secrets-quarantine/MANIFEST.txt"))
        # the original path works as a name too
        code, out, err = run_script(self.tree.root, ["--restore", "build/blob.txt.gz"])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.tree.read_bytes("build/blob.txt.gz"), self.before[os.path.join("build", "blob.txt.gz")])
        if posix:
            self.assertEqual(stat.S_IMODE(os.stat(self.tree.path("build/blob.txt.gz")).st_mode), 0o755)
        # a file already back is not offered again; a taken place is refused; so is a run without openssl
        code, out, err = run_script(self.tree.root, ["--restore", "build/keys.zip"])
        self.assertEqual(code, 1, out + err)
        self.assertIn("build/keys.zip is not in", err)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])    # both go back into quarantine
        self.assertEqual(code, 0, out + err)
        self.tree.write("build/keys.zip", b"something new")
        code, out, err = run_script(self.tree.root, ["--restore", "build/keys.zip"])
        self.assertEqual(code, 1, out + err)
        self.assertIn("build/keys.zip exists; move it out of the way first", err)
        self.assertEqual(self.tree.read_bytes("build/keys.zip"), b"something new")
        self.assertTrue(os.path.isfile(self.tree.path(".secrets-quarantine/build/keys.zip.enc")))
        code, out, err = run_script(self.tree.root, ["--restore", "build/blob.txt.gz", "--openssl", sys.executable])
        self.assertEqual(code, 1, out + err)
        self.assertIn("openssl is needed to decrypt build/blob.txt.gz.enc", err)
        self.assertTrue(os.path.isfile(self.tree.path(".secrets-quarantine/build/blob.txt.gz.enc")))
        self.assertFalse(os.path.exists(self.tree.path("build/blob.txt.gz")))
        self.assertNoLeftovers()

    def test_a_quarantine_only_tree_gets_its_own_key_pair_with_the_usual_custody(self):
        store = sas.native_store_name() or "Linux Secret Service"
        tree = ProjectTree({})       # archives only: no env file gets a key pair in this run
        before = tree.snapshot()
        try:
            code, out, err = run_script(tree.root, ["--yes", "--quarantine"])
            self.assertEqual(code, 0, out + err)
            keys_env = tree.read(".secrets-quarantine/.env")
            self.assertRegex(keys_env, r'(?m)^DOTENV_PUBLIC_KEY="02fake\w+" # -fk \.env\.keys$')
            self.assertTrue(encrypted("QUARANTINE_KEY_1", keys_env), keys_env)
            self.assertTrue(os.path.isfile(tree.path(".secrets-quarantine/.env.keys")))
            self.assertFalse(os.path.exists(tree.path(".env")))
            self.assertIn("private key file: .secrets-quarantine/.env.keys  (file custody: ", out)
            self.assertNotIn("holds the quarantine's passphrases, encrypted to the key pair of", out)
            self.assertIn(".env.keys*", tree.read(".gitignore"))
            self.assertEqual(quarantined_bytes(tree, "build/keys.zip"), before[os.path.join("build", "keys.zip")])
            # the primer's key commands name the file whose key pair is new, not a .env that does not exist
            self.assertRegex(out, r"dotenvx keypair -f \.secrets-quarantine/\.env\s+prints the key pair")
            self.assertNotIn("keypair DOTENV_PRIVATE_KEY", out)
            self.assertIn("dotenvx run -- <your command>", out)
            # with a dotenvx that could use the store but found none, native up names that file too
            code, out, err = run_script(tree.root, ["--yes", "--quarantine", "--restore", "build/keys.zip"],
                                        extra_env={"FAKE_DOTENVX_VERSION": "2.38.0"})
            self.assertEqual(code, 0, out + err)
            more = ProjectTree({})
            try:
                code, out, err = run_script(more.root, ["--yes", "--quarantine"], extra_env={"FAKE_DOTENVX_VERSION": "2.38.0"})
                self.assertEqual(code, 0, out + err)
                self.assertRegex(out, r"dotenvx native up -f \.secrets-quarantine/\.env\s+moves the private key")
            finally:
                more.cleanup()
        finally:
            tree.cleanup()
        # with a dotenvx that can, that key pair's private key goes to the OS store like any other
        other = ProjectTree({})
        before = other.snapshot()
        store_dir = tempfile.mkdtemp(prefix="sweep-store-")
        store_file = os.path.join(store_dir, "store.json")
        env = {"FAKE_DOTENVX_VERSION": "2.38.0", "FAKE_DOTENVX_STORE": store_file}
        try:
            code, out, err = run_script(other.root, ["--yes", "--quarantine"], extra_env=env)
            self.assertEqual(code, 0, out + err)
            self.assertIn("private key of .secrets-quarantine/.env: in the %s, kept by dotenvx (nothing on disk)" % store, out)
            self.assertFalse(os.path.exists(other.path(".secrets-quarantine/.env.keys")))
            self.assertNotIn("-fk", other.read(".secrets-quarantine/.env"))
            with io.open(store_file, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)), 1)
            self.assertEqual(quarantined_bytes(other, "build/keys.zip", extra_env=env), before[os.path.join("build", "keys.zip")])
        finally:
            other.cleanup()
            shutil.rmtree(store_dir, ignore_errors=True)

    def test_restore_uses_the_quarantines_own_key_when_the_project_got_another_later(self):
        # the quarantine got a key pair of its own (nothing else to encrypt at the time); later the
        # project's .env got one too. Restoring must use the quarantine's key, whatever dotenvx's rules
        # for picking a key by name (1.x: the environment first, so the project's key must not be put there)
        for version in ("1.6.0", "2.38.0"):
            tree = ProjectTree({})
            before = tree.snapshot()
            env = {"FAKE_DOTENVX_VERSION": version}
            try:
                code, out, err = run_script(tree.root, ["--yes", "--quarantine"], extra_env=env)
                self.assertEqual(code, 0, out + err)
                self.assertTrue(os.path.isfile(tree.path(".secrets-quarantine/.env.keys")), version)
                tree.write("app.py", ('TOKEN = "%s"\n' % GITHUB_TOKEN).encode("utf-8"))
                code, out, err = run_script(tree.root, ["--yes"], extra_env=env)
                self.assertEqual(code, 0, out + err)
                self.assertTrue(os.path.isfile(tree.path(".env.keys")), version)     # a second, different key pair
                code, out, err = run_script(tree.root, ["--restore", "build/keys.zip"], extra_env=env)
                self.assertEqual(code, 0, version + "\n" + out + err)
                self.assertEqual(tree.read_bytes("build/keys.zip"), before[os.path.join("build", "keys.zip")])
                # and a file quarantined now still goes into the quarantine's own .env, decryptable
                code, out, err = run_script(tree.root, ["--yes", "--quarantine"], extra_env=env)
                self.assertEqual(code, 0, out + err)
                self.assertEqual(quarantined_bytes(tree, "build/keys.zip", keys_file=".secrets-quarantine/.env.keys", extra_env=env),
                                 before[os.path.join("build", "keys.zip")])
            finally:
                tree.cleanup()

    def test_an_unknown_dotenvx_version_still_gets_a_sound_custody_record(self):
        store = sas.native_store_name() or "Linux Secret Service"
        # --no-version-check with a dotenvx whose version cannot be read: taken for a current one, so -fk is
        # given and the key is adopted from the staging folder like any other
        env = {"FAKE_DOTENVX_VERSION": "nonsense"}
        code, out, err = run_script(self.tree.root, ["--yes", "--no-rewrite", "--no-version-check"], extra_env=env)
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("Traceback", err)
        self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
        self.assertIn("private key file: .env.keys  (file custody: dotenvx's version is unknown (--no-version-check),"
                      " so the %s was not tried)" % store, out)
        self.assertEqual(dotenvx_get(self.tree.root, "STRIPE_SECRET_KEY", extra_env=env), STRIPE_KEY)
        # a dotenvx that writes no key file at all kept the key itself: said so, not crashed over
        other = ProjectTree({"app.py": 'TOKEN = "%s"\n' % GITHUB_TOKEN})
        try:
            code, out, err = run_script(other.root, ["--yes"], extra_env={"FAKE_DOTENVX_NO_KEYS_FILE": "1"})
            self.assertEqual(code, 0, out + err)
            self.assertNotIn("Traceback", err)
            self.assertIn("[--] .env: dotenvx wrote no .env.keys for the new key pair; it keeps the private key itself", out)
            self.assertIn("private key of .env: in the %s, kept by dotenvx (nothing on disk)" % store, out)
            self.assertFalse(os.path.exists(other.path(".env.keys")))
        finally:
            other.cleanup()

    def test_a_later_run_tightens_an_earlier_setup(self):
        store = sas.native_store_name() or "Linux Secret Service"
        original = self.before[os.path.join("build", "keys.zip")]
        # an earlier sweep: a dotenvx that keeps keys in files, and no openssl, so the quarantine holds plaintext
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine", "--openssl", os.path.join(self.tree.root, "none")])
        self.assertEqual(code, 0, out + err)
        self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
        self.assertEqual(quarantine_record(self.tree, "build/keys.zip")["encrypted"], False)
        store_dir = tempfile.mkdtemp(prefix="sweep-store-")
        store_file = os.path.join(store_dir, "store.json")
        env = {"FAKE_DOTENVX_VERSION": "2.38.0", "FAKE_DOTENVX_STORE": store_file}
        try:
            # a dry run names what can be tightened and changes nothing
            code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env=env)
            self.assertEqual(code, 0, out + err)
            self.assertIn("Setup to tighten", out)
            self.assertIn("the private key of .env is in .env.keys; dotenvx can keep it in the %s instead, with nothing on disk"
                          % store, out)
            self.assertIn("3 file(s) in .secrets-quarantine are stored as they are, secrets inside; they can be AES-256 encrypted",
                          out)
            self.assertIn("Dry run: nothing was changed.", out)
            self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
            self.assertFalse(os.path.exists(store_file))
            # an interactive no changes nothing and exits 2
            code, out, err = run_script(self.tree.root, [], stdin_text="n\n", extra_env=env)
            self.assertEqual(code, 2, out + err)
            # the fixture's config/.env.production carries a header called DOTENV_PUBLIC_KEY like .env's, but its
            # private key is not here: the key in .env.keys is .env's, and is never taken for the other file's
            self.assertNotIn("config/.env.production is in .env.keys", out)
            self.assertIn("Tighten the setup now (move 1 private key(s) into the %s, encrypt 3 quarantined file(s))? [y/N]: "
                          % store, out)
            self.assertIn("Nothing changed.", out)
            self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
            self.assertFalse(os.path.exists(store_file))
            # yes: the key goes into the store, the quarantined files are encrypted in place, the primer follows
            code, out, err = run_script(self.tree.root, [], stdin_text="y\n", extra_env=env)
            self.assertEqual(code, 0, out + err)
            self.assertIn("Tightening the setup ...", out)
            self.assertIn("[ok] .env: private key moved from .env.keys into the %s (nothing on disk)" % store, out)
            self.assertNotIn("config/.env.production: private key moved", out)
            self.assertIn("[ok] .secrets-quarantine/build/keys.zip: encrypted in place as build/keys.zip.enc", out)
            self.assertIn("[ok] private key of .env: moved from .env.keys into the %s, kept by dotenvx (nothing on disk)" % store, out)
            self.assertIn(".secrets-quarantine/.env holds the quarantine's passphrases, encrypted to the key pair of .env", out)
            self.assertIn("Done: 0 secret(s) stored encrypted; 1 private key(s) moved into the %s; 3 quarantined file(s) encrypted"
                          " in place" % store, out)
            self.assertIn("3 file(s) an earlier run had moved to .secrets-quarantine as they were are now AES-256 encrypted", out)
            self.assertIn("dotenvx from here on", out)
            self.assertNotIn("treat them as exposed", out)     # no secret was handled by this run
            self.assertFalse(os.path.exists(self.tree.path(".env.keys")))
            self.assertNotIn("-fk", self.tree.read(".env"))
            with io.open(store_file, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)), 1)
            self.assertEqual(dotenvx_get(self.tree.root, "STRIPE_SECRET_KEY", extra_env=env), STRIPE_KEY)
            record = quarantine_record(self.tree, "build/keys.zip")
            self.assertEqual((record["quarantined"], record["encrypted"], record["cipher"]), ("build/keys.zip.enc", True, "aes-256-cbc"))
            self.assertTrue(record["key"].startswith("QUARANTINE_KEY_"), record)
            self.assertIn("encrypted_at", record)
            self.assertEqual(record["sha256"], hashlib.sha256(original).hexdigest())
            self.assertFalse(os.path.exists(self.tree.path(".secrets-quarantine/build/keys.zip")))
            self.assertEqual(quarantined_bytes(self.tree, "build/keys.zip", extra_env=env), original)
            self.assertIn("encrypted build/keys.zip -> build/keys.zip.enc  enc: %s (aes-256-cbc, kdf pbkdf2)" % record["key"],
                          self.tree.read(".secrets-quarantine/MANIFEST.txt"))
            for dirpath, _, names in os.walk(self.tree.path(".secrets-quarantine")):
                for name in names:
                    with io.open(os.path.join(dirpath, name), "rb") as fh:
                        self.assertNotIn(STRIPE_KEY.encode("utf-8"), fh.read(), name)
            # a further run has nothing to tighten, and says where the key is
            code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"], extra_env=env)
            self.assertEqual(code, 0, out + err)
            self.assertIn("Nothing to encrypt.", out)
            self.assertNotIn("Setup to tighten", out)
            self.assertIn("[ok] .env: encrypted with dotenvx; its private key is kept by dotenvx, not in a key file here", out)
            self.assertIn("[--] config/.env.production: encrypted with dotenvx, but its private key is not available on this"
                          " machine", out)
            self.assertIn("https://dotenvx.com/docs", out)
            # --restore still works with the key in the store
            code, out, err = run_script(self.tree.root, ["--restore", "build/keys.zip"], extra_env=env)
            self.assertEqual(code, 0, out + err)
            self.assertEqual(self.tree.read_bytes("build/keys.zip"), original)
            self.assertNoLeftovers()
        finally:
            shutil.rmtree(store_dir, ignore_errors=True)

    def test_tightening_keeps_the_records_of_files_moved_in_the_same_run(self):
        original = self.before[os.path.join("build", "keys.zip")]
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine", "--openssl", os.path.join(self.tree.root, "none")])
        self.assertEqual(code, 0, out + err)
        self.tree.write("build/more.zip", original)        # a new file to quarantine, and two old ones to encrypt
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("build/more.zip: moved to .secrets-quarantine/build/more.zip.enc (encrypted)", out)
        self.assertIn("[ok] .secrets-quarantine/build/keys.zip: encrypted in place as build/keys.zip.enc", out)
        index = json.loads(self.tree.read(".secrets-quarantine/index.json"))
        self.assertEqual(sorted(r["quarantined"] for r in index),
                         ["build/blob.txt.gz.enc", "build/keys.zip.enc", "build/more.zip.enc", "docs/deploy_key.pem.enc"])
        self.assertTrue(all(r["encrypted"] for r in index), index)
        for rel in ("build/more.zip", "build/keys.zip", "build/blob.txt.gz"):
            self.assertEqual(quarantined_bytes(self.tree, rel), self.before.get(rel.replace("/", os.sep), original), rel)
        code, out, err = run_script(self.tree.root, ["--restore", "build/more.zip"])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.tree.read_bytes("build/more.zip"), original)
        self.assertNoLeftovers()

    def test_tightening_respects_no_native_ci_and_an_unreachable_store(self):
        store = sas.native_store_name() or "Linux Secret Service"
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"])    # keys in a file (dotenvx 2.0), quarantine encrypted
        self.assertEqual(code, 0, out + err)
        self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
        store_dir = tempfile.mkdtemp(prefix="sweep-store-")
        store_file = os.path.join(store_dir, "store.json")
        try:
            # --no-native: nothing to tighten, the key stays where it is and the run says where that is
            code, out, err = run_script(self.tree.root, ["--yes", "--quarantine", "--no-native"],
                                        extra_env={"FAKE_DOTENVX_VERSION": "2.38.0", "FAKE_DOTENVX_STORE": store_file})
            self.assertEqual(code, 0, out + err)
            self.assertNotIn("Setup to tighten", out)
            self.assertIn("[ok] .env: encrypted with dotenvx; its private key is in .env.keys", out)
            # a key of the same name is in .env.keys, but it is .env's, not this file's: never claimed for it
            self.assertIn("[--] config/.env.production: encrypted with dotenvx, but its private key is not available on this"
                          " machine (.env.keys holds a key of the same name that does not decrypt it)", out)
            self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
            # on CI (the CI variable set) keys stay in files, as dotenvx itself keeps them there
            code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"],
                                        extra_env={"FAKE_DOTENVX_VERSION": "2.38.0", "FAKE_DOTENVX_STORE": store_file, "CI": "true"})
            self.assertEqual(code, 0, out + err)
            self.assertNotIn("Setup to tighten", out)
            self.assertFalse(os.path.exists(store_file))
            other = ProjectTree({"app.py": 'TOKEN = "%s"\n' % GITHUB_TOKEN})
            try:
                code, out, err = run_script(other.root, ["--yes"],
                                            extra_env={"FAKE_DOTENVX_VERSION": "2.38.0", "FAKE_DOTENVX_STORE": store_file, "CI": "true"})
                self.assertEqual(code, 0, out + err)
                self.assertIn("private key file: .env.keys  (file custody: CI is set: keys stay in files there, as dotenvx itself does)", out)
                self.assertFalse(os.path.exists(store_file))
            finally:
                other.cleanup()
            # a store that is not reachable: the move is tried, fails, and the key stays in its file; the run still succeeds
            code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"], extra_env={"FAKE_DOTENVX_VERSION": "2.38.0"})
            self.assertEqual(code, 0, out + err)
            self.assertIn("Setup to tighten", out)
            self.assertIn("[--] .env: the private key stays in .env.keys: failed to save private key to %s" % store, out)
            self.assertIn("1 could not be tightened (see above)", out)
            self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
            self.assertEqual(dotenvx_get(self.tree.root, "STRIPE_SECRET_KEY"), STRIPE_KEY)
        finally:
            shutil.rmtree(store_dir, ignore_errors=True)

    def test_without_openssl_quarantined_files_are_moved_as_they_are_and_the_run_says_so(self):
        missing = os.path.join(self.tree.root, "no-such-openssl")
        code, out, err = run_script(self.tree.root, ["--dry-run", "--quarantine", "--openssl", missing])
        self.assertEqual(code, 0, out + err)
        self.assertIn("move to .secrets-quarantine/build/keys.zip", out)
        self.assertNotIn(".enc", out)
        self.assertNotIn("(encrypted)", out)
        self.assertIn("is moved whole to .secrets-quarantine AS IT IS: openssl was not found at --openssl %s" % missing, out)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine", "--openssl", missing])
        self.assertEqual(code, 0, out + err)
        self.assertRegex(out, r"(?m)build/keys\.zip: moved to \.secrets-quarantine/build/keys\.zip\s*$")
        self.assertNotIn("(encrypted)", out)
        self.assertIn("[--] 3 file(s) were moved to .secrets-quarantine AS THEY ARE, secrets inside: openssl was not found", out)
        self.assertIn("were moved to .secrets-quarantine AS THEY ARE (openssl was not found at --openssl", out)
        self.assertEqual(self.tree.read_bytes(".secrets-quarantine/build/keys.zip"), self.before[os.path.join("build", "keys.zip")])
        self.assertFalse(os.path.exists(self.tree.path(".secrets-quarantine/.env")))
        record = quarantine_record(self.tree, "build/keys.zip")
        self.assertEqual((record["quarantined"], record["encrypted"]), ("build/keys.zip", False))
        self.assertNotIn("key", record)
        self.assertIn("build/keys.zip  <- build/keys.zip  (Stripe)  why: zip archive  inside: config/prod.env  PLAINTEXT",
                      self.tree.read(".secrets-quarantine/MANIFEST.txt"))
        # an openssl that cannot encrypt a probe file counts as missing too
        other = ProjectTree({"app.py": 'TOKEN = "%s"\n' % GITHUB_TOKEN})
        try:
            code, out, err = run_script(other.root, ["--dry-run", "--quarantine", "--openssl", sys.executable])
            self.assertEqual(code, 0, out + err)
            self.assertIn("AS IT IS: openssl at %s could not encrypt a probe file" % sys.executable, out)
        finally:
            other.cleanup()

    def test_an_old_openssl_without_pbkdf2_still_encrypts_the_quarantine(self):
        original = self.before[os.path.join("build", "keys.zip")]
        env = {"FAKE_OPENSSL_NO_PBKDF2": "1"}
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"], extra_env=env)
        self.assertEqual(code, 0, out + err)
        record = quarantine_record(self.tree, "build/keys.zip")
        self.assertEqual((record["encrypted"], record["kdf"]), (True, "legacy"))
        self.assertIn("enc: %s (aes-256-cbc, kdf legacy)" % record["key"], self.tree.read(".secrets-quarantine/MANIFEST.txt"))
        self.assertEqual(quarantined_bytes(self.tree, "build/keys.zip"), original)
        code, out, err = run_script(self.tree.root, ["--restore", "build/keys.zip"], extra_env=env)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.tree.read_bytes("build/keys.zip"), original)

    def test_a_quarantined_dot_env_never_replaces_the_quarantines_own_key_file(self):
        # with the secrets going to config/secrets.env, a .env that cannot be fixed is quarantined; it
        # must not land on the quarantine's own .env, which holds the passphrases
        tree = ProjectTree({".env": "TOKEN=PWD-abcdefgh\n", "src/app.py": 'STRIPE = "%s"\n' % STRIPE_KEY})
        try:
            code, out, err = run_script(tree.root, ["--yes", "--quarantine", "--env-file", "config/secrets.env",
                                                    "--min-length", "16"])
            self.assertEqual(code, 0, out + err)
            self.assertIn(".env: moved to .secrets-quarantine/.env.1.enc (encrypted)", out)
            self.assertEqual(quarantined_bytes(tree, ".env", keys_file="config/.env.keys"), b"TOKEN=PWD-abcdefgh\n")
            public = re.search(r'^DOTENV_PUBLIC_KEY\w*="?([0-9A-Za-z]+)', tree.read("config/secrets.env"), re.M).group(1)
            self.assertIn('DOTENV_PUBLIC_KEY="%s"' % public, tree.read(".secrets-quarantine/.env"))
            self.assertTrue(encrypted("STRIPE", tree.read("config/secrets.env")))
        finally:
            tree.cleanup()

    def test_quarantine_refuses_reserved_folders(self):
        for name in (".sweep-and-secure-q", ".env.keys", "."):
            code, out, err = run_script(self.tree.root, ["--dry-run", "--quarantine-dir", name])
            self.assertEqual(code, 1, name + "\n" + out + err)
            self.assertIn("cannot be used", err)

    def test_nothing_found_is_a_clean_exit(self):
        clean = tempfile.mkdtemp(prefix="sweep-clean-")
        try:
            with io.open(os.path.join(clean, "readme.txt"), "wb") as fh:
                fh.write(b"nothing to see here\n")
            code, out, err = run_script(clean, [])
            self.assertEqual(code, 0, out + err)
            self.assertIn("no plaintext secrets", out)
            self.assertIn("Nothing to encrypt", out)
            self.assertIn("A real run on a folder with secrets sets dotenvx up", out)
        finally:
            shutil.rmtree(clean, ignore_errors=True)

    def test_non_utf8_console_does_not_break_the_run(self):
        # dotenvx prints non-ASCII glyphs; with -v they are echoed. An ASCII-only stdout
        # (Windows pipe, LANG=C) must not turn into a traceback half way through.
        code, out, err = run_script(self.tree.root, ["--yes", "-v"], extra_env={"PYTHONIOENCODING": "ascii"})
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("Traceback", err)
        self.assertIn("Done:", out)
        self.assertIn("${AWS_ACCESS_KEY_ID}", self.tree.read("src/settings.py"))


class InterruptionTests(unittest.TestCase):
    """What a run that dies half way leaves behind, and what it says about it."""

    def setUp(self):
        self.tree = ProjectTree()

    def tearDown(self):
        self.tree.cleanup()

    def test_interrupt_after_encryption_protects_the_key_file_and_reports_the_state(self):
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt()
        run = InProcess(self.tree.root, ["--yes"], {"rewrite_source": interrupted}).run()
        self.assertIsInstance(run.exception, KeyboardInterrupt)
        self.assertIn(".env.keys*", self.tree.read(".gitignore"))          # protected before encrypting
        self.assertTrue(encrypted("AWS_ACCESS_KEY_ID", self.tree.read(".env")))
        self.assertIn("Stopped early (interrupted). State of the tree:", run.out)
        self.assertIn("encrypted and saved:   .env", run.out)
        self.assertIn("still plaintext:       src/settings.py", run.out)
        self.assertIn("Run again to finish", run.out)
        self.assertEqual(self.tree.leftovers(), [])

    def test_unexpected_exception_reports_the_state_and_exits_1(self):
        def broken(*args, **kwargs):
            raise RuntimeError("boom")
        run = InProcess(self.tree.root, ["--yes"], {"rewrite_source": broken}).run()
        self.assertIsNone(run.exception)
        self.assertEqual(run.code, 1)
        self.assertIn("unexpected error", run.out)
        self.assertIn("RuntimeError", run.err)
        self.assertIn("State of the tree", run.out)
        self.assertIn(".env.keys*", self.tree.read(".gitignore"))

    def test_interrupt_during_dotenvx_leaves_the_env_file_and_no_staging_behind(self):
        real_encrypt = sas.dotenvx_encrypt

        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt()

        try:
            existing = self.tree.path(".env")
            args = sas.parse_args([self.tree.root, "--yes"])
            job = {"keys": ["NEW_KEY"], "new": [("NEW_KEY", "value")], "items": []}
            sas.dotenvx_encrypt = interrupted
            self.assertRaises(KeyboardInterrupt, sas.encrypt_env_file, existing, job, "dotenvx", self.tree.root, args)
            self.assertEqual(self.tree.read(".env"), FILES[".env"])
            missing = self.tree.path("new.env")
            self.assertRaises(KeyboardInterrupt, sas.encrypt_env_file, missing, job, "dotenvx", self.tree.root, args)
            self.assertFalse(os.path.exists(missing))
            self.assertEqual(self.tree.leftovers(), [])
        finally:
            sas.dotenvx_encrypt = real_encrypt


class UnitTests(unittest.TestCase):

    def test_parse_env_entries(self):
        text = ('export A=1\nB="two\nlines"\nC=\'single # not a comment\'\nD=plain # comment\n'
                'E=x#y\n# comment\nnot an entry\nF=\n')
        entries = list(sas.parse_env_entries(text))
        self.assertEqual([(k, v) for k, v, _ in entries],
                         [("A", "1"), ("B", "two\nlines"), ("C", "single # not a comment"),
                          ("D", "plain"), ("E", "x"), ("F", "")])
        self.assertEqual([line for _, _, line in entries], [1, 2, 4, 5, 6, 9])
        self.assertEqual([k for k, _, _ in sas.parse_env_entries(u"\ufeffFIRST=1\nSECOND=2\n")], ["FIRST", "SECOND"])

    def test_quote_env_value_follows_dotenvx_rules(self):
        # measured against dotenvx 2.38: see the docstring of quote_env_value
        self.assertEqual(sas.quote_env_value("pa$$ #w\\n"), ("'pa$$ #w\\n'", True))
        self.assertEqual(sas.quote_env_value(PEM), ("'" + PEM + "'", True))
        self.assertEqual(sas.quote_env_value("it's"), ("`it's`", True))
        self.assertEqual(sas.quote_env_value("it's $ecret"), ("`it's \\$ecret`", True))
        self.assertEqual(sas.quote_env_value("it's `x` and $y"), ('"it\'s `x` and \\$y"', True))
        for value in ("it's `x` \"$y\"", "it's a\\path", "it's \\$lit", "a'b`c\"d"):
            quoted, exact = sas.quote_env_value(value)
            self.assertFalse(exact, value)
            self.assertTrue(quoted.startswith('"'))
        self.assertIn("backslash", sas.inexact_reason("it's a\\path"))
        self.assertIn("backtick", sas.inexact_reason("a'b`c\"d"))

    def test_choose_name(self):
        self.assertEqual(sas.choose_name("Github", "token", "x"), "GITHUB_TOKEN")
        self.assertEqual(sas.choose_name("Stripe", "api_key", "x"), "STRIPE_API_KEY")
        self.assertEqual(sas.choose_name("GoogleGeminiAPIKey", "apiKey", "x"), "GOOGLE_GEMINI_API_KEY")
        self.assertEqual(sas.choose_name("AWS", "AWS_ACCESS_KEY_ID", "x"), "AWS_ACCESS_KEY_ID")
        self.assertEqual(sas.choose_name("AWS", "access_key_id", "x"), "AWS_ACCESS_KEY_ID")
        self.assertEqual(sas.choose_name("Postgres", "database_url", "x"), "DATABASE_URL")
        self.assertEqual(sas.choose_name("SlackWebhook", "url", "x"), "SLACK_WEBHOOK")
        self.assertEqual(sas.choose_name("Stripe", "DOTENV_THING", "x"), "APP_DOTENV_THING")
        self.assertTrue(re.match(r"^STRIPE_SECRET_[0-9A-F]{6}$", sas.choose_name("Stripe", None, "x")))
        self.assertTrue(re.match(r"^PRIVATE_KEY_[0-9A-F]{6}$", sas.choose_name("PrivateKey", None, "x")))
        self.assertEqual(sas.choose_name("PrivateKey", None, PEM), PEM_FALLBACK_KEY)
        self.assertEqual(sas.choose_name("Stripe", "123abc", "x"), "STRIPE_123ABC")

    def test_detector_words(self):
        self.assertEqual(sas.detector_words("GoogleGeminiAPIKey"), "GOOGLE_GEMINI_API_KEY")
        self.assertEqual(sas.detector_words("SlackWebhook"), "SLACK_WEBHOOK")
        self.assertEqual(sas.detector_words("AWS"), "AWS")
        self.assertEqual(sas.detector_words("URI"), "URI")
        self.assertEqual(sas.detector_words(""), "SECRET")

    def test_guess_name_from_prefix(self):
        cases = [
            ('API_KEY = "', "API_KEY"),
            ('  "apiKey": "', "apiKey"),
            ("password: ", "password"),
            ('os.environ["KEY"] = "', "KEY"),
            ("export STRIPE_KEY=", "STRIPE_KEY"),
            ('setdefault("TOKEN", "', "TOKEN"),
            ("Use webhook ", None),
            ("-H 'Authorization: Bearer ", None),
            ("", None),
        ]
        for prefix, expected in cases:
            self.assertEqual(sas.guess_name_from_prefix(prefix), expected, prefix)

    def test_parse_selection(self):
        self.assertEqual(sas.parse_selection("1 3 5-7", 9), [1, 3, 5, 6, 7])
        self.assertEqual(sas.parse_selection("2,2, 1", 3), [1, 2])
        self.assertEqual(sas.parse_selection("all", 3), [1, 2, 3])
        for bad in ("0", "4", "x", "3-1", "1-"):
            self.assertIsNone(sas.parse_selection(bad, 3), bad)

    def test_candidate_secrets_splits_aws_pairs(self):
        finding = sas.Finding("/p", 1, "AWS", AWS_ID, AWS_ID + ":" + AWS_SECRET, False, "PLAIN", {})
        self.assertEqual(sas.candidate_secrets(finding), [AWS_ID, AWS_ID + ":" + AWS_SECRET, AWS_SECRET])
        short = sas.Finding("/p", 1, "X", "abcdefghij", "abcdefghij:5432", False, "PLAIN", {})
        self.assertEqual(sas.candidate_secrets(short), ["abcdefghij", "abcdefghij:5432"])

    def test_candidate_secrets_keeps_boundary_characters_of_the_second_part(self):
        secret = "abc/DEF+ghi/JKL=mno/PQR=="          # '/' and '=' at the edges are part of it
        finding = sas.Finding("/p", 1, "X", "ID0123456789", "ID0123456789:" + secret, False, "PLAIN", {})
        self.assertIn(secret, sas.candidate_secrets(finding))
        finding = sas.Finding("/p", 1, "X", "ID0123456789", secret + ":ID0123456789", False, "PLAIN", {})
        self.assertIn(secret, sas.candidate_secrets(finding))
        finding = sas.Finding("/p", 1, "X", "ID0123456789", "ID0123456789" + secret, False, "PLAIN", {})
        self.assertIn(secret, sas.candidate_secrets(finding))  # no delimiter at all

    def test_locate_extends_urls_and_handles_escaped_newlines(self):
        data = ('DATABASE_URL = "%s"\nOTHER = "%s"\n' % (PG_URL, PG_URL.replace("/app", "/test"))).encode("utf-8")
        found = sas.locate(data, PG_URL[:PG_URL.rindex("/")], "PLAIN")
        self.assertEqual([token for token, _, _, _ in found],
                         [PG_URL.encode("utf-8"), PG_URL.replace("/app", "/test").encode("utf-8")])
        self.assertEqual([canonical for _, _, _, canonical in found], [PG_URL, PG_URL.replace("/app", "/test")])
        prose = ("See %s. Then [%s], (%s) and %s!" % (PG_URL, PG_URL, PG_URL, PG_URL)).encode("utf-8")
        found = sas.locate(prose, PG_URL[:PG_URL.rindex("/")], "PLAIN")
        self.assertEqual([token for token, _, _, _ in found], [PG_URL.encode("utf-8")] * 4)
        escaped = b'KEY="-----BEGIN X-----\\nabc\\n-----END X-----"'
        found = sas.locate(escaped, "-----BEGIN X-----\nabc\n-----END X-----", "PLAIN")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][0], b"-----BEGIN X-----\\nabc\\n-----END X-----")  # replaced in the file
        self.assertEqual(found[0][3], "-----BEGIN X-----\nabc\n-----END X-----")      # stored in .env
        self.assertEqual(sas.locate(b"nothing here", "missing-secret", "PLAIN"), [])
        utf16 = b"\xff\xfe" + u"k = 'secret-value-123'".encode("utf-16-le")
        found = sas.locate(utf16, "secret-value-123", "PLAIN")
        self.assertEqual([(token, enc) for token, enc, _, _ in found], [(u"secret-value-123".encode("utf-16-le"), "utf-16-le")])

    def test_trim_url_tail(self):
        self.assertEqual(sas.trim_url_tail(b"postgres://h/db.", b"postgres://h"), b"postgres://h/db")
        self.assertEqual(sas.trim_url_tail(b"postgres://h/db],", b"postgres://h"), b"postgres://h/db")
        self.assertEqual(sas.trim_url_tail(b"postgres://h/a(1)", b"postgres://h"), b"postgres://h/a(1)")
        self.assertEqual(sas.trim_url_tail(b"postgres://h.", b"postgres://h."), b"postgres://h.")

    def test_find_tool_returns_an_absolute_path(self):
        found = sas.find_tool("dotenvx", FAKE_DOTENVX, REPO)
        self.assertTrue(os.path.isabs(found))
        self.assertEqual(os.path.splitext(found)[0], FAKE_DOTENVX)   # Windows picks dotenvx.cmd
        cwd = os.getcwd()
        os.chdir(HERE)
        try:
            found = sas.find_tool("dotenvx", os.path.join("fakebin", "dotenvx"), REPO)
        finally:
            os.chdir(cwd)
        self.assertEqual(os.path.splitext(found)[0], FAKE_DOTENVX)

    def test_write_bytes_replaces_atomically_and_keeps_the_mode(self):
        folder = tempfile.mkdtemp(prefix="sweep-unit-")
        try:
            path = os.path.join(folder, "settings.py")
            with io.open(path, "wb") as fh:
                fh.write(b"old")
            os.chmod(path, 0o640)
            sas.write_bytes(path, b"new content")
            with io.open(path, "rb") as fh:
                self.assertEqual(fh.read(), b"new content")
            if os.name != "nt":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o640)
            self.assertEqual(os.listdir(folder), ["settings.py"])  # no temp file left behind
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    @unittest.skipUnless(hasattr(os, "symlink") and os.name != "nt", "symlinks")
    def test_write_bytes_writes_through_a_symlink(self):
        folder = tempfile.mkdtemp(prefix="sweep-unit-")
        try:
            target = os.path.join(folder, "real.env")
            link = os.path.join(folder, ".env")
            with io.open(target, "wb") as fh:
                fh.write(b"old")
            os.symlink("real.env", link)
            sas.write_bytes(link, b"new")
            self.assertTrue(os.path.islink(link))
            with io.open(target, "rb") as fh:
                self.assertEqual(fh.read(), b"new")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_write_bytes_falls_back_to_in_place_and_restores_on_failure(self):
        folder = tempfile.mkdtemp(prefix="sweep-unit-")
        real_mkstemp = sas.tempfile.mkstemp

        def no_temp_files(*args, **kwargs):
            raise OSError(13, "Permission denied")

        try:
            path = os.path.join(folder, "file.txt")
            with io.open(path, "wb") as fh:
                fh.write(b"original")
            sas.tempfile.mkstemp = no_temp_files
            sas.write_bytes(path, b"replaced")
            with io.open(path, "rb") as fh:
                self.assertEqual(fh.read(), b"replaced")
            self.assertRaises(TypeError, sas.write_bytes, path, u"not bytes")   # write fails half way
            with io.open(path, "rb") as fh:
                self.assertEqual(fh.read(), b"replaced")                        # old content is back
        finally:
            sas.tempfile.mkstemp = real_mkstemp
            shutil.rmtree(folder, ignore_errors=True)

    def test_say_never_raises(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        sas.say(u"\u25c8 glyph \u26c9", stream)
        stream.seek(0)
        self.assertEqual(stream.read(), u"? glyph ?\n")
        sas.say(u"nowhere", None)   # pythonw: no stdout at all
        closed = io.StringIO()
        closed.close()
        sas.say(u"closed", closed)

    def test_run_command_kills_the_child_when_interrupted(self):
        events = []

        class FakeProcess(object):
            returncode = 0

            def communicate(self, data):
                raise KeyboardInterrupt()

            def kill(self):
                events.append("kill")

            def wait(self):
                events.append("wait")

        real_popen = sas.subprocess.Popen
        sas.subprocess.Popen = lambda *args, **kwargs: FakeProcess()
        try:
            self.assertRaises(KeyboardInterrupt, sas.run_command, ["dotenvx", "encrypt"])
        finally:
            sas.subprocess.Popen = real_popen
        self.assertEqual(events, ["kill", "wait"])

    @unittest.skipUnless(sas.which("git"), "git is not installed")
    def test_ensure_gitignore_asks_git_and_wins_over_negated_rules(self):
        folder = tempfile.mkdtemp(prefix="sweep-git-")
        try:
            subprocess.check_call(["git", "init", "-q", folder])
            keys = os.path.join(folder, ".env.keys")
            with io.open(keys, "wb") as fh:
                fh.write(b"DOTENV_PRIVATE_KEY=fake\n")
            ignore = os.path.join(folder, ".gitignore")
            with io.open(ignore, "wb") as fh:
                fh.write(b".env.keys*\r\n!.env.keys\r\n")        # a line matches, but git re-includes the file
            self.assertFalse(sas.git_ignores(folder, keys))
            changed, message = sas.ensure_gitignore(folder, [keys])
            self.assertTrue(changed, message)
            self.assertNotIn("STILL", message)
            self.assertTrue(sas.git_ignores(folder, keys))
            with io.open(ignore, "rb") as fh:
                self.assertNotIn(b"\n.env.keys*\n", fh.read())   # keeps the file's CRLF line ends
            changed, message = sas.ensure_gitignore(folder, [keys])
            self.assertFalse(changed, message)
            self.assertIn("already ignores", message)
            # a keys file that does not exist yet can be protected ahead of time
            future = os.path.join(folder, "config", ".env.keys")
            changed, message = sas.ensure_gitignore(folder, [future])
            self.assertFalse(changed, message)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_is_env_file(self):
        for name in (".env", ".env.production", "prod.env", ".env.local", ".env.example"):
            self.assertTrue(sas.is_env_file(name), name)
        for name in (".env.keys", ".env.keys.bak", ".env.vault", ".envrc", "environment.py", "env", "settings.py"):
            self.assertFalse(sas.is_env_file(name), name)
        for name in (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env", ".env.Example"):
            self.assertTrue(sas.is_example_env_file(name), name)
        for name in (".env", ".env.production", "prod.env", "example.txt"):
            self.assertFalse(sas.is_example_env_file(name), name)
        self.assertTrue(sas.is_lockfile("package-lock.json"))
        self.assertTrue(sas.is_lockfile("Cargo.lock"))
        self.assertFalse(sas.is_lockfile("lock.py"))

    def test_is_excluded_accepts_either_separator(self):
        rules = [re.compile(p) for p in sas.ALWAYS_EXCLUDES + sas.DEFAULT_EXCLUDES]
        self.assertTrue(sas.is_excluded("/p/node_modules/x/.env", rules))
        self.assertTrue(sas.is_excluded("C:\\p\\node_modules\\x\\.env".replace("\\", os.sep), rules))
        self.assertTrue(sas.is_excluded("/p/.sweep-and-secure-abc", rules))
        self.assertTrue(sas.is_excluded("/p/.env.keys", rules))
        self.assertFalse(sas.is_excluded("/p/src/.env", rules))
        # --no-default-excludes drops only the version-control and vendor folders
        always = [re.compile(p) for p in sas.ALWAYS_EXCLUDES]
        self.assertTrue(sas.is_excluded("/p/.env.keys", always))
        self.assertTrue(sas.is_excluded("/p/config/.env.keys.bak", always))
        self.assertTrue(sas.is_excluded("/p/sub/.env.keys.production", always))
        self.assertTrue(sas.is_excluded("/p/.sweep-and-secure-x/.env", always))
        self.assertFalse(sas.is_excluded("/p/node_modules/x/.env", always))
        # the key-file rule names files, not every descendant of a similarly named folder
        self.assertFalse(sas.is_excluded("/backup/.env.keys-project/src/a.py", always))
        self.assertFalse(sas.is_excluded("/p/.env.keysmith", always))

    def test_build_plan_ignores_findings_in_excluded_paths(self):
        folder = tempfile.mkdtemp(prefix="sweep-unit-")
        try:
            path = os.path.join(folder, "node_modules", "pkg", "index.js")
            os.makedirs(os.path.dirname(path))
            with io.open(path, "wb") as fh:
                fh.write(("const t = '%s';\n" % GITHUB_TOKEN).encode("utf-8"))
            finding = sas.Finding(path, 1, "Github", GITHUB_TOKEN, "", False, "PLAIN", {})
            args = sas.parse_args([folder, "--yes"])
            rules = [re.compile(p) for p in sas.DEFAULT_EXCLUDES]
            plan = sas.build_plan([finding], folder, os.path.join(folder, ".env"), args, [], rules)
            self.assertEqual((plan.ignored, plan.items, list(plan.unfixable)), (1, [], []))
            plan = sas.build_plan([finding], folder, os.path.join(folder, ".env"), args, [], [])
            self.assertEqual(len(plan.items), 1)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_inventory_never_reports_the_store_as_stale(self):
        folder = tempfile.mkdtemp(prefix="sweep-unit-")
        try:
            odd = os.path.join(folder, ".sweep-and-secure-store.env")
            other = os.path.join(folder, ".sweep-and-secure-leftover")
            for path in (odd, other):
                with io.open(path, "wb") as fh:
                    fh.write(b"K=v\n")
            _, _, stale = sas.inventory_env_files(folder, [], protect=(odd,))
            self.assertEqual(stale, [other])
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_archive_kind(self):
        folder = tempfile.mkdtemp(prefix="sweep-unit-")
        try:
            def write(name, data):
                path = os.path.join(folder, name)
                with io.open(path, "wb") as fh:
                    fh.write(data)
                return path
            self.assertEqual(sas.archive_kind(write("a.bin", b"PK\x03\x04rest")), "zip")
            self.assertEqual(sas.archive_kind(write("b.dat", b"\x1f\x8b\x08")), "gzip")
            self.assertEqual(sas.archive_kind(write("c.tar", b"\x00" * 257 + b"ustar\x00")), "tar")
            self.assertEqual(sas.archive_kind(write("d.jar", b"not really")), "jar")   # by name
            self.assertIsNone(sas.archive_kind(write("e.txt", b"plain text\n")))
            self.assertIsNone(sas.archive_kind(os.path.join(folder, "missing")))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def finding(self, path, detector, raw, raw_v2="", decoder="PLAIN"):
        return sas.Finding(path, 0, detector, raw, raw_v2, False, decoder, {})

    def test_inspect_archive_names_the_files_inside_that_hold_the_secrets(self):
        folder = tempfile.mkdtemp(prefix="sweep-inside-")
        try:
            inner = io.BytesIO()
            with zipfile.ZipFile(inner, "w") as z:
                z.writestr("deep/creds.txt", "aws %s %s\n" % (AWS_ID, AWS_SECRET))
            tgz = io.BytesIO()
            with tarfile.open(fileobj=tgz, mode="w:gz") as tf:
                data = ("hook: %s\n" % SLACK).encode("utf-8")
                info = tarfile.TarInfo("docs/hooks.yml")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            outer = os.path.join(folder, "bundle.zip")
            with zipfile.ZipFile(outer, "w") as z:
                z.writestr("conf/prod.env", "STRIPE_SECRET_KEY=%s\n" % STRIPE_KEY)
                z.writestr("readme.txt", "nothing here\n")
                z.writestr("nested/keys.zip", inner.getvalue())
                z.writestr("nested/docs.tar.gz", tgz.getvalue())
                z.writestr("misc/notes.txt", "the stripe key again: %s\n" % STRIPE_KEY)
            archive = sas.Unfixable(outer, "zip" + u" archive", "zip")
            archive.findings = [self.finding(outer, "Stripe", STRIPE_KEY),
                                self.finding(outer, "AWS", AWS_ID, "%s:%s" % (AWS_ID, AWS_SECRET)),
                                self.finding(outer, "SlackWebhook", SLACK),
                                self.finding(outer, "Github", GITHUB_TOKEN)]   # not in there at all
            sas.inspect_archive(archive)
            inside = [(member, [f.detector for f in found]) for member, found in archive.inside]
            self.assertEqual(inside, [("conf/prod.env", ["Stripe"]),
                                      ("nested/keys.zip!deep/creds.txt", ["AWS"]),
                                      ("nested/docs.tar.gz!docs/hooks.yml", ["SlackWebhook"]),
                                      ("misc/notes.txt", ["Stripe"])])
            self.assertEqual([f.detector for f in archive.unplaced], ["Github"])
            self.assertIn("1 secret(s) not found verbatim in any file inside (TruffleHog decoder: PLAIN)", archive.note)
            # a single gzip file: the member is named after the gzip header, falling back to the file name
            gz = os.path.join(folder, "dump.sql.gz")
            with gzip.open(gz, "wb") as fh:
                fh.write(("insert %s\n" % STRIPE_KEY).encode("utf-8"))
            archive = sas.Unfixable(gz, "gzip" + u" archive", "gzip")
            archive.findings = [self.finding(gz, "Stripe", STRIPE_KEY)]
            sas.inspect_archive(archive)
            self.assertEqual([m for m, _ in archive.inside], ["dump.sql"])
            self.assertEqual(archive.note, "")
            # formats the standard library cannot open are said so, and the secrets still listed
            seven = os.path.join(folder, "old.7z")
            with io.open(seven, "wb") as fh:
                fh.write(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 40)
            archive = sas.Unfixable(seven, "7z" + u" archive", "7z")
            archive.findings = [self.finding(seven, "Stripe", STRIPE_KEY)]
            sas.inspect_archive(archive)
            self.assertEqual(archive.inside, [])
            self.assertEqual(len(archive.unplaced), 1)
            self.assertIn("cannot look inside a 7z archive from here", archive.note)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_inspect_archive_names_lone_compressed_files_after_the_archive(self):
        folder = tempfile.mkdtemp(prefix="sweep-inside-")
        try:
            body = ("insert %s\n" % STRIPE_KEY).encode("utf-8")
            nameless = os.path.join(folder, "dump.sql.gz")       # gzip -n: no file name in the header
            with io.open(nameless, "wb") as fh:
                with gzip.GzipFile(filename="", fileobj=fh, mode="wb") as gz:
                    gz.write(body)
            with bz2.BZ2File(os.path.join(folder, "notes.bz2"), "wb") as fh:
                fh.write(body)
            with lzma.LZMAFile(os.path.join(folder, "report.txt.xz"), "wb") as fh:
                fh.write(body)
            for name, kind, member in (("dump.sql.gz", "gzip", "dump.sql"), ("notes.bz2", "bzip2", "notes"),
                                       ("report.txt.xz", "xz", "report.txt")):
                archive = sas.Unfixable(os.path.join(folder, name), kind + u" archive", kind)
                archive.findings = [self.finding(archive.path, "Stripe", STRIPE_KEY)]
                sas.inspect_archive(archive)
                self.assertEqual([m for m, _ in archive.inside], [member], name)
                self.assertEqual(archive.note, "", name)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_inspect_archive_copes_with_undecodable_member_names(self):
        folder = tempfile.mkdtemp(prefix="sweep-inside-")
        try:
            path = os.path.join(folder, "old.tar")
            with tarfile.open(path, "w", encoding="latin-1", format=tarfile.USTAR_FORMAT) as tf:   # a name that is not UTF-8
                data = ("key %s\n" % STRIPE_KEY).encode("utf-8")
                info = tarfile.TarInfo(u"caf\u00e9.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            archive = sas.Unfixable(path, "tar" + u" archive", "tar")
            archive.findings = [self.finding(path, "Stripe", STRIPE_KEY)]
            sas.inspect_archive(archive)
            self.assertEqual([m for m, _ in archive.inside], [u"caf\ufffd.txt"])
            u"".join(m for m, _ in archive.inside).encode("utf-8")   # printable and encodable
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_secrets_text_counts_distinct_secrets_that_mask_alike(self):
        twin = STRIPE_KEY[:10] + "ABCD" + STRIPE_KEY[14:]   # same first four and last two characters
        self.assertNotEqual(twin, STRIPE_KEY)
        findings = [self.finding("a.zip", "Stripe", STRIPE_KEY), self.finding("a.zip", "Stripe", twin),
                    self.finding("a.zip", "Stripe", STRIPE_KEY),   # the same secret again: counted once
                    self.finding("a.zip", "AWS", AWS_ID, "%s:%s" % (AWS_ID, AWS_SECRET))]
        self.assertEqual(sas.secrets_text(findings), "Stripe %s (x2), AWS %s" % (sas.mask(STRIPE_KEY), sas.mask(AWS_ID)))

    def test_inspect_archive_searches_big_members_in_chunks_within_a_budget(self):
        folder = tempfile.mkdtemp(prefix="sweep-inside-")
        saved = sas.INSPECT_FULL_READ_BYTES, sas.INSPECT_CHUNK, sas.INSPECT_BUDGET_BYTES
        try:
            path = os.path.join(folder, "big.zip")
            padding = b"x" * 1020
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("logs/huge.log", padding + STRIPE_KEY.encode("utf-8") + b"\n" + b"y" * 3000)
                z.writestr("logs/other.log", b"z" * 5000)
            archive = sas.Unfixable(path, "zip" + u" archive", "zip")
            archive.findings = [self.finding(path, "Stripe", STRIPE_KEY)]
            sas.INSPECT_FULL_READ_BYTES, sas.INSPECT_CHUNK = 1000, 1024   # the key straddles a chunk boundary
            sas.inspect_archive(archive)
            self.assertEqual([m for m, _ in archive.inside], ["logs/huge.log"])
            self.assertEqual(archive.note, "")
            sas.INSPECT_BUDGET_BYTES = 2000   # not enough to read everything: say so, keep what was seen
            archive = sas.Unfixable(path, "zip" + u" archive", "zip")
            archive.findings = [self.finding(path, "Stripe", STRIPE_KEY)]
            sas.inspect_archive(archive)
            self.assertIn("stopped looking after 0 MB of content; the rest was not checked", archive.note)
            # a member of unknown size (a gzip stream inside the zip) that turns out too big to hold:
            # the part already read is kept, so a secret straddling that boundary is still found
            sas.INSPECT_BUDGET_BYTES = saved[2]
            inner = io.BytesIO()
            with gzip.GzipFile(filename="big.log", fileobj=inner, mode="wb") as gz:
                gz.write(b"x" * 990 + STRIPE_KEY.encode("utf-8") + b"\n" + b"y" * 4000)
            path = os.path.join(folder, "wrapped.zip")
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("logs/big.log.gz", inner.getvalue())
            archive = sas.Unfixable(path, "zip" + u" archive", "zip")
            archive.findings = [self.finding(path, "Stripe", STRIPE_KEY)]
            sas.inspect_archive(archive)
            self.assertEqual([m for m, _ in archive.inside], ["logs/big.log.gz!big.log"])
            self.assertEqual(archive.note, "")
        finally:
            sas.INSPECT_FULL_READ_BYTES, sas.INSPECT_CHUNK, sas.INSPECT_BUDGET_BYTES = saved
            shutil.rmtree(folder, ignore_errors=True)

    def test_compiled_kind(self):
        folder = tempfile.mkdtemp(prefix="sweep-compiled-")
        try:
            def make(name, data=b"\x00" * 8):
                path = os.path.join(folder, name)
                with io.open(path, "wb") as fh:
                    fh.write(data)
                return path
            self.assertEqual(sas.compiled_kind(make("libz.so.1.2.11")), ".so file")
            self.assertEqual(sas.compiled_kind(make("Thing.DLL")), ".dll file")
            self.assertEqual(sas.compiled_kind(make("mod.cpython-311.pyc")), ".pyc file")
            self.assertEqual(sas.compiled_kind(make("Main.class", b"text")), ".class file")
            self.assertEqual(sas.compiled_kind(make("tool", b"\x7fELF" + b"\x00" * 60)), "ELF binary")
            self.assertEqual(sas.compiled_kind(make("mach", b"\xcf\xfa\xed\xfe" + b"\x00" * 60)), "Mach-O binary")
            self.assertEqual(sas.compiled_kind(make("module.wasm2", b"\x00asm\x01\x00\x00\x00")), "WebAssembly module")
            pe = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 16
            self.assertEqual(sas.compiled_kind(make("setup", pe)), "Windows PE binary")
            # MZ without a PE header is text that happens to start with MZ, not a program
            self.assertIsNone(sas.compiled_kind(make("notes.txt", b"MZ Corp quarterly notes\n" + b"x" * 64)))
            self.assertIsNone(sas.compiled_kind(make("data.bin", b"\x00\x01\x02binary")))
            self.assertIsNone(sas.compiled_kind(make("archive.zip", b"PK\x03\x04")))
            self.assertIsNone(sas.compiled_kind(make("README.so.txt", b"text")))
            self.assertIsNone(sas.compiled_kind(os.path.join(folder, "missing")))
            cache = {}
            path = make("cached", b"\x7fELF" + b"\x00" * 60)
            self.assertEqual(sas.compiled_kind(path, cache), "ELF binary")
            os.remove(path)
            self.assertEqual(sas.compiled_kind(path, cache), "ELF binary")   # answered from the cache
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_strings_near_masks_every_reported_secret_and_stops_at_string_ends(self):
        folder = tempfile.mkdtemp(prefix="sweep-near-")
        try:
            def make(name, data):
                path = os.path.join(folder, name)
                with io.open(path, "wb") as fh:
                    fh.write(data)
                return path
            path = make("lib.so", ("\0\x01junk\0AWS_ACCESS_KEY_ID=%s\0AWS_SECRET_ACCESS_KEY=%s\0" % (AWS_ID, AWS_SECRET)).encode("utf-8"))
            aws = sas.Finding(path, 0, "AWS", AWS_ID, AWS_ID + ":" + AWS_SECRET, False, "PLAIN", {})
            secrets = [sas.to_bytes(c) for c in sas.candidate_secrets(aws)]
            # cut at the NUL byte: the secret key in the next string is not shown
            self.assertEqual(sas.strings_near(path, aws, secrets), "AWS_ACCESS_KEY_ID=AKIA...M2")
            key = sas.Finding(path, 0, "AWS", AWS_SECRET, "", False, "PLAIN", {})
            self.assertEqual(sas.strings_near(path, key, secrets), "AWS_SECRET_ACCESS_KEY=1tUm...IU")
            # both on one line: the other reported secret is masked too
            one_line = make("one.so", ("id=%s secret=%s\n" % (AWS_ID, AWS_SECRET)).encode("utf-8"))
            self.assertEqual(sas.strings_near(one_line, aws, secrets), "id=AKIA...M2 secret=1tUm...IU")
            # a long printable run is clipped either side
            long_run = make("long.so", b"x" * 100 + AWS_ID.encode("utf-8") + b"y" * 100)
            near = sas.strings_near(long_run, aws, secrets)
            self.assertEqual(near, "..." + "x" * 40 + "AKIA...M2" + "y" * 40 + "...")
            # a reported secret that starts inside the shown width but runs past it is masked, not cut
            edge = make("edge.so", ("id=%s " % AWS_ID).encode("utf-8") + b"x" * 30 + AWS_SECRET.encode("utf-8") + b"\n")
            near = sas.strings_near(edge, aws, secrets)
            self.assertNotIn(AWS_SECRET[:8], near)
            self.assertIn("1tUm...IU", near)
            # a byte TruffleHog tacked on beyond the string (old releases) does not hide the match
            extra = sas.Finding(path, 0, "AWS", AWS_ID + "Q", "", False, "PLAIN", {})
            self.assertEqual(sas.strings_near(path, extra, secrets), "AWS_ACCESS_KEY_ID=AKIA...M2")
            # not in the file as such, unreadable, empty
            encoded = sas.Finding(path, 0, "X", "not-there-at-all-1234", "", False, "BASE64", {})
            self.assertEqual(sas.strings_near(path, encoded, secrets), "")
            self.assertEqual(sas.strings_near(os.path.join(folder, "missing"), aws, secrets), "")
            self.assertEqual(sas.strings_near(make("empty.so", b""), aws, secrets), "")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_lockfile_identifier(self):
        sha1 = "2e85b818" + "17ebec4241b8f55ef1b62e4f150abcee"
        b64 = integrity_hash("sha512", "x")[len("sha512-"):]   # 86 characters and ==, as packages.lock.json stores it

        def finding(raw):
            return sas.Finding("x", 1, "CloudflareApiToken", raw, "", False, "PLAIN", {})

        # public: a URL's fragment or path, a checksum / revision / reference field, a mix.lock entry
        public = ('resolved "https://registry.yarnpkg.com/cloudflare/-/cloudflare-1.0.0.tgz#%s"',
                  '"url": "https://api.github.com/repos/acme/thing/zipball/%s",',
                  '"https://deno.land/std@0.224.0/path/mod.ts": "%s",',
                  '      "reference": "%s",', '  revision: %s', '  checksum: 10c0/%s', 'checksum = "%s"',
                  'digest = "1:%s"', '"resolved": "git+ssh://git@github.com/cloudflare/x.git#%s"', '"rev": "%s",',
                  '      "revision" : "%s",', '"RemoteSha": "%s",', '      sha256: "%s"', '  :commit: %s',
                  '  "sentry": {:hex, :sentry, "10.0.0", "%s", [:mix], [], "hexpm", "0123"},')
        for line in public:
            self.assertTrue(sas.lockfile_identifier(finding(sha1), (line % sha1).encode("utf-8")), line)
        self.assertTrue(sas.lockfile_identifier(finding(sha1 * 3 + "deadbeef"), ("  checksum: 10c0/%s\n" % (sha1 * 3 + "deadbeef")).encode("utf-8")))
        self.assertTrue(sas.lockfile_identifier(finding(b64[10:50]), ('"contentHash": "%s"\n' % b64).encode("utf-8")))
        # an entry of a checksum section (Podfile.lock), a hashes block (.terraform.lock.hcl): the header vouches
        self.assertTrue(sas.lockfile_identifier(finding(sha1), ("SPEC CHECKSUMS:\n  Sentry: %s\n  Other: abc\n" % sha1).encode("utf-8")))
        self.assertTrue(sas.lockfile_identifier(finding(sha1), ('  hashes = [\n    "h1:abc=",\n    "zh:%s",\n  ]\n' % sha1).encode("utf-8")))
        self.assertTrue(sas.lockfile_identifier(finding(sha1), ("#x\nresolved \"https://a/b.tgz#%s\"\nresolved \"https://a/c.tgz#%s\"\n" % (sha1, sha1)).encode("utf-8")))   # every occurrence
        # a credential, whatever its shape; and a digest nobody vouches for stays a finding
        credentials = ('resolved "https://cloudflare:%s@npm.example.com/x.tgz"', 'tarball: https://npm.example.com/x.tgz?token=%s',
                       '"token": "%s"', '  password: %s', 'NPM_TOKEN = %s', 'https://%s@npm.example.com/x.tgz',
                       '"key": "%s"', '  Sentry: %s', '%s', '  value: %s', '"authToken": "%s"')
        for line in credentials:
            self.assertFalse(sas.lockfile_identifier(finding(sha1), (line % sha1).encode("utf-8")), line)
        self.assertFalse(sas.lockfile_identifier(finding(sha1), ("password:\n  %s\n" % sha1).encode("utf-8")))   # the header does not vouch
        self.assertFalse(sas.lockfile_identifier(finding(sha1), ("#x\nresolved \"https://a/b.tgz#%s\"\nkey: %s\n" % (sha1, sha1)).encode("utf-8")))   # once unvouched
        self.assertFalse(sas.lockfile_identifier(finding(sha1[:-1]), ('#%s"' % sha1[:-1]).encode("utf-8")))   # 39 digits: not a digest
        self.assertFalse(sas.lockfile_identifier(finding(sha1), ('resolved "https://a/b.tgz#%s"\nkey=%s\n' % (sha1, sha1)).encode("utf-8")))  # once as a value
        self.assertFalse(sas.lockfile_identifier(finding(sha1), b"nothing here\n"))
        self.assertFalse(sas.lockfile_identifier(finding(sha1), b""))
        for name in ("go.sum", "Podfile.lock", "Package.resolved", "deno.lock", "mix.lock", "yarn.lock"):
            self.assertTrue(sas.is_lockfile(name), name)

    def test_pinned_identifier(self):
        # outside lock files: a commit id or checksum in hex that a manifest vouches for
        sha1 = "2e85b818" + "17ebec4241b8f55ef1b62e4f150abcee"
        sha256 = "7452a46f185b7cc1e0a33b7b5bc3ecb9" + "4dc85968268cf63e08314caae3c96e2f"
        b64 = integrity_hash("sha512", "x")[len("sha512-"):]

        def finding(raw):
            return sas.Finding("x", 1, "CloudflareApiToken", raw, "", False, "PLAIN", {})

        public = ('    "cloudflare": "github:cloudflare/node-cloudflare#%s",',
                  '    "wrangler": "git+https://github.com/cloudflare/workers-sdk.git#%s",',
                  '    "sdk": "cloudflare/sdk#%s",', '"cloudflare/sdk": "dev-main#%s"',
                  '    "ssh": "git@github.com:cloudflare/ssh.git#%s",',
                  '  "gitHead": "%s",', '  "_shasum": "%s",', '    "shasum": "%s",', '"sha": "%s"',
                  '      - uses: cloudflare/wrangler-action@%s # v3', "      - uses: 'cloudflare/wrangler-action@%s'",
                  '    rev: %s', '      ref: %s', "gem 'cloudflare', git: 'https://github.com/cloudflare/x.git', ref: '%s'",
                  'cloudflare = { git = "https://github.com/cloudflare/cloudflare-rs", rev = "%s" }',
                  'git+https://github.com/cloudflare/python-cloudflare.git@%s#egg=cloudflare',
                  'source = "git::https://github.com/cloudflare/terraform-modules.git?ref=%s"',
                  '    commit = "%s",', 'GIT_COMMIT=%s', 'CLOUDFLARE_DEPLOY_SHA=%s',
                  'url = "https://x/y?token=abc"; ref = "%s"',   # the name of the field is ref, whatever came before the ;
                  '* cloudflare fix ([abc1234](https://github.com/cloudflare/x/commit/%s))')
        for line in public:
            self.assertTrue(sas.pinned_identifier(finding(sha1), (line % sha1).encode("utf-8")), line)
        self.assertTrue(sas.pinned_identifier(finding(sha256), ('    sha256 = "%s",\n' % sha256).encode("utf-8")))
        self.assertTrue(sas.pinned_identifier(finding(sha1), ('{"a": "github:cloudflare/a#%s", "b": "cloudflare/b#%s"}\n'
                                                              % (sha1, sha1)).encode("utf-8")))   # every occurrence
        # a credential, whatever its shape; a digest nobody vouches for; a base64 shape counts in lock files only
        credentials = ('"cloudflare_token": "%s"', 'CLOUDFLARE_API_TOKEN=%s', '  apiToken: %s', 'KEY=%s', '  password: %s',
                       'https://%s@github.com/cloudflare/x.git', 'https://npm.example.com/x.tgz?token=%s',
                       '"cloudflare": "%s"', 'Authorization: Bearer %s', '%s', '  value: %s', '"authToken": "%s"',
                       'PASSWORD_HASH=%s', '"secret_sha": "%s"', '  api_key_hash: %s', '"private_key_fingerprint": "%s"',
                       '{"cloudflare secret sha": "%s"}', '  api key sha: %s', "  'Cloudflare Auth Commit': '%s',")
        for line in credentials:
            self.assertFalse(sas.pinned_identifier(finding(sha1), (line % sha1).encode("utf-8")), line)
        self.assertFalse(sas.pinned_identifier(finding(sha1), ('"a": "github:cloudflare/a#%s", "key": "%s"\n' % (sha1, sha1)).encode("utf-8")))   # once unvouched
        self.assertFalse(sas.pinned_identifier(finding(sha1[:-1]), ('    rev: %s\n' % sha1[:-1]).encode("utf-8")))   # 39 digits: not a digest
        self.assertFalse(sas.pinned_identifier(finding(b64[10:50]), ('"contentHash": "%s"\n' % b64).encode("utf-8")))   # base64: lock files only
        self.assertTrue(sas.lockfile_identifier(finding(b64[10:50]), ('"contentHash": "%s"\n' % b64).encode("utf-8")))
        self.assertFalse(sas.pinned_identifier(finding(sha1), b"nothing here\n"))
        self.assertFalse(sas.pinned_identifier(finding(sha1), b""))

    def test_private_key_files_are_recognised_and_their_protection_read(self):
        root = tempfile.mkdtemp(prefix="sweep-keys-")
        try:
            def key(rel, content):
                data = content if isinstance(content, bytes) else content.encode("utf-8")
                path = os.path.join(root, rel.replace("/", os.sep))
                folder = os.path.dirname(path)
                if not os.path.isdir(folder):
                    os.makedirs(folder)
                with io.open(path, "wb") as fh:
                    fh.write(data)
                return sas.key_file_of(path, data)

            bare = key("deploy/id_ed25519", openssh_key_text(b"none", b"none"))
            self.assertEqual((bare.protection, bare.protected, bare.ssh_like, bare.in_ssh_dir), ((None, ""), False, True, False))
            self.assertEqual(sas.passphrase_text(bare), "none (OpenSSH format)")
            protected = key(".ssh/id_ed25519", openssh_key_text(b"aes256-ctr", b"bcrypt"))
            self.assertEqual((protected.protection, protected.protected, protected.in_ssh_dir), (("openssh", "aes256-ctr, bcrypt"), True, True))
            self.assertEqual(sas.passphrase_text(protected), "yes (OpenSSH format, aes256-ctr, bcrypt)")
            legacy = key("keys/old.pem", LEGACY_PEM_PROTECTED)
            self.assertEqual((legacy.protection, legacy.protected, legacy.ssh_like), (("legacy", "AES-128-CBC"), True, False))
            self.assertEqual(sas.passphrase_text(legacy), "yes, legacy PEM cipher (AES-128-CBC)")
            plain = key("keys/plain.pem", LEGACY_PEM_BARE)
            self.assertEqual((plain.protection, plain.protected, plain.ssh_like), ((None, ""), False, False))
            self.assertEqual(sas.passphrase_text(plain), "none (PEM)")
            with io.open(os.path.join(root, "keys", "plain.pem.pub"), "wb") as fh:   # a .pub beside it: ssh's
                fh.write(b"ssh-rsa AAAA x\n")
            self.assertTrue(key("keys/plain.pem", LEGACY_PEM_BARE).ssh_like)
            self.assertEqual(key("keys/p8.pem", PKCS8_PROTECTED).protection, ("pkcs8", ""))
            self.assertEqual(sas.passphrase_text(key("keys/p8.pem", PKCS8_PROTECTED)), "yes (PKCS#8)")
            self.assertEqual(sas.passphrase_text(key("docs/deploy_key.pem", PEM + "\n")), "none (PKCS#8)")
            bundle = key("certs/server.pem", CERT_BLOCK + LEGACY_PEM_BARE)   # a certificate with its key: the bare key counts
            self.assertEqual((bundle.labels, bundle.protection), ([b"CERTIFICATE", b"RSA PRIVATE KEY"], (None, "")))
            self.assertEqual(key("certs/mixed.pem", LEGACY_PEM_PROTECTED + LEGACY_PEM_BARE).protection, (None, ""))   # the weakest counts
            self.assertEqual(key("keys/crlf.pem", LEGACY_PEM_PROTECTED.replace("\n", "\r\n")).protection, ("legacy", "AES-128-CBC"))
            self.assertIsNotNone(key("keys/bom.pem", b"\xef\xbb\xbf" + LEGACY_PEM_BARE.encode("utf-8")))
            odd = key("keys/odd", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
            self.assertEqual(odd.protection[0], "unknown")
            self.assertFalse(odd.protected)
            self.assertTrue(sas.passphrase_text(odd).startswith("cannot tell: "))
            # not key files: a key inside other text, a certificate alone, a public key, text after the block, an empty file
            for rel, content in (("inventory.yml", "key: |\n" + LEGACY_PEM_BARE), ("cert.pem", CERT_BLOCK),
                                 ("id_ed25519.pub", "ssh-ed25519 AAAA x\n"), ("note.txt", LEGACY_PEM_BARE + "do not share\n"),
                                 ("empty", ""), ("sa.json", '{"private_key": "%s"}' % PEM.replace("\n", "\\n"))):
                self.assertIsNone(key(rel, content), rel)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_inside_archive_name_and_finding_field(self):
        line = (b'      "resolved": "https://registry.npmjs.org/@babel/helper-explode-assignable-expression/-/'
                b'helper-explode-assignable-expression-7.18.6.tgz",')
        run = b"-explode-assignable-expression-7"
        last = line.rfind(run)
        self.assertTrue(sas.inside_archive_name(line, last, last + len(run)))      # in the archive's file name
        first = line.find(run)
        self.assertTrue(sas.inside_archive_name(line, first, first + len(run)))    # in the segment that name repeats
        token = b"abcdefghijklmnopqrstuvwxyz012345"
        for text in (b'"resolved": "https://npm-proxy.fury.io/' + token + b'/org/pkg/-/pkg-1.0.0.tgz"',   # a segment of its own
                     b'"resolved": "https://npm.example.com/x/-/x-1.0.0.tgz?token=' + token + b'"',       # in the query
                     b'"resolved": "https://npm.example.com/' + token + b'/x-1.0.0.tgz"',                  # not repeated by the name
                     b'"url": "https://example.com/api/' + token + b'"',                                   # no archive name
                     b'"url": "https://example.com?token=/' + token + b'.zip"',                             # a slash in the query, no path
                     b'"url": "https://example.com#/' + token + b'.tgz"',                                   # a slash in the fragment
                     b'"key": "' + token + b'"'):                                                           # no URL at all
            pos = text.find(token)
            self.assertFalse(sas.inside_archive_name(text, pos, pos + len(token)), text)
        finding = sas.Finding("x", 1, "Signable", run.decode("ascii"), "", False, "PLAIN", {})
        self.assertTrue(sas.lockfile_identifier(finding, line + b"\n"))
        self.assertTrue(sas.pinned_identifier(finding, line + b"\n"))
        self.assertEqual(sas.finding_field(line + b"\n", finding), "resolved")

        def plain(raw):
            return sas.Finding("x", 1, "D", raw, "", False, "PLAIN", {})
        self.assertEqual(sas.finding_field(b'  resolved "https://x/-/x-1.0.0.tgz#abc"\n', plain("x-1.0.0")), "resolved")
        self.assertEqual(sas.finding_field(b"TOKEN=abc\n", plain("abc")), "TOKEN")
        self.assertEqual(sas.finding_field(b"  api_key: abc\n", plain("abc")), "api_key")
        self.assertEqual(sas.finding_field(b"    resolution: {tarball: https://npm.example.com/x.tgz?token=abc}\n", plain("abc")), "tarball")
        self.assertEqual(sas.finding_field(b'{"a": 1, "secret_sha": "abc"}\n', plain("abc")), "secret_sha")
        self.assertIsNone(sas.finding_field(b"just abc here\n", plain("abc")))
        self.assertIsNone(sas.finding_field(b"nothing\n", plain("abc")))
        # a field name that is itself a reported secret, or is suspiciously long, is masked in the listing and the log
        data = ('{"%s": "%s", "long%s": "%s"}\n' % (GITHUB_TOKEN, STRIPE_KEY, "x" * 60, STRIPE_KEY_2)).encode("utf-8")
        findings = [sas.Finding("x", 1, "Github", GITHUB_TOKEN, "", False, "PLAIN", {}),
                    sas.Finding("x", 1, "Stripe", STRIPE_KEY, "", False, "PLAIN", {}),
                    sas.Finding("x", 1, "Stripe", STRIPE_KEY_2, "", False, "PLAIN", {})]
        shown = sas.secrets_text(findings, lines=True, data=data)
        self.assertNotIn(GITHUB_TOKEN, shown)
        self.assertNotIn(STRIPE_KEY, shown)
        self.assertIn('in "%s"' % sas.mask(GITHUB_TOKEN), shown)          # the Stripe key sits under the token
        self.assertIn('in "%s"' % sas.mask("long" + "x" * 60), shown)      # the long name is cut as well
        self.assertNotIn("xxxxxxxxxx", shown)

    def test_current_patterns_and_base64_blobs(self):
        def finding(detector, raw):
            return sas.Finding("x", 1, detector, raw, "", False, "PLAIN", {})

        # a PagerDuty key is u+ and 18 characters since TruffleHog 3.60; anything else an old release reports is set aside
        self.assertIn("u+ and 18 characters", sas.current_pattern_rejects(finding("PagerDutyApiKey", "pager-item-active-xy"), None))
        self.assertIsNone(sas.current_pattern_rejects(finding("PagerDutyApiKey", "u+AbCdEfGhIjKlMnOpQr"), None))
        self.assertIsNone(sas.current_pattern_rejects(finding("CloudflareApiToken", "pager-item-active-xy"), None))   # no rule for it
        # a Signable match after the word assignable or designable, in the 40 characters the keyword window spans
        run = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"
        sig = finding("Signable", run)
        for text in ('export const isAssignable = (x) => x === "%s";\n', "designable-thing: %s\n", "Assignable %s\n"):
            self.assertIn("assignable or designable", sas.current_pattern_rejects(sig, (text % run).encode("utf-8")), text)
        for text in ("signable_key = %s\n", "Signable token: %s\n", "assignable and signable: %s\n", "x: %s\n"):
            self.assertIsNone(sas.current_pattern_rejects(sig, (text % run).encode("utf-8")), text)
        self.assertIsNone(sas.current_pattern_rejects(sig, None))   # without the file there is nothing to check
        # inside a base64 blob: a data: URI payload, or well inside a long run; not alone, at an edge, or with other characters
        payload = base64.b64encode(bytes(bytearray(range(96)))).decode("ascii")
        middle = payload[30:70]
        cf = finding("CloudflareApiToken", middle)
        self.assertTrue(sas.inside_base64_blob(cf, (".x{background:url(data:image/png;base64,%s)}\n" % payload).encode("utf-8")))
        self.assertTrue(sas.inside_base64_blob(finding("CloudflareApiToken", payload[:40]),
                                               ("src: url(data:font/woff2;base64,%s)\n" % payload).encode("utf-8")))   # at the payload's start
        self.assertTrue(sas.inside_base64_blob(cf, ("blob = \"%s\"\n" % payload).encode("utf-8")))
        self.assertFalse(sas.inside_base64_blob(finding("CloudflareApiToken", payload[:40]), ("blob = \"%s\"\n" % payload).encode("utf-8")))  # at the run's edge
        self.assertFalse(sas.inside_base64_blob(cf, ("KEY=%s\n" % middle).encode("utf-8")))                       # standing alone
        self.assertFalse(sas.inside_base64_blob(finding("CloudflareApiToken", payload[12:52]),
                                                ("KEY=%s\n" % payload[:64]).encode("utf-8")))   # most of a 64-character run: a long secret, not a blob
        self.assertFalse(sas.inside_base64_blob(cf, ("blob = \"%s\"\nKEY=%s\n" % (payload, middle)).encode("utf-8")))   # once outside
        self.assertFalse(sas.inside_base64_blob(finding("Github", "ghp_" + "A" * 36), ("blob = \"%s\"\n" % payload).encode("utf-8")))  # not found
        self.assertFalse(sas.inside_base64_blob(cf, b""))

    def test_inside_integrity_hash(self):
        aws = sas.Finding("x", 1, "AWS", AWS_ID, "", False, "PLAIN", {})
        inside = ('"integrity": "%s"\n' % integrity_hash("sha512", AWS_ID)).encode("utf-8")
        self.assertTrue(sas.inside_integrity_hash(aws, inside))
        gosum = ("mod v1 %s\n" % integrity_hash("h1", AWS_ID)).encode("utf-8")
        self.assertTrue(sas.inside_integrity_hash(aws, gosum))
        pip = ("--hash=sha256:%s\n" % ("ab" * 32)).encode("utf-8")
        hexish = sas.Finding("x", 1, "Generic", "ab" * 32, "", False, "PLAIN", {})
        self.assertTrue(sas.inside_integrity_hash(hexish, pip))
        # only a digest of its algorithm's exact length counts: a longer or shorter random string
        # with the same prefix may be anything, a credential included
        for algo in ("sha1", "sha256", "sha384", "sha512", "h1"):
            self.assertTrue(sas.inside_integrity_hash(aws, integrity_hash(algo, AWS_ID).encode("utf-8")), algo)
            for extra in (1, -1, 7):
                self.assertFalse(sas.inside_integrity_hash(aws, integrity_hash(algo, AWS_ID, extra).encode("utf-8")), algo)
        self.assertFalse(sas.inside_integrity_hash(hexish, ("sha256:%sab\n" % ("ab" * 32)).encode("utf-8")))   # 66 digits
        self.assertFalse(sas.inside_integrity_hash(hexish, ("sha256:%s\n" % ("ab" * 31)).encode("utf-8")))     # 62 digits
        self.assertTrue(sas.inside_integrity_hash(hexish, ("image@sha512:%s\n" % ("ab" * 64)).encode("utf-8")))
        sha1ish = sas.Finding("x", 1, "Generic", "ab" * 20, "", False, "PLAIN", {})
        self.assertTrue(sas.inside_integrity_hash(sha1ish, ("sha1:%s\n" % ("ab" * 20)).encode("utf-8")))
        self.assertFalse(sas.inside_integrity_hash(sha1ish, ("sha1:%sa\n" % ("ab" * 20)).encode("utf-8")))   # 41 digits
        self.assertFalse(sas.inside_integrity_hash(aws, ("key = %s\n" % AWS_ID).encode("utf-8")))
        self.assertFalse(sas.inside_integrity_hash(aws, inside + ("also %s\n" % AWS_ID).encode("utf-8")))  # once outside: a secret
        self.assertFalse(sas.inside_integrity_hash(aws, b"nothing here\n"))
        self.assertFalse(sas.inside_integrity_hash(aws, b""))

    def test_default_log_dir_honours_the_environment(self):
        saved = os.environ.get("SWEEP_AND_SECURE_LOG_DIR")
        try:
            os.environ["SWEEP_AND_SECURE_LOG_DIR"] = os.path.join("x", "logs")
            self.assertEqual(sas.default_log_dir(), os.path.join("x", "logs"))
            del os.environ["SWEEP_AND_SECURE_LOG_DIR"]
            self.assertTrue(sas.default_log_dir().endswith(os.path.join("sweep-and-secure", "logs")) or sys.platform == "darwin")
        finally:
            if saved is None:
                os.environ.pop("SWEEP_AND_SECURE_LOG_DIR", None)
            else:
                os.environ["SWEEP_AND_SECURE_LOG_DIR"] = saved

    def test_scan_progress_counts_and_draws(self):
        out = StringIO()
        progress = sas.ScanProgress(stream=out, is_tty=False, heartbeat=0)
        progress.saw_stderr(b'{"msg":"scanning file","path":"/a"}\n')
        progress.saw_stderr(b'{"msg":"scanning file","path":"/b"}\n')
        progress.saw_stderr(b'{"msg":"finished scanning"}\n')
        progress.saw_stdout(b'{"DetectorName":"AWS"}\n')
        progress.saw_stdout(b'not json\n')
        progress.tick()
        self.assertEqual((progress.files, progress.findings), (2, 1))
        self.assertIn("2 file(s), 1 finding(s) so far", out.getvalue())
        self.assertTrue(out.getvalue().endswith("\n"))                      # heartbeat lines
        tty = StringIO()
        progress = sas.ScanProgress(stream=tty, is_tty=True, heartbeat=0)
        progress.REDRAW = 0
        progress.tick()
        self.assertTrue(tty.getvalue().startswith("\r  scanning ..."))       # redrawn in place
        progress.finish()
        self.assertTrue(tty.getvalue().endswith("\r"))                        # and cleared
        sas.ScanProgress(stream=None).tick()                                   # silent mode never writes

    def test_run_streaming_delivers_lines_as_they_come(self):
        seen = []
        code, out, err = sas.run_streaming(
            [sys.executable, "-c", "import sys; print('{\"a\":1}'); sys.stderr.write('log\\n'); sys.exit(3)"],
            None, lambda line: seen.append(("out", line)), lambda line: seen.append(("err", line)), lambda: None)
        self.assertEqual(code, 3)
        self.assertEqual([l.strip() for l in out], [b'{"a":1}'])
        self.assertEqual([l.strip() for l in err], [b"log"])
        self.assertEqual(sorted(k for k, _ in seen), ["err", "out"])

    def test_set_keys_hint_names_the_keys_file_or_drops_the_hint(self):
        data = b'DOTENV_PUBLIC_KEY_PRODUCTION="02ab" # -fk ../.sweep-and-secure-x/.env.keys\nK=encrypted:x\n'
        self.assertEqual(sas.set_keys_hint(data, ".env.keys"), b'DOTENV_PUBLIC_KEY_PRODUCTION="02ab" # -fk .env.keys\nK=encrypted:x\n')
        self.assertEqual(sas.set_keys_hint(data, None), b'DOTENV_PUBLIC_KEY_PRODUCTION="02ab"\nK=encrypted:x\n')
        crlf = b'DOTENV_PUBLIC_KEY="02ab" # -fk x\r\nK=1\r\n'
        self.assertEqual(sas.set_keys_hint(crlf, None), b'DOTENV_PUBLIC_KEY="02ab"\r\nK=1\r\n')
        self.assertEqual(sas.set_keys_hint(b"no header\n", None), b"no header\n")
        self.assertEqual(sas.set_keys_hint(b'DOTENV_PUBLIC_KEY="02ab"\nK=1\n', ".env.keys"), b'DOTENV_PUBLIC_KEY="02ab" # -fk .env.keys\nK=1\n')

    def test_custody_decisions(self):
        folder = tempfile.mkdtemp(prefix="sweep-custody-")
        saved = dict(sas.DOTENVX_INFO)
        saved_ci = os.environ.pop("CI", None)   # the suite runs on CI too; this test wants a developer's machine first
        try:
            keys = os.path.join(folder, ".env.keys")
            with io.open(keys, "w", encoding="utf-8") as fh:
                fh.write(u'# keys\nDOTENV_PRIVATE_KEY="aa11"\nDOTENV_PRIVATE_KEY_PRODUCTION=bb22\nOTHER=x\n')
            self.assertEqual(sas.private_keys_from([keys, os.path.join(folder, "missing")]),
                             {"DOTENV_PRIVATE_KEY": "aa11", "DOTENV_PRIVATE_KEY_PRODUCTION": "bb22"})
            args = sas.parse_args(["--yes"])
            sas.DOTENVX_INFO.clear()
            sas.DOTENVX_INFO.update({"version": (2, 38, 0)})
            store = sas.native_store_name()
            if store:
                self.assertTrue(sas.native_store_wanted(args))
                self.assertEqual(sas.file_custody_reason(args), "the %s is not reachable here" % store)
                self.assertEqual(sas.file_custody_reason(args, "no secret-tool"), "no secret-tool")
            self.assertFalse(sas.native_store_wanted(sas.parse_args(["--yes", "--no-native"])))
            self.assertEqual(sas.file_custody_reason(sas.parse_args(["--no-native"])), "--no-native")
            os.environ["CI"] = "true"   # an ephemeral runner: keys stay in files, as dotenvx itself keeps them there
            self.assertFalse(sas.native_store_wanted(args))
            self.assertEqual(sas.file_custody_reason(args), "CI is set: keys stay in files there, as dotenvx itself does")
            del os.environ["CI"]
            sas.DOTENVX_INFO.update({"version": (2, 0, 0)})
            self.assertFalse(sas.native_store_wanted(args))
            if store:
                self.assertEqual(sas.file_custody_reason(args),
                                 "dotenvx 2.0.0 keeps keys in files; 2.3.0 or later can keep them in the %s" % store)
            os.environ["DOTENVX_NO_NATIVE"] = "true"
            try:
                sas.DOTENVX_INFO.update({"version": (2, 38, 0)})
                self.assertFalse(sas.native_store_wanted(args))
                self.assertEqual(sas.file_custody_reason(args), "DOTENVX_NO_NATIVE is set")
            finally:
                del os.environ["DOTENVX_NO_NATIVE"]
        finally:
            if saved_ci is not None:
                os.environ["CI"] = saved_ci
            sas.DOTENVX_INFO.clear()
            sas.DOTENVX_INFO.update(saved)
            shutil.rmtree(folder, ignore_errors=True)

    def test_cli_entry_point_returns_exit_codes(self):
        real_main = sas.main
        saved = sys.stderr
        try:
            sas.main = lambda argv=None: 0
            self.assertEqual(sas.cli([]), 0)

            def interrupted(argv=None):
                raise KeyboardInterrupt()
            sas.main = interrupted
            sys.stderr = StringIO()
            self.assertEqual(sas.cli([]), 130)
            self.assertIn("Interrupted", sys.stderr.getvalue())
        finally:
            sas.main = real_main
            sys.stderr = saved

    @unittest.skipUnless(sys.version_info >= (3, 11), "tomllib")
    def test_pyproject_console_script_points_at_a_real_function(self):
        import tomllib
        with io.open(os.path.join(REPO, "pyproject.toml"), "rb") as fh:
            project = tomllib.load(fh)["project"]
        module, function = project["scripts"]["sweep-and-secure"].split(":")
        self.assertEqual(module, "sweep_and_secure")
        self.assertTrue(callable(getattr(sas, function)))
        self.assertEqual(project["dynamic"], ["version"])

    def test_mask_never_reveals_much(self):
        self.assertEqual(sas.mask(STRIPE_KEY), "sk_l...23")
        self.assertEqual(sas.mask("tenchars!!"), "te...!")
        self.assertEqual(sas.mask("short"), "***")
        self.assertEqual(sas.mask(PEM), "----...--")

    def test_finding_from_json_accepts_relative_paths(self):
        obj = {"SourceMetadata": {"Data": {"Filesystem": {"file": "src/a.py", "line": 3}}},
               "DetectorName": "AWS", "Raw": AWS_ID, "RawV2": "", "Verified": True, "DecoderName": "PLAIN"}
        finding = sas.Finding.from_json(obj, os.path.join(os.sep, "root"))
        self.assertEqual(finding.path, os.path.join(os.sep, "root", "src", "a.py"))
        self.assertEqual((finding.line, finding.detector, finding.verified), (3, "AWS", True))
        self.assertIsNone(sas.Finding.from_json({"SourceMetadata": {"Data": {"Git": {"commit": "x"}}}}, "/r"))


REAL_TOOLS = os.environ.get("SWEEP_TEST_REAL_TOOLS") and sas.which("trufflehog") and sas.which("dotenvx")


@unittest.skipUnless(REAL_TOOLS, "set SWEEP_TEST_REAL_TOOLS=1 with trufflehog and dotenvx on PATH")
class RealToolsTests(unittest.TestCase):
    """The same script against the real TruffleHog and dotenvx. The real TruffleHog
    does not flag the test fixture's toy PEM key or GitHub token, so these tests
    only assert on the credentials it does detect."""

    def setUp(self):
        self.tree = ProjectTree()
        self.tree.write("config/.env.staging", ("STRIPE_KEY=%s\n" % STRIPE_KEY_2).encode("utf-8"))
        self.tree.write(".env", ("PORT=3000\nSTRIPE_SECRET_KEY=%s\nDB_PASSWORD=%s\nPOSTGRES_PASSWORD=%s\n"
                                 % (STRIPE_KEY, STRIPE_KEY_2, STRIPE_KEY_2)).encode("utf-8"))
        self.path = os.pathsep.join(p for p in os.environ.get("PATH", "").split(os.pathsep) if p != FAKEBIN)
        self.dotenvx = sas.which("dotenvx")

    def tearDown(self):
        self.tree.cleanup()

    def get(self, key, env_file=".env", keys_file=None):
        return dotenvx_get(self.tree.root, key, env_file, keys_file, binary=self.dotenvx)

    def test_full_run_round_trips_and_reruns_cleanly(self):
        code, first, err = run_script(self.tree.root, ["--yes", "--no-rewrite"], path=self.path)
        self.assertEqual(code, 0, first + err)
        # the nested env file was encrypted by this first run, so its advice is printed here
        self.assertIn("dotenvx run -f config/.env.staging -- <your command>", first)
        code, out, err = run_script(self.tree.root, ["--yes"], path=self.path)
        self.assertEqual(code, 0, out + err)
        env = self.tree.read(".env")
        for secret in (STRIPE_KEY, STRIPE_KEY_2, AWS_ID, AWS_SECRET, SLACK, PG_URL):
            self.assertNotIn(secret, env)
            self.assertNotIn(secret, self.tree.read("src/settings.py") + self.tree.read("config/app.json"))
        self.assertNotIn("_2=", env)
        for key, want in (("STRIPE_SECRET_KEY", STRIPE_KEY), ("DB_PASSWORD", STRIPE_KEY_2),
                          ("POSTGRES_PASSWORD", STRIPE_KEY_2), ("AWS_ACCESS_KEY_ID", AWS_ID),
                          ("AWS_SECRET_ACCESS_KEY", AWS_SECRET), ("DATABASE_URL", PG_URL), ("SLACK_WEBHOOK", SLACK)):
            self.assertEqual(self.get(key), want, key)
        self.assertEqual(self.get("STRIPE_KEY", "config/.env.staging", "config/.env.keys"), STRIPE_KEY_2)
        self.assertIn("(value already in .env)", out)   # the re-run recognised the stored values
        self.assertIn('AWS_ACCESS_KEY_ID = "${AWS_ACCESS_KEY_ID}"', self.tree.read("src/settings.py"))
        self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
        self.assertIn(".env.keys*", self.tree.read(".gitignore"))
        self.assertEqual(self.tree.leftovers(), [])

    def test_dry_run_shows_what_is_inside_the_archives(self):
        # a tar.gz member too: the real TruffleHog looks inside it, and the listing names the file
        self.tree.write("build/site.tar.gz", b"")
        with tarfile.open(self.tree.path("build/site.tar.gz"), "w:gz") as tf:
            data = ("hook: %s\n" % SLACK).encode("utf-8")
            info = tarfile.TarInfo("etc/hooks.yml")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        code, out, err = run_script(self.tree.root, ["--dry-run"], path=self.path)
        self.assertEqual(code, 0, out + err)
        # the toy GitHub token in blob.txt.gz is not something the real TruffleHog flags
        self.assertTrue(re.search(r"Files holding secrets that cannot be fixed in place: [23]", out), out)
        self.assertIn("tar.gz: etc/hooks.yml", out)
        self.assertIn("etc/hooks.yml", out)
        self.assertIn("SlackWebhook http", out)
        self.assertIn("zip: config/prod.env", out)
        self.assertIn("config/prod.env", out)
        self.assertIn("Stripe sk_l", out)
        self.assertIn("move to .secrets-quarantine/build/keys.zip", out)

    def test_check_setup_passes_with_the_real_tools(self):
        code, out, err = run_script(self.tree.root, ["--check-setup"], path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertIn("[ok] trufflehog  3.", out)
        self.assertIn("[ok] dotenvx ", out)
        self.assertIn("trufflehog  ran in a scratch folder: exit status 0, 1 file(s) scanned, no findings", out)
        self.assertIn("dotenvx     ran in a scratch folder: encrypted a value, decrypted it back; the private key went to", out)
        self.assertIn("Setup looks good", out)
        self.assertEqual(self.tree.leftovers(), [])

    def test_lock_file_checksums_next_to_vendor_names_are_set_aside(self):
        # measured: every real TruffleHog from 3.0 to 3.99 reports CloudflareApiToken for the sha1 URL
        # fragment of a package called cloudflare in yarn.lock, and SentryToken for sentry's checksum in mix.lock
        sha1 = "2e85b818" + "17ebec4241b8f55ef1b62e4f150abcee"
        sha256 = "7452a46f185b7cc1e0a33b7b5bc3ecb9" + "4dc85968268cf63e08314caae3c96e2f"
        self.tree.write("yarn.lock", ('# yarn lockfile v1\n\n\ncloudflare@^1.0.0:\n  version "1.0.0"\n'
                                      '  resolved "https://registry.yarnpkg.com/cloudflare/-/cloudflare-1.0.0.tgz#%s"\n'
                                      '  integrity %s\n' % (sha1, integrity_hash("sha512", "cf"))).encode("utf-8"))
        self.tree.write("mix.lock", ('%%{\n  "sentry": {:hex, :sentry, "10.0.0", "%s", [:mix], [], "hexpm", "%s"},\n}\n'
                                     % (sha256, sha256[::-1])).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"], path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertRegex(out, r"Set aside [1-9]\d* finding\(s\) that are package integrity hashes")
        self.assertNotIn("generated lock file", out)
        self.assertNotIn("yarn.lock", out)
        self.assertNotIn("mix.lock", out)

    def test_commit_pins_in_manifests_are_set_aside_by_the_real_trufflehog(self):
        # measured: every real TruffleHog from 3.6 to 3.99 reports CloudflareApiToken for a dependency called
        # cloudflare pinned to a commit in package.json, for a gitHead under a @cloudflare name, for an action
        # pinned to a commit and for a rev field; the newest releases no less than the old ones
        shas = [hashlib.sha1(("real pin %d" % i).encode("utf-8")).hexdigest() for i in range(5)]
        self.tree.write("package.json", json.dumps({
            "name": "@cloudflare/demo", "gitHead": shas[0], "version": "1.0.0",
            "dependencies": {"cloudflare": "github:cloudflare/node-cloudflare#%s" % shas[1],
                             "wrangler": "git+https://github.com/cloudflare/workers-sdk.git#%s" % shas[2]}},
            indent=2).encode("utf-8"))
        self.tree.write(".github/workflows/deploy.yml", ("on: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
                                                        "      - uses: cloudflare/wrangler-action@%s # v3\n" % shas[3]).encode("utf-8"))
        self.tree.write("Cargo.toml", ('[dependencies]\ncloudflare = { git = "https://github.com/cloudflare/cloudflare-rs", rev = "%s" }\n'
                                       % shas[4]).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"], path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertRegex(out, r"Set aside [1-9]\d* finding\(s\) that are package integrity hashes")
        for name in ("package.json", "deploy.yml", "Cargo.toml"):
            self.assertNotIn(name, out)

    def test_private_key_files_with_the_real_trufflehog(self):
        # measured: TruffleHog 3.40 to 3.99 report an RSA key in the PEM and PKCS#8 forms, a legacy-encrypted PEM key
        # with ExtraData encrypted=true (its text not verbatim: the blank line after DEK-Info is dropped) and an
        # OpenSSH-format key with or without a passphrase; never a PKCS#8 ENCRYPTED PRIVATE KEY or a toy key
        openssl = shutil.which("openssl", path=self.path)
        if not openssl:
            self.skipTest("no openssl on PATH")

        def make(rel, command):
            path = self.tree.path(rel)
            folder = os.path.dirname(path)
            if not os.path.isdir(folder):
                os.makedirs(folder)
            proc = subprocess.Popen([c.replace("PATH", path) for c in command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _, err = proc.communicate()
            if proc.returncode != 0 or not os.path.isfile(path):
                self.skipTest("%s could not make a key: %s" % (command[0], err.decode("utf-8", "replace")[:200]))

        make("deploy/legacy.pem", [openssl, "genrsa", "-traditional", "-out", "PATH", "2048"])
        make("deploy/service.pem", [openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "PATH"])
        make(".ssh/id_rsa_old", [openssl, "genrsa", "-traditional", "-aes256", "-passout", "pass:correct horse", "-out", "PATH", "2048"])
        keygen = shutil.which("ssh-keygen", path=self.path)
        if keygen:
            make("deploy/id_ed25519", [keygen, "-q", "-t", "ed25519", "-N", "", "-f", "PATH"])
            make(".ssh/id_ed25519", [keygen, "-q", "-t", "ed25519", "-N", "correct horse", "-f", "PATH"])
        originals = dict((rel, self.tree.read_bytes(rel)) for rel in ("deploy/legacy.pem", "deploy/service.pem", ".ssh/id_rsa_old"))
        code, out, err = run_script(self.tree.root, ["--dry-run"], path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertIn("Private key files: %d" % (5 if keygen else 3), out)
        self.assertRegex(out, r"\d+\s+deploy/legacy\.pem\s+none \(PEM\)\s+move to \.secrets-quarantine/deploy/legacy\.pem\.enc")
        self.assertRegex(out, r"\d+\s+deploy/service\.pem\s+none \(PKCS#8\)\s+move to \.secrets-quarantine/deploy/service\.pem\.enc")
        self.assertRegex(out, r"-\s+\.ssh/id_rsa_old\s+yes, legacy PEM cipher \(AES-256-CBC\)\s+left as it is; upgrade its passphrase")
        self.assertIn("ssh-keygen -p -o -a 100 -f deploy/legacy.pem", out)
        self.assertIn("ssh-keygen -p -o -a 100 -f .ssh/id_rsa_old", out)
        if keygen:
            self.assertRegex(out, r"\d+\s+deploy/id_ed25519\s+none \(OpenSSH format\)\s+move to")
            self.assertRegex(out, r"-\s+\.ssh/id_ed25519\s+yes \(OpenSSH format, aes256-ctr, bcrypt\)\s+left as it is")
            self.assertIn("ssh-keygen -p -a 100 -f deploy/id_ed25519", out)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"], path=self.path)
        self.assertEqual(code, 0, out + err)
        for rel in ("deploy/legacy.pem", "deploy/service.pem") + (("deploy/id_ed25519",) if keygen else ()):
            self.assertFalse(os.path.exists(self.tree.path(rel)), rel)
            self.assertTrue(os.path.isfile(self.tree.path(".secrets-quarantine/" + rel + ".enc")), rel)
        self.assertEqual(self.tree.read_bytes(".ssh/id_rsa_old"), originals[".ssh/id_rsa_old"])
        code, out, err = run_script(self.tree.root, ["--restore", "deploy/legacy.pem"], path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.tree.read_bytes("deploy/legacy.pem"), originals["deploy/legacy.pem"])
        self.assertEqual(self.tree.leftovers(), [])

    def test_quarantined_files_are_encrypted_with_the_real_openssl_and_come_back(self):
        openssl = shutil.which("openssl", path=self.path)
        if not openssl:
            self.skipTest("no openssl on PATH")
        original = self.tree.read_bytes("build/keys.zip")
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"], path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertIn("build/keys.zip: moved to .secrets-quarantine/build/keys.zip.enc (encrypted)", out)
        self.assertIn(".secrets-quarantine/.env holds the quarantine's passphrases, encrypted to the key pair of .env", out)
        record = quarantine_record(self.tree, "build/keys.zip")
        self.assertEqual((record["encrypted"], record["cipher"], record["kdf"]), (True, "aes-256-cbc", "pbkdf2"))
        self.assertEqual(record["sha256"], hashlib.sha256(original).hexdigest())
        self.assertNotIn(STRIPE_KEY.encode("utf-8"), self.tree.read_bytes(".secrets-quarantine/build/keys.zip.enc"))
        self.assertFalse(os.path.exists(self.tree.path(".secrets-quarantine/.env.keys")))   # the .env key pair serves
        # the hand recipe from MANIFEST.txt, run as written from inside the folder
        back = os.path.join(self.tree.root, "keys.zip.back")
        recipe = ("%s get %s -f .env -fk ../.env.keys | %s enc -d -aes-256-cbc -pbkdf2 -pass stdin -in %s -out %s"
                  % (self.dotenvx, record["key"], openssl, record["quarantined"], back))
        subprocess.check_call(recipe, shell=True, cwd=self.tree.path(".secrets-quarantine"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with io.open(back, "rb") as fh:
            self.assertEqual(fh.read(), original)
        # and --restore does the same by itself
        code, out, err = run_script(self.tree.root, ["--restore", "build/keys.zip"], path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.tree.read_bytes("build/keys.zip"), original)
        self.assertFalse(os.path.exists(self.tree.path(".secrets-quarantine/build/keys.zip.enc")))
        self.assertEqual(self.tree.leftovers(), [])

    def test_an_earlier_plaintext_quarantine_is_encrypted_in_place_by_a_later_run(self):
        if not shutil.which("openssl", path=self.path):
            self.skipTest("no openssl on PATH")
        original = self.tree.read_bytes("build/keys.zip")
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine", "--openssl", os.path.join(self.tree.root, "none")],
                                    path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(quarantine_record(self.tree, "build/keys.zip")["encrypted"], False)
        code, out, err = run_script(self.tree.root, ["--yes", "--quarantine"], path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertIn("[ok] .secrets-quarantine/build/keys.zip: encrypted in place as build/keys.zip.enc", out)
        record = quarantine_record(self.tree, "build/keys.zip")
        self.assertEqual((record["quarantined"], record["encrypted"], record["kdf"]), ("build/keys.zip.enc", True, "pbkdf2"))
        self.assertNotIn(STRIPE_KEY_2.encode("utf-8"), self.tree.read_bytes(".secrets-quarantine/build/keys.zip.enc"))
        self.assertFalse(os.path.exists(self.tree.path(".secrets-quarantine/build/keys.zip")))
        code, out, err = run_script(self.tree.root, ["--restore", "build/keys.zip"], path=self.path)
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.tree.read_bytes("build/keys.zip"), original)

    def test_quoting_round_trips_through_real_dotenvx(self):
        values = {"PLAIN": "pa$$word${HOME} #x", "PEM": PEM, "APOS": "it's#a$ecret", "APOS_TICK": "it's `x` $HOME",
                  "APOS_DQ": "it's \"q\" $y", "UNI": u"p\u00e4ss \u2713"}
        lines = []
        for key, value in values.items():
            quoted, exact = sas.quote_env_value(value)
            self.assertTrue(exact, key)
            lines.append(u"%s=%s" % (key, quoted))
        self.tree.write("quoting.env", (u"\n".join(lines) + u"\n").encode("utf-8"))
        cmd = [self.dotenvx, "encrypt", "-f", "quoting.env"] + sum([["-k", k] for k in values], [])
        subprocess.check_call(cmd, cwd=self.tree.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for key, value in values.items():
            self.assertEqual(self.get(key, "quoting.env"), value, key)


if __name__ == "__main__":
    unittest.main()
