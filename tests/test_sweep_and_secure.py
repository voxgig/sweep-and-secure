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

import gzip
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

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
              "FAKE_TRUFFLEHOG_FAIL", "FAKE_TRUFFLEHOG_PARTIAL", "FAKE_DOTENVX_VERSION")


def clean_env(extra_env=None, path=None):
    env = dict(os.environ)
    env["PATH"] = (FAKEBIN + os.pathsep + env.get("PATH", "")) if path is None else path
    env["NO_COLOR"] = "1"
    for name in FAKE_KNOBS:
        env.pop(name, None)
    if extra_env:
        env.update(extra_env)
    return env


def run_script(root, args, stdin_text="", extra_env=None, path=None):
    env = clean_env(extra_env, path)
    proc = subprocess.Popen([sys.executable, SCRIPT, root] + list(args), cwd=root, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(stdin_text.encode("utf-8"))
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def dotenvx_get(root, key, env_file=".env", keys_file=None, binary=None):
    """What dotenvx (the stand-in by default) decrypts for key; --overload makes the
    file win over our own environment, as the script does when it verifies."""
    cmd = [sys.executable, FAKE_DOTENVX] if binary is None else [binary]
    cmd += ["get", key, "-f", env_file, "--overload"]
    if keys_file:
        cmd += ["-fk", keys_file]
    proc = subprocess.Popen(cmd, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate()
    out = out.decode("utf-8")
    return out[:-1] if out.endswith("\n") else out


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

    def test_too_old_dotenvx_is_rejected(self):
        code, out, err = run_script(self.tree.root, ["--dry-run"], extra_env={"FAKE_DOTENVX_VERSION": "0.44.1"})
        self.assertEqual(code, 1)
        self.assertIn("too old", err)
        self.assertIn("https://dotenvx.com", err)

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
        self.assertIn("Plaintext secrets found: 11 in 8 file(s)", out)
        for needle in ("Stripe", "STRIPE_SECRET_KEY", "encrypt in place",
                       "AWS", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                       "Postgres", "DATABASE_URL", "SlackWebhook", "SLACK_WEBHOOK",
                       "PrivateKey", PEM_KEY, "Github", "GITHUB_TOKEN", "src/settings.py:2",
                       "config/service_account.json:3", "docs/db.md:1"):
            self.assertIn(needle, out)
        self.assertIn("Already encrypted with dotenvx", out)
        self.assertIn("DB_PASSWORD", out)
        self.assertIn("config/.env.production", out)
        self.assertIn("build/blob.txt.gz", out)          # archive: listed as not fixable
        self.assertIn("binary or archive", out)
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
        self.assertIn("Encrypt these 11 secret(s) now?", out)
        self.assertIn("Nothing encrypted", out)
        self.assertUnchanged()

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
        self.assertEqual(self.tree.read("docs/deploy_key.pem"), "${%s}\n" % PEM_KEY)
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
        self.assertUnchanged("node_modules/pkg/.env", "build/blob.txt.gz", "config/.env.production")
        self.assertIn("Done: 7 secret(s) stored encrypted; 11 plaintext occurrence(s) removed from 7 file(s);"
                      " 1 need manual attention", out)
        self.assertIn("Next steps", out)
        self.assertIn("dotenvx run -- <your command>", out)
        self.assertNotIn("-fk", out)                     # .env and .env.keys share a folder
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
        # dotenvx keeps the private key in the swept folder and only looks next to the env
        # file on its own, so the advice must say where the key is
        self.assertIn("dotenvx run -f config/secrets.env -fk .env.keys -- <your command>", out)
        self.assertIn("-fk points it at the one it wrote", out)
        self.assertEqual(dotenvx_get(self.tree.root, "AWS_ACCESS_KEY_ID", "config/secrets.env", ".env.keys"), AWS_ID)
        self.assertTrue(dotenvx_get(self.tree.root, "AWS_ACCESS_KEY_ID", "config/secrets.env").startswith("encrypted:"))

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
        self.assertIn("dotenvx cannot store this value exactly (it contains both an apostrophe and a backslash)", out)
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

    def test_example_env_files_are_left_for_manual_attention(self):
        self.tree.write(".env.example", ("STRIPE_SECRET_KEY=%s\nPORT=1\n" % STRIPE_KEY).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run", "--env-all"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("example/template env file", out)
        self.assertNotIn(".env.example:1", out)          # not a numbered item
        self.assertNotIn(".env.example: PORT", out)      # not in the --env-all inventory either

    def test_lock_files_and_pdfs_are_left_for_manual_attention(self):
        self.tree.write("package-lock.json", ('{"resolved": "https://npm.pkg.github.com/x?token=%s"}\n'
                                              % GITHUB_TOKEN).encode("utf-8"))
        self.tree.write("docs/report.pdf", ("%%PDF-1.4 token %s\n" % GITHUB_TOKEN).encode("utf-8"))
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("generated lock file", out)
        self.assertIn("PDF - rewriting bytes would corrupt it", out)

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

    def test_nothing_found_is_a_clean_exit(self):
        clean = tempfile.mkdtemp(prefix="sweep-clean-")
        try:
            with io.open(os.path.join(clean, "readme.txt"), "wb") as fh:
                fh.write(b"nothing to see here\n")
            code, out, err = run_script(clean, [])
            self.assertEqual(code, 0, out + err)
            self.assertIn("no plaintext secrets", out)
            self.assertIn("Nothing to encrypt", out)
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
            self.assertEqual((plan.ignored, plan.items, plan.skipped), (1, [], []))
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

    def test_fix_keys_hint_repoints_at_the_same_keys_file(self):
        staged = os.path.join(os.sep, "proj", ".sweep-and-secure-x")
        data = b'DOTENV_PUBLIC_KEY_PRODUCTION="02ab" # -fk ../.env.keys\nK=encrypted:x\n'
        fixed = sas.fix_keys_hint(data, staged, os.path.join(os.sep, "proj", "config"))
        self.assertEqual(fixed, b'DOTENV_PUBLIC_KEY_PRODUCTION="02ab" # -fk ../.env.keys\nK=encrypted:x\n')
        fixed = sas.fix_keys_hint(data, staged, os.path.join(os.sep, "proj"))
        self.assertEqual(fixed, b'DOTENV_PUBLIC_KEY_PRODUCTION="02ab" # -fk .env.keys\nK=encrypted:x\n')
        self.assertEqual(sas.fix_keys_hint(b"no hint here\n", staged, os.sep), b"no hint here\n")

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
        self.assertIn("dotenvx run -f config/.env.staging -fk .env.keys -- <your command>", first)
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
        self.assertEqual(self.get("STRIPE_KEY", "config/.env.staging", ".env.keys"), STRIPE_KEY_2)
        self.assertIn("(value already in .env)", out)   # the re-run recognised the stored values
        self.assertIn('AWS_ACCESS_KEY_ID = "${AWS_ACCESS_KEY_ID}"', self.tree.read("src/settings.py"))
        self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
        self.assertIn(".env.keys*", self.tree.read(".gitignore"))
        self.assertEqual(self.tree.leftovers(), [])

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
