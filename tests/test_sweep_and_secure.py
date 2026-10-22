# -*- coding: utf-8 -*-
"""Tests for sweep_and_secure.py.

The end-to-end tests run the script as a subprocess against a throw-away project
tree, with the stand-ins for trufflehog and dotenvx from tests/fakebin on the
PATH, so neither real tool is needed. Works on Python 2.7 and 3.x:

    python -m unittest discover -s tests -v
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

sys.path.insert(0, REPO)
import sweep_and_secure as sas  # noqa: E402

# Realistic-looking but entirely made-up credentials. They are assembled from
# fragments at run time so that this file itself never contains a secret-shaped
# string: neither GitHub's push protection nor a TruffleHog sweep of this very
# repository should trip over the test-suite.
GITHUB_TOKEN = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dcXYZ123"
AWS_ID = "AKIA" + "QYLPMN5HHHFPZAM2"
AWS_SECRET = "1tUm636uS1yOEcfP5pvfqJ/" + "ml36mF7AkyHsEU0IU"
SLACK = "https://hooks.slack.com/" + "services/T0A1B2C3D4/B0E5F6G7H8/aBcDeFgHiJkLmNoPqRsTuVwX"
PG_URL = "postgres://" + "admin:SuperSecretPassw0rd@db-prod.acme-corp.io:5432/app"
PEM = ("-----BEGIN " + "PRIVATE KEY-----\n"
       "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n"
       "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
       "-----END " + "PRIVATE KEY-----")
PEM_KEY = "PRIVATE_KEY_" + hashlib.sha256(PEM.encode("utf-8")).hexdigest()[:6].upper()

FILES = {
    ".env": "PORT=3000\nSTRIPE_SECRET_KEY=%s\nAPP_NAME=demo\n" % STRIPE_KEY,
    ".gitignore": "node_modules/\n",
    "config/.env.production": 'DOTENV_PUBLIC_KEY="02abc"\nDB_PASSWORD="encrypted:QUJD"\nLOG_LEVEL=info\n',
    "config/app.json": '{\n  "name": "demo",\n  "slack_webhook": "%s"\n}\n' % SLACK,
    "src/settings.py": ('DEBUG = True\nAWS_ACCESS_KEY_ID = "%s"\nAWS_SECRET_ACCESS_KEY = "%s"\n'
                        'DATABASE_URL = "%s"\n' % (AWS_ID, AWS_SECRET, PG_URL)),
    "src/client.js": "const token = '%s';\nconst stripe = require('stripe')('%s');\n" % (GITHUB_TOKEN, STRIPE_KEY),
    "docs/notes.md": "# Notes\n\nAlerts go to %s for now.\n" % SLACK,
    "docs/deploy_key.pem": PEM + "\n",
    "node_modules/pkg/.env": "TOKEN=%s\n" % GITHUB_TOKEN,
}


class ProjectTree(object):
    """A temporary project folder seeded with planted secrets."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="sweep-test-")
        os.mkdir(os.path.join(self.root, ".git"))
        for rel, content in FILES.items():
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

    def snapshot(self):
        files = {}
        for dirpath, _, filenames in os.walk(self.root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                with io.open(path, "rb") as fh:
                    files[os.path.relpath(path, self.root)] = fh.read()
        return files

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def run_script(root, args, stdin_text="", extra_env=None, path=None):
    env = dict(os.environ)
    env["PATH"] = (FAKEBIN + os.pathsep + env.get("PATH", "")) if path is None else path
    env["NO_COLOR"] = "1"
    for name in ("TRUFFLEHOG_BIN", "DOTENVX_BIN", "FAKE_DOTENVX_FAIL", "FAKE_DOTENVX_NOOP",
                 "FAKE_TRUFFLEHOG_FAIL", "FAKE_DOTENVX_VERSION"):
        env.pop(name, None)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen([sys.executable, SCRIPT, root] + list(args), cwd=root, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(stdin_text.encode("utf-8"))
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def fake_dotenvx_get(root, key, env_file=".env"):
    proc = subprocess.Popen([os.path.join(FAKEBIN, "dotenvx"), "get", key, "-f", env_file], cwd=root,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate()
    return out.decode("utf-8")[:-1]  # drop the trailing newline print() adds


def item_number(listing, detector, key, where=None):
    """The '#' of the listed item for detector/key (optionally restricted to a location)."""
    for line in listing.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)", line)
        if match and match.group(2) == detector and match.group(3) == key:
            if where is None or where in match.group(4):
                return match.group(1)
    raise AssertionError("no listed item for %s %s in:\n%s" % (detector, key, listing))


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

    def test_dry_run_lists_findings_with_types_and_already_encrypted_keys(self):
        code, out, err = run_script(self.tree.root, ["--dry-run"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("Plaintext secrets found: 9", out)
        for needle in ("Stripe", "STRIPE_SECRET_KEY", "encrypt in place",
                       "AWS", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                       "Postgres", "DATABASE_URL", "SlackWebhook", "SLACK_WEBHOOK",
                       "PrivateKey", PEM_KEY, "Github", "GITHUB_TOKEN", "src/settings.py:2"):
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
        self.assertIn("Encrypt these 9 secret(s) now?", out)
        self.assertIn("Nothing encrypted", out)
        self.assertUnchanged()

    def test_yes_encrypts_env_files_in_place_and_moves_other_secrets(self):
        code, out, err = run_script(self.tree.root, ["--yes"])
        self.assertEqual(code, 0, out + err)
        env = self.tree.read(".env")
        self.assertNotIn(STRIPE_KEY, env)
        self.assertIn("PORT=3000", env)                  # unflagged key left alone
        for key in ("STRIPE_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                    "DATABASE_URL", "SLACK_WEBHOOK", "GITHUB_TOKEN", PEM_KEY):
            self.assertTrue(re.search(r'^%s="encrypted:' % re.escape(key), env, re.M), key + "\n" + env)
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
        # decrypt round trip through the stand-in, including the multi-line and extended values
        self.assertEqual(fake_dotenvx_get(self.tree.root, "AWS_SECRET_ACCESS_KEY"), AWS_SECRET)
        self.assertEqual(fake_dotenvx_get(self.tree.root, "DATABASE_URL"), PG_URL)
        self.assertEqual(fake_dotenvx_get(self.tree.root, PEM_KEY), PEM)
        self.assertEqual(fake_dotenvx_get(self.tree.root, "STRIPE_SECRET_KEY"), STRIPE_KEY)
        self.assertTrue(os.path.isfile(self.tree.path(".env.keys")))
        self.assertIn(".env.keys*", self.tree.read(".gitignore"))
        self.assertUnchanged("node_modules/pkg/.env", "build/blob.txt.gz", "config/.env.production")
        self.assertIn("Done: 9 secret(s) encrypted, 1 need manual attention", out)
        self.assertIn("Next steps", out)
        self.assertIn("dotenvx run -- <your command>", out)
        self.assertIn("howtorotate.com/docs/tutorials/stripe/", out)

    def test_select_a_single_item(self):
        _, listing, _ = run_script(self.tree.root, ["--dry-run"])
        number = item_number(listing, "AWS", "AWS_SECRET_ACCESS_KEY")
        code, out, err = run_script(self.tree.root, [], stdin_text="s\n%s\ny\n" % number)
        self.assertEqual(code, 0, out + err)
        settings = self.tree.read("src/settings.py")
        self.assertIn("${AWS_SECRET_ACCESS_KEY}", settings)
        self.assertIn(AWS_ID, settings)                  # not selected: left in place
        env = self.tree.read(".env")
        self.assertIn('AWS_SECRET_ACCESS_KEY="encrypted:', env)
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
        self.assertEqual(fake_dotenvx_get(self.tree.root, "SLACK_WEBHOOK"), SLACK)
        self.assertIn("${SLACK_WEBHOOK}", self.tree.read("docs/notes.md"))
        self.assertUnchanged("config/app.json", "src/settings.py")

    def test_bad_selection_input_is_rejected(self):
        code, out, err = run_script(self.tree.root, [], stdin_text="maybe\ns\n0 99\n\nn\n")
        self.assertEqual(code, 2, out + err)
        self.assertIn("Please answer y (yes), n (no) or s (select)", out)
        self.assertIn("Could not understand", out)
        self.assertUnchanged()

    def test_dotenvx_failure_restores_env_file_and_leaves_sources_alone(self):
        code, out, err = run_script(self.tree.root, ["--yes"], extra_env={"FAKE_DOTENVX_FAIL": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("simulated failure", out)
        self.assertIn("could not be stored encrypted", out)
        self.assertUnchanged(".env", "src/settings.py", "src/client.js", "docs/notes.md",
                             "config/app.json", "docs/deploy_key.pem")

    def test_dotenvx_that_changes_nothing_is_caught(self):
        code, out, err = run_script(self.tree.root, ["--yes"], extra_env={"FAKE_DOTENVX_NOOP": "1"})
        self.assertEqual(code, 1, out + err)
        self.assertIn("still plaintext", out)
        self.assertUnchanged(".env", "src/settings.py")

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
        self.assertIn('PORT="encrypted:', env)
        self.assertIn('APP_NAME="encrypted:', env)
        production = self.tree.read("config/.env.production")
        self.assertIn('LOG_LEVEL="encrypted:', production)
        self.assertIn('DB_PASSWORD="encrypted:QUJD"', production)   # already encrypted: untouched
        self.assertEqual(fake_dotenvx_get(self.tree.root, "PORT"), "3000")

    def test_placeholder_template_and_no_rewrite(self):
        code, out, err = run_script(self.tree.root, ["--yes", "--placeholder", "process.env.NAME"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("('process.env.STRIPE_SECRET_KEY')", self.tree.read("src/client.js"))

        fresh = ProjectTree()
        try:
            code, out, err = run_script(fresh.root, ["--yes", "--no-rewrite"])
            self.assertEqual(code, 0, out + err)
            self.assertEqual(fresh.read("src/settings.py"), FILES["src/settings.py"])
            self.assertIn('AWS_SECRET_ACCESS_KEY="encrypted:', fresh.read(".env"))
            self.assertIn("--no-rewrite left the plaintext", out)
        finally:
            fresh.cleanup()

    def test_custom_env_file_receives_moved_secrets(self):
        code, out, err = run_script(self.tree.root, ["--yes", "--env-file", "config/secrets.env"])
        self.assertEqual(code, 0, out + err)
        secrets = self.tree.read("config/secrets.env")
        self.assertIn('AWS_ACCESS_KEY_ID="encrypted:', secrets)
        self.assertIn("Created by sweep_and_secure.py", secrets)
        env = self.tree.read(".env")
        self.assertIn('STRIPE_SECRET_KEY="encrypted:', env)   # in place, as before
        self.assertNotIn("AWS_ACCESS_KEY_ID", env)
        self.assertIn("dotenvx run -f config/secrets.env -- <your command>", out)

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


class UnitTests(unittest.TestCase):

    def test_parse_env_entries(self):
        text = ('export A=1\nB="two\nlines"\nC=\'single # not a comment\'\nD=plain # comment\n'
                'E=x#y\n# comment\nnot an entry\nF=\n')
        entries = list(sas.parse_env_entries(text))
        self.assertEqual([(k, v) for k, v, _ in entries],
                         [("A", "1"), ("B", "two\nlines"), ("C", "single # not a comment"),
                          ("D", "plain"), ("E", "x"), ("F", "")])
        self.assertEqual([line for _, _, line in entries], [1, 2, 4, 5, 6, 9])

    def test_quote_env_value_prefers_literal_single_quotes(self):
        self.assertEqual(sas.quote_env_value("pa$$ #w\\n"), ("'pa$$ #w\\n'", True))
        self.assertEqual(sas.quote_env_value("it's"), ("`it's`", True))
        self.assertEqual(sas.quote_env_value("it's `x`"), ('"it\'s `x`"', True))
        quoted, exact = sas.quote_env_value("it's `x` \"$y\"")
        self.assertFalse(exact)
        self.assertTrue(quoted.startswith('"'))

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

    def test_locate_extends_urls_and_handles_escaped_newlines(self):
        data = ('DATABASE_URL = "%s"\nOTHER = "%s"\n' % (PG_URL, PG_URL.replace("/app", "/test"))).encode("utf-8")
        found = sas.locate(data, PG_URL[:PG_URL.rindex("/")], "PLAIN")
        self.assertEqual([token for token, _, _ in found],
                         [PG_URL.encode("utf-8"), PG_URL.replace("/app", "/test").encode("utf-8")])
        escaped = b'KEY="-----BEGIN X-----\\nabc\\n-----END X-----"'
        self.assertEqual(len(sas.locate(escaped, "-----BEGIN X-----\nabc\n-----END X-----", "PLAIN")), 1)
        self.assertEqual(sas.locate(b"nothing here", "missing-secret", "PLAIN"), [])

    def test_is_env_file(self):
        for name in (".env", ".env.production", "prod.env", ".env.local", ".env.example"):
            self.assertTrue(sas.is_env_file(name), name)
        for name in (".env.keys", ".env.keys.bak", ".env.vault", ".envrc", "environment.py", "env", "settings.py"):
            self.assertFalse(sas.is_env_file(name), name)

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


if __name__ == "__main__":
    unittest.main()
