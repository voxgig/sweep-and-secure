# sweep-and-secure

`sweep_and_secure.py` sweeps a folder tree for API keys and secrets, shows you
what it found, and -- once you say yes -- encrypts them with
[dotenvx](https://dotenvx.com). The finding is done by
[TruffleHog](https://trufflesecurity.com/trufflehog).

```
$ python sweep_and_secure.py
sweep-and-secure 1.1.0  (TruffleHog + dotenvx)
Folder: /home/me/shop
  [ok] trufflehog  3.99.3     /usr/local/bin/trufflehog
  [ok] dotenvx     2.38.2     /usr/local/bin/dotenvx
Scanning with TruffleHog (this can take a while on big trees) ...

Plaintext secrets found: 5 in 4 file(s)
  #  Type          Key / name             Secret     Where                Action
  1  Stripe        STRIPE_SECRET_KEY      sk_l...23  .env:2               encrypt in place
  2  SlackWebhook  SLACK_WEBHOOK          http...wX  config/app.json:4    move to .env, replace with ${SLACK_WEBHOOK}
  3  SlackWebhook  SLACK_WEBHOOK          http...wX  docs/notes.md:3      replace with ${SLACK_WEBHOOK} (value already in .env)
  4  AWS           AWS_ACCESS_KEY_ID      AKIA...M2  src/settings.py:4    move to .env, replace with ${AWS_ACCESS_KEY_ID}
  5  AWS           AWS_SECRET_ACCESS_KEY  1tUm...IU  src/settings.py:5    move to .env, replace with ${AWS_SECRET_ACCESS_KEY}

Found but cannot fix automatically: 1
  Github             build/blob.txt.gz
                     binary or archive file - delete it or rebuild it without the secret

Already encrypted with dotenvx (left as is): 1
  Key          Where
  DB_PASSWORD  config/.env.production:8

Other plaintext keys in env files: 2  (not flagged by TruffleHog; add --env-all to encrypt them too)
  .env: PORT, APP_NAME

Encrypt these 5 secret(s) now? [y/N/s]  (s = choose which): y
  [ok] added .env.keys* to /home/me/shop/.gitignore

Encrypting ...
  [ok] .env: encrypted 4 key(s): STRIPE_SECRET_KEY, SLACK_WEBHOOK, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  [ok] config/app.json: replaced 1 occurrence(s) of 1 secret(s) with placeholders (SLACK_WEBHOOK)
  [ok] docs/notes.md: replaced 1 occurrence(s) of 1 secret(s) with placeholders (SLACK_WEBHOOK)
  [ok] src/settings.py: replaced 2 occurrence(s) of 2 secret(s) with placeholders (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

  [ok] private key file: .env.keys

Done: 4 secret(s) stored encrypted; 4 plaintext occurrence(s) removed from 3 file(s); 1 need manual attention (see above)

Next steps
  ...
```

## Installation

The tool is one Python file with no dependencies of its own; take whichever
route suits you. Each gives you a `sweep-and-secure` command.

**With pipx (or uv)**, in an isolated environment:

```
pipx install git+https://github.com/voxgig/sweep-and-secure            # latest from the default branch
pipx install git+https://github.com/voxgig/sweep-and-secure@v1.1.0     # a specific release
pipx run --spec git+https://github.com/voxgig/sweep-and-secure sweep-and-secure --dry-run   # try it without installing
uvx --from git+https://github.com/voxgig/sweep-and-secure sweep-and-secure --dry-run
```

**With curl, from a GitHub release** (macOS and Linux). The installer downloads
`sweep_and_secure.py` from the latest release, checks its SHA-256 against the
release's `SHA256SUMS`, and installs it as `sweep-and-secure`:

```
curl -sSfL https://github.com/voxgig/sweep-and-secure/releases/latest/download/install.sh | sh -s -- -b /usr/local/bin
```

`-b DIR` chooses the folder (default: `/usr/local/bin` when writable, otherwise
`~/.local/bin`), `-v v1.1.0` a specific release. The installer is `install.sh`
in this repository and is attached to every release, so you can read it first.

**By hand**: download `sweep_and_secure.py` from the
[latest release](https://github.com/voxgig/sweep-and-secure/releases/latest),
check it against `SHA256SUMS`, make it executable and put it on your `PATH`, or
simply run `python sweep_and_secure.py` from wherever it sits. On Windows use
pipx or this route.

`sweep-and-secure --version` confirms the install. Then install the two tools
it drives:

## Requirements

* Python 3.8 or newer. (The script still carries Python 2.7 compatibility code
  and may well work there, but only 3.8 and up are tested; see Development.)
* [TruffleHog](https://trufflesecurity.com/trufflehog) 3.x on your `PATH`
  ([install](https://github.com/trufflesecurity/trufflehog#floppy_disk-installation)):
  `brew install trufflehog` or
  `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin`
* [dotenvx](https://dotenvx.com) 1.0 or newer on your `PATH`
  ([install](https://dotenvx.com/docs/install)):
  `curl -sfS https://dotenvx.sh | sh`, `brew install dotenvx/brew/dotenvx` or
  `npm install -g @dotenvx/dotenvx`

If either tool is missing the script stops, says which one, and prints these
links. `--trufflehog PATH` / `--dotenvx PATH` (or the `TRUFFLEHOG_BIN` /
`DOTENVX_BIN` environment variables) point it at a copy that is not on your
`PATH`; a project-local `node_modules/.bin/dotenvx` is picked up automatically.
A tool whose `--version` cannot be read is refused (it usually means the file
cannot be executed from here); `--no-version-check` overrides that.

## Usage

```
cd your/project
sweep-and-secure            # scan, list, ask, encrypt
sweep-and-secure --dry-run  # scan and list only
sweep-and-secure --yes      # no questions (scripts, CI)
sweep-and-secure some/dir   # sweep a different folder
```

Without installing, `python sweep_and_secure.py ...` (or
`chmod +x sweep_and_secure.py && ./sweep_and_secure.py`) does the same.

The run is interactive: it first lists every secret TruffleHog found (the
detector type, the key or variable name it will use, a masked preview, where it
is, and what will happen to it), then the keys that are already encrypted with
dotenvx, then asks. Answer `y` to encrypt everything listed, `n` to stop, or
`s` to pick items by number (`1 3 5-7`).

### What happens to a secret

| where it was found | what is done |
| --- | --- |
| a dotenv file (`.env`, `.env.production`, `prod.env`, ...), as the value of `KEY=...` | `dotenvx encrypt -k KEY` encrypts that key in place: `KEY="encrypted:..."`. Every key whose value holds the secret is encrypted, not just the first |
| anywhere else (source code, JSON, YAML, Markdown, certificates, ...) | the value is added to the project's `.env` (`--env-file` to change) and encrypted there; the plaintext in the file is replaced by `${KEY}` (`--placeholder` to change) |
| a binary or archive file, a symlink, a secret TruffleHog had to decode first, a PDF, a generated lock file (`package-lock.json`, `poetry.lock`, ...), an example env file (`.env.example`, `.env.sample`, ...) | listed under "cannot fix automatically" for you to deal with by hand |
| a value dotenvx cannot store exactly (it contains an apostrophe together with a backslash, or with both a backtick and a double quote) | listed under "cannot fix automatically"; moving it would corrupt it |

Variable names come from the code around the secret (`AWS_SECRET_ACCESS_KEY = "..."`,
`"apiKey": "..."`, `password: ...`), made specific with the detector name when
they are too generic (`token` found by the GitHub detector becomes
`GITHUB_TOKEN`), and fall back to the detector name plus a short hash
(`PRIVATE_KEY_28AF08`). The same secret found in several files gets one name.
A secret that is already in the env file -- in plaintext, or encrypted where the
private key lets the script check -- is reused under its existing key, so running
again after `--no-rewrite` or an interrupted run does not pile up `KEY_2`
duplicates. A name that is taken by a different value gets a numeric suffix, and
the listing says why.

### How files are changed

Nothing is written to an env file until the result has been checked. The env
file is copied, under its own name, into a staging folder inside the swept
folder; the new entries are appended to the copy; dotenvx encrypts the copy;
the script then checks that every key is `encrypted:`, that no entry still holds
a secret in plaintext, and -- where the private key is at hand -- that each value
decrypts back to exactly what was stored. Only then is the copy moved over the
real file in one atomic rename. If anything fails the real file has not been
touched, and the source files are left alone. Plaintext never lands on the real
env file's path, not even for a moment, so a crash or a power cut cannot leave
it there. Source files are rewritten atomically as well, and only after their
value has been stored.

dotenvx writes the private key to `.env.keys` (dotenvx 2.x puts it in the swept
folder; 1.x next to each env file). Before anything is encrypted the script asks
`git check-ignore` whether that file is ignored and appends `.env.keys*` to your
`.gitignore` if it is not, so that an interrupted run cannot leave the key
exposed; afterwards it checks again and warns loudly if the file is tracked by
git. If a run is interrupted or hits an unexpected error it says exactly what
was changed and what still holds plaintext; running again finishes the job.

dotenvx itself only looks for `.env.keys` next to the env file, so for an env
file in a sub-folder the "Next steps" give the command with `-fk`
(`dotenvx run -f config/.env.production -fk .env.keys -- <your command>`).

### Options

```
path                    folder to sweep (default: current folder)
-n, --dry-run, --list   scan and list only; change nothing
-y, --yes               encrypt everything found without asking
--env-file PATH         dotenv file that receives secrets moved out of other files (default: .env)
--env-all               also encrypt every other plaintext key in dotenv files
--no-rewrite            store secrets encrypted but leave the source files untouched
--placeholder TEMPLATE  text that replaces a secret; NAME becomes the key (default: ${NAME})
--verify                let TruffleHog verify secrets against their services (network access)
--exclude REGEX         skip paths matching REGEX (repeatable)
--no-default-excludes   also scan .git, node_modules, virtualenvs, __pycache__ ...
--min-length N          ignore secrets shorter than N characters (default: 8)
--trufflehog PATH       trufflehog executable        --dotenvx PATH   dotenvx executable
--no-version-check      use a tool even if its --version could not be read
-v, --verbose           show the commands run and the tools' output
--no-color              plain output
```

`--exclude` patterns are regular expressions matched against the whole path; the
built-in ones accept `/` and `\` as separators so that they work on Windows too,
where TruffleHog sees backslashes.

Exit codes: `0` done or nothing to do, `1` a tool is missing, the scan failed
or was cut short, an encryption or its verification failed, or the run was
stopped by an unexpected error, `2` you said no (or stdin was not a terminal
and `--yes` was not given), `130` interrupted.

## After a run

1. Replace the placeholders in your code with real environment lookups
   (`os.environ["AWS_ACCESS_KEY_ID"]`, `process.env.AWS_ACCESS_KEY_ID`, ...).
2. Start your program through dotenvx so the values are decrypted at run time:
   `dotenvx run -- <your command>`, or for an env file in a sub-folder
   `dotenvx run -f config/.env.production -fk .env.keys -- ...` (the exact
   commands are printed).
3. Keep `.env.keys` private: share the `DOTENV_PRIVATE_KEY*` values through a
   password manager or your CI's secret store. The encrypted `.env` files are
   safe to commit.
4. The secrets were in plaintext, so rotate them. The script prints
   TruffleHog's rotation guides where it has them.
5. Git history still holds the old values: `trufflehog git file://.`

## Limitations

* TruffleHog only knows the credential formats it has detectors for; a plain
  `DB_PASSWORD=hunter2` in a `.env` file is listed under "other plaintext keys"
  and is encrypted only with `--env-all`.
* Secrets inside binaries, archives (TruffleHog looks inside them), PDFs, lock
  files or base64-encoded text are reported but not rewritten.
* dotenvx expands `$NAME` and backslash escapes in double-quoted and backtick
  values and keeps `\"` and `\\` as they are, so a value containing an apostrophe
  together with a backslash (or with a backtick and a double quote) cannot be
  stored exactly and is left for you to handle.
* Values that were already in an env file and contain `$` or a backslash are
  encrypted as dotenvx reads them (expanded), which is what your program got
  before as well; they are checked for being decryptable, not for equality.
* Replacing a literal with `${KEY}` removes the secret but does not make the
  program read the variable; that is the follow-up work the script lists.
* Only the working tree is changed, never git history.

## Development

```
python -m unittest discover -s tests -v
```

The end-to-end tests run the script against a throw-away project with
stand-ins for `trufflehog` and `dotenvx` from `tests/fakebin`, so they need
neither tool installed. The stand-in dotenvx follows the real tool's quoting,
key-naming and key-lookup rules as measured against dotenvx 2.38. With
`SWEEP_TEST_REAL_TOOLS=1` and the real tools on your `PATH` an extra tier runs
the script against them. CI (`.github/workflows/test.yml`) runs the suite on
Linux, macOS and Windows with Python 3.8 to 3.13, the real-tools tier on Linux
with the current TruffleHog and dotenvx, and a packaging job that builds the
wheel, runs the console script and exercises `install.sh`.

To release: set `__version__` in `sweep_and_secure.py`, merge, then either push
a matching tag (`git tag v1.1.0 && git push origin v1.1.0`) or run the release
workflow from the Actions tab with the version, which creates the tag for you.
The workflow (`.github/workflows/release.yml`) checks that the tag matches the
version, runs the tests, builds the sdist and wheel, and publishes a GitHub
release carrying the script, `install.sh`, both packages and `SHA256SUMS`, which
is what the curl installer and `pipx install ...@vX.Y.Z` fetch.
