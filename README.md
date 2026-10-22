# sweep-and-secure

`sweep_and_secure.py` sweeps a folder tree for API keys and secrets, shows you
what it found, and -- once you say yes -- encrypts them with
[dotenvx](https://dotenvx.com). The finding is done by
[TruffleHog](https://trufflesecurity.com/trufflehog).

```
$ python sweep_and_secure.py
sweep-and-secure 1.3.1  (TruffleHog + dotenvx)
Folder: /home/me/shop
  [ok] trufflehog  3.99.3     /usr/local/bin/trufflehog
  [ok] dotenvx     2.38.2     /usr/local/bin/dotenvx
Scanning with TruffleHog (this can take a while on big trees) ...
  Scanned 212 file(s) in 0:05; TruffleHog reported 6 finding(s).

Plaintext secrets found: 6 in 5 file(s)
  #  Type          Key / name             Secret     Where                Action
  1  Stripe        STRIPE_SECRET_KEY      sk_l...23  .env:2               encrypt in place
  2  Github        -                      ghp_...3f  build/blob.txt.gz    move to .secrets-quarantine/build/blob.txt.gz
  3  SlackWebhook  SLACK_WEBHOOK          http...wX  config/app.json:4    move to .env, replace with ${SLACK_WEBHOOK}
  4  SlackWebhook  SLACK_WEBHOOK          http...wX  docs/notes.md:3      replace with ${SLACK_WEBHOOK} (value already in .env)
  5  AWS           AWS_ACCESS_KEY_ID      AKIA...M2  src/settings.py:4    move to .env, replace with ${AWS_ACCESS_KEY_ID}
  6  AWS           AWS_SECRET_ACCESS_KEY  1tUm...IU  src/settings.py:5    move to .env, replace with ${AWS_SECRET_ACCESS_KEY}
  Archives holding secrets are offered for moving to .secrets-quarantine; answer s to leave them in place. A --yes run moves them only with --quarantine.

Already encrypted with dotenvx (left as is): 1
  Key          Where
  DB_PASSWORD  config/.env.production:8

Other plaintext keys in env files: 2  (not flagged by TruffleHog; add --env-all to encrypt them too)
  .env: PORT, APP_NAME

Encrypt 5 secret(s) and move 1 archive(s) to quarantine now? [y/N/s]  (s = choose which): y
  [ok] added .env.keys* to /home/me/shop/.gitignore
  [ok] added /.secrets-quarantine/ to /home/me/shop/.gitignore

Encrypting ...
  [ok] .env: encrypted 4 key(s): STRIPE_SECRET_KEY, SLACK_WEBHOOK, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  [ok] config/app.json: replaced 1 occurrence(s) of 1 secret(s) with placeholders (SLACK_WEBHOOK)
  [ok] docs/notes.md: replaced 1 occurrence(s) of 1 secret(s) with placeholders (SLACK_WEBHOOK)
  [ok] src/settings.py: replaced 2 occurrence(s) of 2 secret(s) with placeholders (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  [ok] build/blob.txt.gz: moved to .secrets-quarantine/build/blob.txt.gz

  [ok] private key file: .env.keys

Done: 4 secret(s) stored encrypted; 4 plaintext occurrence(s) removed from 3 file(s); 1 archive(s) moved to .secrets-quarantine

Next steps
  ...
```

## Installation

The tool is one Python file with no dependencies of its own; take whichever
route suits you. Each gives you a `sweep-and-secure` command.

**With pipx (or uv)**, in an isolated environment:

```
pipx install git+https://github.com/voxgig/sweep-and-secure            # latest from the default branch
pipx install git+https://github.com/voxgig/sweep-and-secure@v1.3.1     # a specific release
pipx run --spec git+https://github.com/voxgig/sweep-and-secure sweep-and-secure --dry-run   # try it without installing
uvx --from git+https://github.com/voxgig/sweep-and-secure sweep-and-secure --dry-run
```

**With curl, from a GitHub release** (macOS and Linux). The installer downloads
`sweep_and_secure.py` from the latest release, checks its SHA-256 against the
release's `SHA256SUMS`, installs it as `sweep-and-secure`, then runs
`sweep-and-secure --check-setup` so that you see at once whether the machine is
ready: the TruffleHog and dotenvx it finds, with versions and locations (the
same lines every run prints), a trial run of each, and what is missing if
anything is:

```
$ curl -sSfL https://github.com/voxgig/sweep-and-secure/releases/latest/download/install.sh | sh -s -- -b /usr/local/bin
Downloading sweep_and_secure.py from https://github.com/voxgig/sweep-and-secure/releases/latest/download ...
Checksum OK.
Installed /usr/local/bin/sweep-and-secure

sweep-and-secure 1.3.1  (TruffleHog + dotenvx)
Python 3.12.3 (/usr/bin/python3) on Linux-6.8.0-x86_64-with-glibc2.39
  [ok] trufflehog  3.99.3     /usr/local/bin/trufflehog
  [ok] dotenvx     2.38.2     /usr/local/bin/dotenvx
  [ok] git         2.43.0     /usr/bin/git  (optional: keeps .env.keys out of commits)
  Scanned 1 file(s) in 0:02; TruffleHog reported 0 finding(s).
  [ok] trufflehog  ran in a scratch folder: exit status 0, 1 file(s) scanned, no findings
  [ok] dotenvx     ran in a scratch folder: encrypted a value, decrypted it back, wrote .env.keys

Setup looks good. Nothing was changed. Next: sweep-and-secure --dry-run in a project folder.
```

`-b DIR` chooses the folder (default: `/usr/local/bin` when writable, otherwise
`~/.local/bin`), `-v v1.3.1` a specific release, `-n` skips the setup check (for
an image build that installs the tools afterwards). The installer is
`install.sh` in this repository and is attached to every release, so you can
read it first.

**By hand**: download `sweep_and_secure.py` from the
[latest release](https://github.com/voxgig/sweep-and-secure/releases/latest),
check it against `SHA256SUMS`, make it executable and put it on your `PATH`, or
simply run `python sweep_and_secure.py` from wherever it sits. On Windows use
pipx or this route.

Then install the two tools it drives (next section), if the installer's check
did not already find them, and run the checks under "Checking the install".

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

## Checking the install

Three commands check an install without changing anything, in increasing depth.

```
sweep-and-secure --version      # sweep-and-secure 1.3.1
sweep-and-secure --help         # the option reference (see Options below)
sweep-and-secure --check-setup  # are TruffleHog and dotenvx in place, and do they run?
```

The first two run before TruffleHog and dotenvx are installed and exit at once
with code 0, so they prove only that the script is on your `PATH` and that
Python runs it. If you installed with pipx or uv and the command is not found,
run `pipx ensurepath` (or `uv tool update-shell`) and open a new shell.

`--check-setup` is the check to run once the two tools are installed (the curl
installer runs it for you at the end of the install). It prints
the Python it runs under, finds TruffleHog, dotenvx and git (optional) the way a
real run does and shows their versions and locations, then runs both tools in a
scratch folder under the system temp folder: TruffleHog scans a file that holds
no secret, and dotenvx encrypts a throw-away value and decrypts it back, through
the same code a real run uses. Nothing in the current folder is read or written,
and the scratch folder is removed afterwards.

```
$ sweep-and-secure --check-setup
sweep-and-secure 1.3.1  (TruffleHog + dotenvx)
Python 3.12.3 (/home/me/.local/share/pipx/venvs/sweep-and-secure/bin/python) on Linux-6.8.0-x86_64-with-glibc2.39
  [ok] trufflehog  3.99.3     /usr/local/bin/trufflehog
  [ok] dotenvx     2.38.2     /usr/local/bin/dotenvx
  [ok] git         2.43.0     /usr/bin/git  (optional: keeps .env.keys out of commits)
  Scanned 1 file(s) in 0:02; TruffleHog reported 0 finding(s).
  [ok] trufflehog  ran in a scratch folder: exit status 0, 1 file(s) scanned, no findings
  [ok] dotenvx     ran in a scratch folder: encrypted a value, decrypted it back, wrote .env.keys

Setup looks good. Nothing was changed. Next: sweep-and-secure --dry-run in a project folder.
```

Exit code 0 means a real run will find everything it needs. A tool that is
missing, too old, or fails its scratch run is reported with install links and
the exit code is 1; every tool is checked before the verdict, so one report
lists everything that is wrong. `--trufflehog PATH` and `--dotenvx PATH` (or the
`TRUFFLEHOG_BIN` and `DOTENVX_BIN` environment variables) point the check, like
a run, at a copy that is not on your `PATH`.

The last step is a dry run in your real project: `sweep-and-secure --dry-run`
scans the folder and lists what a real run would do, and changes nothing.

To check a downloaded `sweep_and_secure.py` against the published checksums,
from the folder it was downloaded into (the curl installer does this for you):

```
curl -sSfL -O https://github.com/voxgig/sweep-and-secure/releases/download/v1.3.1/SHA256SUMS
grep ' sweep_and_secure.py$' SHA256SUMS | sha256sum -c -      # macOS: ... | shasum -a 256 -c -
```

## Usage

```
cd your/project
sweep-and-secure            # scan, list, ask, encrypt
sweep-and-secure --dry-run  # scan and list only
sweep-and-secure --yes      # no questions (scripts, CI)
sweep-and-secure some/dir   # sweep a different folder
sweep-and-secure --check-setup  # are TruffleHog and dotenvx in place? (see Checking the install)
```

Without installing, `python sweep_and_secure.py ...` (or
`chmod +x sweep_and_secure.py && ./sweep_and_secure.py`) does the same.

While TruffleHog runs, a status line shows how many files it has scanned, how
many findings it has reported so far and the time spent, redrawn in place on a
terminal and printed as a heartbeat line every 15 seconds when the output is a
pipe or a CI log, so a long scan is visibly alive rather than hung. It ends with
`Scanned N file(s) in M:SS; TruffleHog reported K finding(s).`

The run is interactive: it first lists every secret TruffleHog found (the
detector type, the key or variable name it will use, a masked preview, where it
is, and what will happen to it), then the keys that are already encrypted with
dotenvx, then asks. Answer `y` to do everything listed (encrypt the secrets and
move archives that hold secrets into the quarantine folder), `n` to stop, or `s`
to pick items by number (`1 3 5-7`).

### What happens to a secret

| where it was found | what is done |
| --- | --- |
| a dotenv file (`.env`, `.env.production`, `prod.env`, ...), as the value of `KEY=...` | `dotenvx encrypt -k KEY` encrypts that key in place: `KEY="encrypted:..."`. Every key whose value holds the secret is encrypted, not just the first |
| anywhere else (source code, JSON, YAML, Markdown, certificates, ...) | the value is added to the project's `.env` (`--env-file` to change) and encrypted there; the plaintext in the file is replaced by `${KEY}` (`--placeholder` to change) |
| an archive TruffleHog looked inside (`.zip`, `.jar`, `.tar.gz`, ...) | the whole archive is moved out of the tree into the quarantine folder (`.secrets-quarantine` in the swept folder, `--quarantine-dir` to change), keeping its relative path; the folder's `MANIFEST.txt` records where it came from. An interactive run lists the archive as a numbered item ("move to ..."), so `s` can leave it in place; a `--yes` run moves archives only when `--quarantine` is given and otherwise lists them under "cannot fix automatically" |
| a binary file, a symlink, a secret TruffleHog had to decode first, a PDF, a generated lock file (`package-lock.json`, `poetry.lock`, ...), an example env file (`.env.example`, `.env.sample`, ...) | listed under "cannot fix automatically" for you to deal with by hand |
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

`sweep-and-secure --help` prints the short form of this reference.

**Where to scan**

- `path`: the folder to sweep, default the current folder. Every sub-folder is
  included. This folder is also where dotenvx keeps the private key file
  (`.env.keys`), where the default `.env` lives, and where the script stages
  files while it works.
- `--exclude REGEX`: skip paths matching a regular expression; repeat the option
  for several. Patterns are matched against the whole path as TruffleHog sees
  it, so on Windows write `[/\\]` rather than `/` for a separator, for example
  `--exclude '(^|[/\\])fixtures([/\\]|$)'`. These add to the built-in excludes.
- `--no-default-excludes`: also scan `.git`, `.hg`, `.svn`, `node_modules`,
  `__pycache__`, `.venv`, `venv` and `.tox`, which are skipped by default. The
  dotenvx key files (`.env.keys*`), legacy `.env.vault` files and the script's
  own staging files are never scanned or rewritten, whatever you pass.
- `--min-length N`: ignore secrets shorter than N characters (default 8). They
  are listed under "cannot fix automatically" rather than rewritten.
- `--verify`: let TruffleHog check each credential against the service that
  issued it. This sends the secret to that service over the network; live
  credentials are marked `*` in the listing. Off by default.

**What to do with what is found**

- `-n`, `--dry-run`, `--list`: scan and report, change nothing. Exits 0 whatever
  is found (1 only if the scan itself failed), so it suits install checks and
  CI audits.
- `-y`, `--yes`: encrypt everything listed without asking; use it in scripts
  and CI. Archives that hold secrets are moved to quarantine only if
  `--quarantine` is also given, so an unattended run never relocates files it
  was not told to. Without it the question is asked even when stdin is not a terminal
  and the answer is read from there: a piped `y` is accepted, and no input at
  all (end of file) counts as no, so the run lists the findings and exits 2.
- `--env-file PATH`: the dotenv file that receives secrets moved out of other
  files. Default `.env` in the swept folder; a relative PATH is taken from there.
  The file is created with a comment header if it does not exist. Any
  dotenv-style name works; dotenvx names the key variables after the file, so
  `config/.env.production` gets `DOTENV_PRIVATE_KEY_PRODUCTION`. Names reserved
  for dotenvx key files, vault files and the script's staging files
  (`.env.keys*`, `.env.vault`, `.sweep-and-secure-*`) are refused, because they
  are never scanned or rewritten. A secret found inside an existing env file is
  always encrypted in that file, whatever `--env-file` says.
- `--env-all`: also encrypt every other plaintext key in the env files
  (`PORT=3000`, `APP_NAME=demo`, ...), not only the ones TruffleHog flagged. The
  report's "Other plaintext keys" list shows exactly what this adds. Example
  files such as `.env.example` are left out.
- `--no-rewrite`: store the secrets encrypted but leave the source files as they
  are. A later run without the flag recognises the stored values and only does
  the rewriting; it does not store them twice.
- `--quarantine`: with `--yes`, also move every archive that TruffleHog found a
  secret inside (zip, jar, tar, gz, bz2, xz, 7z, rar, zstd ...) out of the tree
  into the quarantine folder, `.secrets-quarantine` inside the swept folder by
  default, keeping its relative path (`build/keys.zip` becomes
  `.secrets-quarantine/build/keys.zip`, with a numeric suffix if that name is
  taken). The folder's `MANIFEST.txt` gets a line per file with the time, the
  original path and the detectors. The folder is added to `.gitignore` before
  anything is moved and is never scanned afterwards. An interactive run offers
  this without the flag: archives appear as numbered items ("move to ..."), `y`
  includes them and `s` lets you leave them out. Other binary files are never
  moved; they stay under "cannot fix automatically".
- `--quarantine-dir DIR`: use DIR as the quarantine folder instead (relative to
  the swept folder, or absolute, including a folder outside the tree); implies
  `--quarantine`. A folder inside the tree is excluded from the scan for that
  run. Reserved names and the swept folder itself are refused.
- `--placeholder TEMPLATE`: the text that replaces a secret in a source file,
  with `NAME` standing for the variable name. Default `${NAME}`;
  `process.env.NAME`, `os.environ["NAME"]` or `<NAME>` are common alternatives.
  This is plain text substitution: it removes the secret, and the code still
  has to be changed to read the variable.

**The tools**

- `--trufflehog PATH`, `--dotenvx PATH`: use these executables instead of
  searching. The search order is the option, the `TRUFFLEHOG_BIN` or
  `DOTENVX_BIN` environment variable, the `PATH`, and for dotenvx a
  project-local `node_modules/.bin/dotenvx`. Both tools are run with the swept
  folder as their current directory.
- `--no-version-check`: use a tool even when its `--version` output cannot be
  read. That is normally refused because it usually means the file cannot be
  executed from here (a POSIX shell script found on Windows, for instance), and
  the failure would otherwise surface half way through a run.
- `--check-setup`: report the Python in use, find both tools (and git) as a run
  would, run each in a scratch folder under the system temp folder, and exit:
  0 when a real run would work, 1 when something is missing or broken, with
  install links. Nothing is scanned and nothing in the folder is touched; see
  "Checking the install".

**Output**

- `-v`, `--verbose`: print every command run (TruffleHog, `dotenvx encrypt`, and
  the `dotenvx get` calls that verify each stored value) and the tools' output.
  Secret values are never printed, only key names and masked previews.
- `--no-color`: plain output. Colour is only used on a terminal, and the
  `NO_COLOR` environment variable has the same effect.
- `-h`, `--help`: the short reference. `--version`: print
  `sweep-and-secure <version>`. Both exit at once, before the tools are looked
  for, which is what makes them useful for checking an install.

**Exit codes**

| code | meaning |
| --- | --- |
| 0 | done, or nothing to do; also every dry run whose scan completed |
| 1 | a tool is missing or unusable (also `--check-setup`'s verdict when a tool is missing or fails its scratch run); the scan failed or was cut short; an encryption or its verification failed; or an unexpected error stopped the run, in which case the state of the tree is printed |
| 2 | you answered no, or gave no answer: stdin was not a terminal, nothing was piped in and `--yes` was not given |
| 130 | interrupted with Ctrl-C; what had already been changed is printed |

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
* Secrets inside binaries, PDFs, lock files or base64-encoded text are reported
  but not rewritten. Archives (TruffleHog looks inside them) are not rewritten
  either; they can only be moved to the quarantine folder as a whole.
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
a matching tag (`git tag v1.3.1 && git push origin v1.3.1`) or run the release
workflow from the Actions tab with the version, which creates the tag for you.
The workflow (`.github/workflows/release.yml`) checks that the tag matches the
version, runs the tests, builds the sdist and wheel, and publishes a GitHub
release carrying the script, `install.sh`, both packages and `SHA256SUMS`, which
is what the curl installer and `pipx install ...@vX.Y.Z` fetch.
