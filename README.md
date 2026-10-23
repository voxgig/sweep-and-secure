# sweep-and-secure

Find the API keys, tokens and passwords sitting in plaintext in a project
folder, and lock them away. One command scans the tree with
[TruffleHog](https://trufflesecurity.com/trufflehog), shows you everything it
found and what it intends to do, and, once you say yes, encrypts the secrets
with [dotenvx](https://dotenvx.com), replaces the plaintext in your files with
placeholders, and moves the files it cannot fix in place (archives, binaries,
PDFs, lock files, example env files) out of the tree into a quarantine folder
that remembers where each came from. It is one Python file with no dependencies
of its own, runs on Linux, macOS and Windows, keeps a log of every run, and is
built so that no file is ever left half-written: each file is changed completely
or not at all, an interrupted run says what it did, and running again finishes
the job.

- [What it does](#what-it-does)
- [Install](#install)
- [Examples](#examples)
- [Reference](#reference): [options](#options), [exit codes](#exit-codes),
  [limitations](#limitations)
- [Development](#development)

## What it does

### The problem

Secrets end up in plaintext in project folders all the time: a `.env` file
that was never encrypted, a key pasted into `settings.py` to get something
working, a webhook URL in a JSON config, a database URL with its password in the
docs, a release zip that bundles a `.env`. Anyone who gets a copy of the folder
gets the credentials, and git keeps every version forever. Finding them by hand
is unreliable, and fixing them by hand across a whole tree is slow and
error-prone: you have to move each value somewhere safe, encrypt it, change
every file that held it, and make sure you never saved a half-done state.

### The approach

sweep-and-secure chains two well-known tools and adds the careful part in
between:

1. **TruffleHog finds the secrets.** It has detectors for hundreds of credential
   formats (AWS, Stripe, GitHub, Slack, database URLs, private keys, ...) and it
   looks inside archives. sweep-and-secure runs it over the folder, skipping
   `.git`, `node_modules`, virtualenvs and its own key files, with a live
   progress line so you can see a long scan is alive.
2. **You see a plan before anything changes.** Every finding becomes a
   numbered line: the detector type, the variable name the secret will be stored
   under, a masked preview, where it is, and exactly what will happen to it.
   Archives get their own list that names the files inside them that hold the
   secrets. Keys that are already encrypted are listed too, so you know what is
   left.
3. **You confirm.** `y` does everything listed, `n` stops, `s` lets you pick
   items by number. Scripts and CI pass `--yes`; `--dry-run` only lists.
4. **dotenvx encrypts.** A secret found inside an env file is encrypted in
   place (`KEY="encrypted:..."`). A secret found anywhere else is added to the
   project's `.env`, encrypted there, and the plaintext in the source file is
   replaced by a placeholder such as `${KEY}`. The same secret in several files
   gets one name. A file whose secrets cannot be fixed in place (an archive, a
   binary, a PDF, a lock file, an example env file) is moved whole into a
   quarantine folder when you choose it, and the folder's manifest and index
   record where it came from.
5. **It tells you what is left to do.** Change the code to read the variables,
   run your program through `dotenvx run`, keep the private key out of git,
   rotate the exposed credentials (with links to the rotation guides), and check
   git history.

### What happens to each kind of finding

| where it was found | what is done |
| --- | --- |
| a dotenv file (`.env`, `.env.production`, `prod.env`, ...), as the value of `KEY=...` | `dotenvx encrypt -k KEY` encrypts that key in place: `KEY="encrypted:..."`. Every key whose value holds the secret is encrypted, not just the first |
| anywhere else (source code, JSON, YAML, Markdown, certificates, ...) | the value is added to the project's `.env` (`--env-file` to change) and encrypted there; the plaintext in the file is replaced by `${KEY}` (`--placeholder` to change) |
| a file that cannot be fixed in place: an archive TruffleHog looked inside (`.zip`, `.jar`, `.tar.gz`, ...), a binary, a PDF, a generated lock file (`package-lock.json`, `poetry.lock`, ...), an example env file (`.env.example`, `.env.sample`, ...), a file too large or unreadable, or a text file whose only secrets are encoded, shorter than `--min-length` or impossible for dotenvx to store exactly | listed in the "Files holding secrets that cannot be fixed in place" section with the reason, and for archives the files inside that hold each secret (zip, tar with any compression, gzip, bzip2 and xz are opened, nested ones too). The whole file is moved out of the tree into the quarantine folder (`.secrets-quarantine` in the swept folder, `--quarantine-dir` to change), keeping its relative path; the folder's `MANIFEST.txt` and `index.json` record where it came from, why, and which files inside held secrets. An interactive run offers this as a numbered item, so `s` can leave a file in place; a `--yes` run moves files only when `--quarantine` is given |
| a text file some of whose secrets are fixed in place and one of which cannot be (encoded, too short, unstorable) | the fixable ones are handled; the file is listed with the other one for you to handle by hand, and is never moved, because moving it would undo the fixes |
| a symbolic link | listed; fix the file it points to |
| a match that sits inside a package integrity hash (`sha512-...` in `package-lock.json` or `yarn.lock`, `h1:...` in `go.sum`, `sha256:...` in a Python lock file) | set aside and counted, not treated as a secret: those are public checksums that happen to match a detector's pattern, a known weakness of several TruffleHog detectors |

Variable names come from the code around the secret (`AWS_SECRET_ACCESS_KEY =
"..."`, `"apiKey": "..."`, `password: ...`), made specific with the detector name
when they are too generic (`token` found by the GitHub detector becomes
`GITHUB_TOKEN`), and fall back to the detector name plus a short hash
(`PRIVATE_KEY_28AF08`). A secret that is already in the env file, in plaintext
or encrypted where the private key lets the script check, is reused under its
existing key, so running again after `--no-rewrite` or an interrupted run does
not pile up `KEY_2` duplicates. A name that is taken by a different value gets a
numeric suffix, and the listing says why.

### What the project looks like afterwards

- `.env` carries dotenvx's public-key header and `KEY="encrypted:..."` values.
  It is safe to commit: the public key only encrypts.
- `.env.keys` holds the private key (`DOTENV_PRIVATE_KEY`, one per env file).
  It is added to `.gitignore` before anything is encrypted. Share it through a
  password manager, and give it to CI as the `DOTENV_PRIVATE_KEY` environment
  variable.
- Source files hold `${KEY}` where the secrets were. The code still has to be
  changed to read the variable (`os.environ["KEY"]`, `process.env.KEY`, ...);
  the placeholder removes the secret and marks the spot.
- `.secrets-quarantine/` holds the files that were moved, under their original
  relative paths (a numeric suffix such as `keys.zip.1` when that name is already
  taken there). Its `MANIFEST.txt` has one line per file and its `index.json`
  one record per file: the stored name, the original path (relative and
  absolute), when it was moved, why, the detectors, and for archives the files
  inside that held secrets. The folder is git-ignored and never scanned. To
  put a file back, move it to its original path by hand once it no longer
  holds the secret.
- A log of the run is in the user's log folder (see below).
- Your program runs as `dotenvx run -- <command>`: dotenvx decrypts the values
  with the private key from `.env.keys` or from the environment and hands them
  to the program as ordinary environment variables.

### It says what it is before it starts

Every run opens with a notice that this is a security tool that changes files
on purpose, that the changes are deliberate and cannot be undone by the tool,
and that you should commit or back up first; the last sentence names the mode
(a dry run changes nothing, an interactive run changes nothing before you
confirm, `--yes` will not ask). The setup check carries no notice because it
changes nothing.

### Every run is logged

Each run writes a plain-text log to one common folder per user, so that any run
on the machine can be looked at afterwards: what was printed (without colour),
the prompts and your answers, the TruffleHog and dotenvx commands with their
diagnostics, and the exit code. Secret values never appear in it: the run prints
masked previews only, and the output of `dotenvx get` is never logged. The folder
is `~/.local/state/sweep-and-secure/logs` on Linux (`$XDG_STATE_HOME` when set),
`~/Library/Logs/sweep-and-secure` on macOS and
`%LOCALAPPDATA%\sweep-and-secure\logs` on Windows; `SWEEP_AND_SECURE_LOG_DIR` or
`--log-dir DIR` choose another, `--no-log` writes none. The newest 100 logs are
kept. Each run prints `Log: <path>` as its second line.

### Built never to leave a file half-written

Nothing is written to an env file until the result has been checked. The env
file is copied, under its own name, into a staging folder inside the swept
folder; the new entries are appended to the copy; dotenvx encrypts the copy; the
script then checks that every key is `encrypted:`, that no entry still holds a
secret in plaintext, and, where the private key is at hand, that each value
decrypts back to exactly what was stored. Only then is the copy moved over the
real file in one atomic rename. If anything fails the real file has not been
touched and the source files are left alone. Plaintext never lands on the real
env file's path, not even for a moment, so a crash or a power cut cannot leave
it there. Source files are rewritten atomically as well, and only after their
value has been stored. Files are moved to quarantine with a rename, or copied
and verified before the original is removed when the quarantine folder is on
another disk; the move is recorded in the folder's manifest and index.

The run as a whole is not one transaction: it changes the env files first,
then the source files one by one, then moves the archives, so a Ctrl-C or a
power cut between two files leaves the earlier ones changed and the later ones
untouched, never a file in between. Before anything is encrypted the script asks
`git check-ignore` whether `.env.keys` is ignored and appends `.env.keys*` (and
the quarantine folder) to your `.gitignore` if not, so that an interrupted run
cannot leave the key exposed; afterwards it checks again and warns loudly if the
key file is tracked by git. Every change is recorded as it is made: a run that
is interrupted or hits an unexpected error prints exactly what was changed and
what still holds plaintext, and after a power cut the next listing shows what is
still in plaintext. Running again finishes the job: stored values are recognised,
not stored twice, and leftover staging files from the interrupted run are
removed (they may hold a plaintext copy of an env file, so they never stay).

### What it does not do

- It does not rotate the credentials. They sat in plaintext, so treat them as
  exposed; the run ends with the rotation guides TruffleHog knows.
- It does not change your code to read environment variables. It removes the
  secret and leaves a placeholder where it was.
- It does not rewrite git history. The old plaintext is still in past commits;
  `trufflehog git file://.` shows where.
- It only finds what TruffleHog has a detector for. A plain
  `DB_PASSWORD=hunter2` in a `.env` file is listed under "other plaintext keys"
  and encrypted only with `--env-all`.
- It does not edit binaries, PDFs or lock files, and it does not edit inside
  archives; such files are moved whole to quarantine, or left for you.

## Install

Three steps, each a single command to copy.

### 1. Install sweep-and-secure

Pick one route. Each gives you a `sweep-and-secure` command.

macOS and Linux, from the latest GitHub release. The installer verifies the
script's SHA-256 against the release's checksums, installs it into
`/usr/local/bin`, then runs the setup check (step 3) so you see at once whether
TruffleHog and dotenvx are in place:

```
curl -sSfL https://github.com/voxgig/sweep-and-secure/releases/latest/download/install.sh | sh -s -- -b /usr/local/bin
```

With pipx, on any system including Windows:

```
pipx install git+https://github.com/voxgig/sweep-and-secure
```

With uv:

```
uv tool install git+https://github.com/voxgig/sweep-and-secure
```

Without installing anything, straight from the repository:

```
uvx --from git+https://github.com/voxgig/sweep-and-secure sweep-and-secure --dry-run
```

To pin a release, append `@v1.4.0` to the git URL, or pass `-v v1.4.0` to the
installer. To upgrade, run the same command again (`pipx upgrade
sweep-and-secure` or `uv tool upgrade sweep-and-secure` for those routes). The
installer takes `-b DIR` for another folder (without `-b` it uses
`/usr/local/bin` when writable, else `~/.local/bin`) and `-n` to skip the setup
check; it is `install.sh` in this repository and attached to every release, so
you can read it first. By hand: download `sweep_and_secure.py` from the
[latest release](https://github.com/voxgig/sweep-and-secure/releases/latest),
check it against `SHA256SUMS`, make it executable and put it on your `PATH`, or
run `python sweep_and_secure.py` from wherever it sits.

<a name="requirements"></a>

### 2. Install TruffleHog and dotenvx

sweep-and-secure needs both on your `PATH`: TruffleHog (3.6 or newer) finds the
secrets, dotenvx (1.4 or newer) encrypts them. Skip whichever you already have.

TruffleHog with Homebrew (macOS, Linux):

```
brew install trufflehog
```

TruffleHog with its own installer (Linux, macOS):

```
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

dotenvx with its own installer (Linux, macOS):

```
curl -sfS https://dotenvx.sh | sh
```

dotenvx with Homebrew:

```
brew install dotenvx/brew/dotenvx
```

dotenvx with npm (any system, including Windows):

```
npm install -g @dotenvx/dotenvx
```

On Windows, TruffleHog ships binaries on its
[releases page](https://github.com/trufflesecurity/trufflehog/releases) and
dotenvx has [installers](https://dotenvx.com/docs/install) besides npm. A tool
that is not on your `PATH` can be pointed at with `--trufflehog PATH` and
`--dotenvx PATH`, or the `TRUFFLEHOG_BIN` and `DOTENVX_BIN` environment
variables; a project-local `node_modules/.bin/dotenvx` is found on its own.

**Older releases are used as they are.** Old machines are a normal target for
this tool, so it does not insist on a current TruffleHog: it runs the command a
current release takes and, when the installed one rejects an option, runs again
without it and says what that costs. Without `--log-level` (added in the 3.8x
releases) the progress line shows findings and time but not the file being
scanned. Without `--exclude-paths` (before about 3.28) TruffleHog scans the
excluded folders as well; their findings are dropped by the script, so the scan
only takes longer. Before about 3.34 the folder is passed as `--directory`.
Releases from 3.6 to 3.12 encode their results differently and report an AWS
key pair as the id alone; the script decodes them and finds the secret access
key next to the id. 3.0 to 3.5 are refused, because their results do not name
the detector, and dotenvx before 1.4 is refused because `encrypt -k` did not
exist. An old TruffleHog does have fewer detectors (database URLs, for example,
are found from 3.70 on), so updating it is still worth doing when you can.

### 3. Check the setup

```
sweep-and-secure --check-setup
```

This finds both tools the way a run does, prints their versions and locations,
and tries each one out in a scratch folder under the system temp folder:
TruffleHog scans a file that holds no secret, and dotenvx encrypts a throw-away
value and decrypts it back. Nothing in the current folder is read or written.
Exit code 0 means a real run will work; 1 names what is missing or broken, with
install links, and every tool is checked before the verdict so one report lists
everything.

```
$ sweep-and-secure --check-setup
sweep-and-secure 1.4.0  (TruffleHog + dotenvx)
Log: /home/me/.local/state/sweep-and-secure/logs/2026-10-23T10-33-32Z-shop-48213.log
Python 3.13.16 (/usr/bin/python3) on Linux-6.8.0-x86_64-with-glibc2.39
  [ok] trufflehog  3.99.3     /usr/local/bin/trufflehog
  [ok] dotenvx     2.38.2     /usr/local/bin/dotenvx
  [ok] git         2.43.0     /usr/bin/git  (optional: keeps .env.keys out of commits)
  Scanned 1 file(s) in 0:02; TruffleHog reported 0 finding(s).
  [ok] trufflehog  ran in a scratch folder: exit status 0, 1 file(s) scanned, no findings
  [ok] dotenvx     ran in a scratch folder: encrypted a value, decrypted it back, wrote .env.keys

Setup looks good. Nothing was changed. Next: sweep-and-secure --dry-run in a project folder.
```

`sweep-and-secure --version` and `sweep-and-secure --help` work before the tools
are installed and prove that the script itself runs. If you installed with pipx
or uv and the command is not found, run `pipx ensurepath` (or `uv tool
update-shell`) and open a new shell.

## Examples

Every example below is a real run against this small sample project, which has
secrets in the usual places (the values are masked in the output; `sk_l...23`
is a Stripe key, `AKIA...M2` an AWS access key id):

```
shop/
  .env                     PORT and APP_NAME, plus a Stripe secret key in plaintext
  .env.example             a copy of .env that was meant as a template, key included
  config/.env.production   LOG_LEVEL in plaintext; DB_PASSWORD already encrypted with dotenvx
  config/app.json          a Slack webhook URL
  docs/notes.md            the same webhook URL again
  src/settings.py          an AWS key pair and a Postgres URL with a password in it
  build/blob.txt.gz        a gzip file holding a Stripe key
  build/keys.zip           a zip whose conf/prod.env holds another Stripe key
```

### See what would change: a dry run

`--dry-run` scans, lists everything and changes nothing. It is the right first
command in any project, and it exits 0 whatever it finds, so it also suits a CI
audit.

```
$ cd shop
$ sweep-and-secure --dry-run
sweep-and-secure 1.4.0  (TruffleHog + dotenvx)
Log: /home/me/.local/state/sweep-and-secure/logs/2026-10-23T10-33-38Z-shop-48213.log
Folder: /home/me/shop
  Note: this is a security tool that changes files on purpose: it encrypts env files, rewrites
  source files and moves files to quarantine. The changes are deliberate and it cannot undo them;
  commit or back up first. This is a dry run: nothing is changed.
  [ok] trufflehog  3.99.3     /usr/local/bin/trufflehog
  [ok] dotenvx     2.38.2     /usr/local/bin/dotenvx
Scanning with TruffleHog (this can take a while on big trees) ...
  Scanned 11 file(s) in 0:02; TruffleHog reported 8 finding(s).

Plaintext secrets found: 6 in 4 file(s)
  #  Type          Key / name             Secret     Where              Action
  1  Stripe        STRIPE_SECRET_KEY      sk_l...23  .env:2             encrypt in place
  5  SlackWebhook  SLACK_WEBHOOK          http...wX  config/app.json:5  move to .env, replace with ${SLACK_WEBHOOK}
  6  SlackWebhook  SLACK_WEBHOOK          http...wX  docs/notes.md:4    replace with ${SLACK_WEBHOOK} (value already in .env)
  7  AWS           AWS_ACCESS_KEY_ID      AKIA...M2  src/settings.py:2  move to .env, replace with ${AWS_ACCESS_KEY_ID}
  8  AWS           AWS_SECRET_ACCESS_KEY  1tUm...IU  src/settings.py:3  move to .env, replace with ${AWS_SECRET_ACCESS_KEY}
  9  Postgres      DATABASE_URL           post...pp  src/settings.py:4  move to .env, replace with ${DATABASE_URL}

Files holding secrets that cannot be fixed in place: 3  (a chosen file is moved whole to .secrets-quarantine; nothing in it is rewritten)
  #  File               Why / inside        Secrets           Action
  2  .env.example       example env file    Stripe sk_l...23  move to .secrets-quarantine/.env.example
  3  build/blob.txt.gz  gzip: blob.txt      Stripe sk_l...23  move to .secrets-quarantine/build/blob.txt.gz
  4  build/keys.zip     zip: conf/prod.env  Stripe sk_l...fE  move to .secrets-quarantine/build/keys.zip
  Offered because this run asks first: y moves them too, s lets you leave them in place. A --yes run moves files only with --quarantine.

Already encrypted with dotenvx (left as is): 1
  Key          Where
  DB_PASSWORD  config/.env.production:9

Other plaintext keys in env files: 3  (not flagged by TruffleHog; add --env-all to encrypt them too)
  .env: PORT, APP_NAME
  config/.env.production: LOG_LEVEL

Dry run: nothing was changed.
```

Reading the listing:

- Every run starts with where its log went and the notice about what the tool
  does; the last sentence of the notice names the mode.
- The **first table** is the secrets in text files that can be fixed in place.
  The Stripe key already lives in `.env`, so it is encrypted where it is. The
  webhook, the AWS pair and the database URL live in code and docs, so each is
  moved into `.env` and replaced by a placeholder; the second copy of the
  webhook in `docs/notes.md` reuses the entry the first one creates ("value
  already in .env").
- **Files holding secrets that cannot be fixed in place** lists each such file
  with the reason, for archives the file inside that holds the secret, the
  secret, and the action. The run is interactive, so they are offered for
  quarantine; `s` can leave any of them in place.
- **Already encrypted** shows what dotenvx already protects. **Other plaintext
  keys** are env values TruffleHog did not flag (`PORT=3000` is not a secret,
  but a plain password would land here too); `--env-all` encrypts them as well.
- The numbers are the handles for `s`. They run across both tables.

### Encrypt: the interactive run

The same command without `--dry-run` shows the same listing and then asks. `y`
does everything listed:

```
$ sweep-and-secure
...the listing above...

Encrypt 6 secret(s) and move 3 file(s) to quarantine now? [y/N/s]  (s = choose which): y
  [ok] added .env.keys* to /home/me/shop/.gitignore
  [ok] added /.secrets-quarantine/ to /home/me/shop/.gitignore

Encrypting ...
  [ok] .env: encrypted 5 key(s): STRIPE_SECRET_KEY, SLACK_WEBHOOK, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, DATABASE_URL
  [ok] config/app.json: replaced 1 occurrence(s) of 1 secret(s) with placeholders (SLACK_WEBHOOK)
  [ok] docs/notes.md: replaced 1 occurrence(s) of 1 secret(s) with placeholders (SLACK_WEBHOOK)
  [ok] src/settings.py: replaced 3 occurrence(s) of 3 secret(s) with placeholders (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, DATABASE_URL)
  [ok] .env.example: moved to .secrets-quarantine/.env.example
  [ok] build/blob.txt.gz: moved to .secrets-quarantine/build/blob.txt.gz
  [ok] build/keys.zip: moved to .secrets-quarantine/build/keys.zip

  [ok] private key file: .env.keys

Done: 5 secret(s) stored encrypted; 5 plaintext occurrence(s) removed from 3 file(s); 3 file(s) moved to .secrets-quarantine

Next steps
  1. Your files now contain placeholders such as ${SLACK_WEBHOOK} where secrets used to be. Change the code to
     read them from the environment instead (os.environ["SLACK_WEBHOOK"], process.env.SLACK_WEBHOOK, ...).
  2. Run your app through dotenvx so the values are decrypted at run time:
       dotenvx run -- <your command>
  3. 3 file(s) holding secrets were moved to .secrets-quarantine; its MANIFEST.txt and index.json map each one to where it came from.
     Nothing reads them from there. Fix or rebuild them without the secrets and move them back, or
     delete them; never commit that folder. If a file was tracked by git, commit its removal.
  4. The private decryption key lives in .env.keys.
     NEVER commit it. Share it through a password manager or your CI's secret store
     (the DOTENV_PRIVATE_KEY* variables). The encrypted .env files themselves are safe to commit.
  5. These secrets sat in plaintext, so treat them as exposed and rotate them.
     How-to guides:
       Stripe             https://howtorotate.com/docs/tutorials/stripe/
       SlackWebhook       https://howtorotate.com/docs/tutorials/slack-webhook/
     Rotate through the provider's console: AWS, Postgres
  6. Git history still holds the old plaintext. Check it with:  trufflehog git file://.
```

The `.gitignore` lines are written before anything is encrypted, so even an
interrupted run cannot leave `.env.keys` exposed. Everything under "Encrypting"
happens through the staging-and-verify path described above. `[ok]` means the
change was made; `[--]` is a warning about a change that was made (for example
a value that could not be checked because the private key for that file is not
on this machine, or a byte order mark that was removed); `[!!]` is a failure:
that file was left untouched, and the reason follows.

### What the files look like afterwards

```
$ cat .env
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY="02a1b2c3d4...e5f6" # -fk .env.keys

# .env
PORT=3000
STRIPE_SECRET_KEY=encrypted:BClCFQt3Fi1S...
APP_NAME=shop
SLACK_WEBHOOK='encrypted:BPyvIUm1ajXa...'
AWS_ACCESS_KEY_ID='encrypted:BLQdDU78sdrq...'
AWS_SECRET_ACCESS_KEY='encrypted:BLAYULRQNlAi...'
DATABASE_URL='encrypted:BD2/M0XgEC0E...'

$ cat src/settings.py
DEBUG = False
AWS_ACCESS_KEY_ID = "${AWS_ACCESS_KEY_ID}"
AWS_SECRET_ACCESS_KEY = "${AWS_SECRET_ACCESS_KEY}"
DATABASE_URL = "${DATABASE_URL}"

$ cat config/app.json
{
  "name": "shop",
  "port": 3000,
  "slack": {
    "webhook": "${SLACK_WEBHOOK}"
  }
}

$ cat .gitignore
node_modules/
__pycache__/

# dotenvx private decryption keys - never commit (added by sweep_and_secure.py)
.env.keys*

# files with secrets moved to quarantine - never commit (added by sweep_and_secure.py)
/.secrets-quarantine/

$ cat .secrets-quarantine/MANIFEST.txt
2026-10-23T10:33:49Z  .env.example  <- .env.example  (Stripe)  why: example env file
2026-10-23T10:33:49Z  build/blob.txt.gz  <- build/blob.txt.gz  (Stripe)  why: gzip archive  inside: blob.txt
2026-10-23T10:33:49Z  build/keys.zip  <- build/keys.zip  (Stripe)  why: zip archive  inside: conf/prod.env

$ cat .secrets-quarantine/index.json
[
  {
    "quarantined": ".env.example",
    "original": ".env.example",
    "original_absolute": "/home/me/shop/.env.example",
    "moved_at": "2026-10-23T10:33:49Z",
    "why": "example env file",
    "detectors": [
      "Stripe"
    ],
    "inside": []
  },
  {
    "quarantined": "build/blob.txt.gz",
    "original": "build/blob.txt.gz",
    "original_absolute": "/home/me/shop/build/blob.txt.gz",
    "moved_at": "2026-10-23T10:33:49Z",
    "why": "gzip archive",
    "detectors": [
      "Stripe"
    ],
    "inside": [
      "blob.txt"
    ]
  },
  {
    "quarantined": "build/keys.zip",
    "original": "build/keys.zip",
    "original_absolute": "/home/me/shop/build/keys.zip",
    "moved_at": "2026-10-23T10:33:49Z",
    "why": "zip archive",
    "detectors": [
      "Stripe"
    ],
    "inside": [
      "conf/prod.env"
    ]
  }
]
```

(The ciphertexts are shortened here; real ones are longer.) The `.env` file,
`src/settings.py` and `config/app.json` can be committed. `.env.keys` and
`.secrets-quarantine/` must not be, and are now ignored. The manifest and the
index map every quarantined file to where it came from; a file whose quarantine
name was already taken gets a numeric suffix (`keys.zip.1`), and the records
carry the name actually used.

### Running it again

A second run finds nothing to do and shows what is protected. Running after an
interruption, or after adding one more secret to a file, picks up exactly what
is still in plaintext; values already stored are recognised and never stored
twice.

```
$ sweep-and-secure --dry-run
sweep-and-secure 1.4.0  (TruffleHog + dotenvx)
Log: /home/me/.local/state/sweep-and-secure/logs/2026-10-23T10-33-49Z-shop-48213.log
Folder: /home/me/shop
  Note: this is a security tool that changes files on purpose: it encrypts env files, rewrites
  source files and moves files to quarantine. The changes are deliberate and it cannot undo them;
  commit or back up first. This is a dry run: nothing is changed.
  [ok] trufflehog  3.99.3     /usr/local/bin/trufflehog
  [ok] dotenvx     2.38.2     /usr/local/bin/dotenvx
Scanning with TruffleHog (this can take a while on big trees) ...
  Scanned 8 file(s) in 0:02; TruffleHog reported 0 finding(s).

TruffleHog found no plaintext secrets to encrypt.

Already encrypted with dotenvx (left as is): 6
  Key                    Where
  STRIPE_SECRET_KEY      .env:9
  SLACK_WEBHOOK          .env:11
  AWS_ACCESS_KEY_ID      .env:12
  AWS_SECRET_ACCESS_KEY  .env:13
  DATABASE_URL           .env:14
  DB_PASSWORD            config/.env.production:9

Other plaintext keys in env files: 3  (not flagged by TruffleHog; add --env-all to encrypt them too)
  .env: PORT, APP_NAME
  config/.env.production: LOG_LEVEL

Nothing to encrypt.
```

### Choosing which items

`s` at the question takes item numbers (`1 3 5-7`, or `all`). Here only the AWS
pair is encrypted; everything else, the quarantine candidates included, is left
in place and counted as needing attention:

```
Encrypt 6 secret(s) and move 3 file(s) to quarantine now? [y/N/s]  (s = choose which): s
Numbers to encrypt (e.g. 1 3 5-7, or 'all'; empty to go back): 7-8
Selected: #7 AWS_ACCESS_KEY_ID, #8 AWS_SECRET_ACCESS_KEY
Go ahead with these 2? [Y/n]: y
  [ok] added .env.keys* to /home/me/shop/.gitignore

Encrypting ...
  [ok] .env: encrypted 2 key(s): AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  [ok] src/settings.py: replaced 2 occurrence(s) of 2 secret(s) with placeholders (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

  [ok] private key file: .env.keys

Done: 2 secret(s) stored encrypted; 2 plaintext occurrence(s) removed from 1 file(s); 3 file(s) need manual attention (see above)
```

### Saying no

`n`, or no answer at all, changes nothing and exits with code 2, so a script
that forgot `--yes` fails visibly instead of silently doing nothing. (The one
thing a declined run still does is remove leftover staging files that an
earlier interrupted run left behind, which it reports; they may hold a
plaintext copy of an env file. Names starting with `.sweep-and-secure-` are
reserved for that staging.)

```
Encrypt 6 secret(s) and move 3 file(s) to quarantine now? [y/N/s]  (s = choose which): n
Nothing encrypted.
$ echo $?
2
```

### Unattended runs: scripts and CI

`--yes` encrypts everything listed without asking. It never moves files it was
not told to, so the files that cannot be fixed in place stay where they are
unless `--quarantine` is given:

```
$ sweep-and-secure --yes
...
Files holding secrets that cannot be fixed in place: 3  (not rewritten; with --yes, pass --quarantine to move them out of the tree)
  #  File               Why / inside        Secrets           Action
  -  .env.example       example env file    Stripe sk_l...23  stays in place (pass --quarantine to move it)
  -  build/blob.txt.gz  gzip: blob.txt      Stripe sk_l...23  stays in place (pass --quarantine to move it)
  -  build/keys.zip     zip: conf/prod.env  Stripe sk_l...fE  stays in place (pass --quarantine to move it)
...
Done: 5 secret(s) stored encrypted; 5 plaintext occurrence(s) removed from 3 file(s); 3 file(s) need manual attention (see above)
```

```
$ sweep-and-secure --yes --quarantine
...
  [ok] .env.example: moved to .secrets-quarantine/.env.example
  [ok] build/blob.txt.gz: moved to .secrets-quarantine/build/blob.txt.gz
  [ok] build/keys.zip: moved to .secrets-quarantine/build/keys.zip
Done: 5 secret(s) stored encrypted; 5 plaintext occurrence(s) removed from 3 file(s); 3 file(s) moved to .secrets-quarantine
```

The exit code tells a script how it went: 0 done, 1 something failed (the
state of the tree is printed), 2 no confirmation. A CI audit that should only
report uses `--dry-run`.

### Encrypting every env key

TruffleHog flags credentials it recognises. `--env-all` also encrypts every other
plaintext key in the env files, which is what you want when a `.env` holds a
plain password or any value you would rather not have readable:

```
$ sweep-and-secure --dry-run --env-all
...
Plaintext secrets found: 9 in 5 file(s)
  #   Type          Key / name             Secret     Where                     Action
  1   env file      PORT                   ***        .env:1                    encrypt in place
  2   Stripe        STRIPE_SECRET_KEY      sk_l...23  .env:2                    encrypt in place
  3   env file      APP_NAME               ***        .env:3                    encrypt in place
  7   env file      LOG_LEVEL              ***        config/.env.production:8  encrypt in place
  8   SlackWebhook  SLACK_WEBHOOK          http...wX  config/app.json:5         move to .env, replace with ${SLACK_WEBHOOK}
  9   SlackWebhook  SLACK_WEBHOOK          http...wX  docs/notes.md:4           replace with ${SLACK_WEBHOOK} (value already in .env)
  10  AWS           AWS_ACCESS_KEY_ID      AKIA...M2  src/settings.py:2         move to .env, replace with ${AWS_ACCESS_KEY_ID}
  11  AWS           AWS_SECRET_ACCESS_KEY  1tUm...IU  src/settings.py:3         move to .env, replace with ${AWS_SECRET_ACCESS_KEY}
  12  Postgres      DATABASE_URL           post...pp  src/settings.py:4         move to .env, replace with ${DATABASE_URL}
...
```

### Using the encrypted values

dotenvx decrypts at run time, so your program sees ordinary environment
variables:

```
dotenvx run -- python src/app.py
```

The private key comes from `.env.keys` next to the env file, or from the
`DOTENV_PRIVATE_KEY` environment variable, which is how CI and servers get it:
put the value from `.env.keys` into your CI's secret store and run the same
command there. An env file in a sub-folder has its own key variable
(`config/.env.production` gets `DOTENV_PRIVATE_KEY_PRODUCTION`), and dotenvx
only looks for `.env.keys` next to the env file, so for those the "Next steps"
print the command with `-fk`:

```
dotenvx run -f config/.env.production -fk .env.keys -- python src/app.py
```

To add a secret later, either run sweep-and-secure again or use dotenvx
directly: `dotenvx set NEW_KEY "value"` encrypts it straight into `.env`.

### Other things you can do

- Keep the moved secrets in a different file: `sweep-and-secure --env-file
  config/secrets.env`.
- Use your language's own lookup as the placeholder:
  `sweep-and-secure --placeholder 'process.env.NAME'` or
  `--placeholder 'os.environ["NAME"]'`.
- Store the secrets encrypted but leave the source files as they are, to change
  the code at your own pace: `sweep-and-secure --no-rewrite`. A later run
  without the flag does only the rewriting.
- Leave test fixtures alone: `sweep-and-secure --exclude '(^|/)fixtures(/|$)'`.
- Scan `node_modules` and `.git` as well: `--no-default-excludes`.
- Move the quarantined files to a folder outside the tree:
  `sweep-and-secure --quarantine-dir ../quarantine`.
- Ask TruffleHog to verify credentials against the issuing services (this
  sends them over the network): `--verify`; live ones are marked `*`.
- Sweep a folder other than the current one: `sweep-and-secure path/to/project`.
- See every command the script runs: `-v`. Keep the run's log somewhere else,
  or not at all: `--log-dir DIR`, `--no-log`.

## Reference

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
  was not told to. Without `--yes` the question is asked even when stdin is not
  a terminal and the answer is read from there: a piped `y` is accepted, and no
  input at all (end of file) counts as no, so the run lists the findings and
  exits 2.
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
- `--quarantine`: with `--yes`, also move every file that holds a secret and
  cannot be fixed in place (archives, binaries, PDFs, generated lock files,
  example env files, files too large or unreadable, text files whose only
  secrets are encoded, too short or unstorable) out of the tree into the
  quarantine folder, `.secrets-quarantine` inside the swept folder by default,
  keeping its relative path (`build/keys.zip` becomes
  `.secrets-quarantine/build/keys.zip`, with a numeric suffix if that name is
  taken). The folder's `MANIFEST.txt` gets a line per file and its `index.json`
  a record per file: the time, the stored name, the original path, the reason,
  the detectors and, for archives, the files inside that held the secrets. The
  folder is added to `.gitignore` before anything is moved and is never scanned
  afterwards. An interactive run offers this without the flag: the files appear
  as numbered items ("move to ..."), `y` includes them and `s` lets you leave
  them out. Every run, with or without the flag, lists these files in their own
  section with the reason, so you can see what you would be moving. A text file
  some of whose secrets are fixed in place is never moved; symbolic links are
  never moved.
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
  install links. Nothing is scanned and nothing in the folder is touched.

**Output**

- `-v`, `--verbose`: print every command run (TruffleHog, `dotenvx encrypt`, and
  the `dotenvx get` calls that verify each stored value) and the tools' output.
  Secret values are never printed, only key names and masked previews.
- `--log-dir DIR`: write this run's log into DIR instead of the user's log folder
  (`~/.local/state/sweep-and-secure/logs`, `~/Library/Logs/sweep-and-secure`,
  `%LOCALAPPDATA%\sweep-and-secure\logs`; `SWEEP_AND_SECURE_LOG_DIR` also
  overrides it). `--no-log`: write no log. The newest 100 logs are kept.
- `--no-color`: plain output. Colour is only used on a terminal, and the
  `NO_COLOR` environment variable has the same effect.
- `-h`, `--help`: the short reference. `--version`: print
  `sweep-and-secure <version>`. Both exit at once, before the tools are looked
  for.

While TruffleHog runs, a status line shows how many files it has scanned, how
many findings it has reported so far and the time spent, redrawn in place on a
terminal and printed as a heartbeat line every 15 seconds when the output is a
pipe or a CI log, so a long scan is visibly alive rather than hung. It ends with
`Scanned N file(s) in M:SS; TruffleHog reported K finding(s).`

### Exit codes

| code | meaning |
| --- | --- |
| 0 | done, or nothing to do; also every dry run whose scan completed, and a setup check that passed |
| 1 | a tool is missing or unusable (also the setup check's verdict when a tool is missing or fails its trial run); the scan failed or was cut short; an encryption or its verification failed; or an unexpected error stopped the run, in which case the state of the tree is printed |
| 2 | you answered no, or gave no answer: stdin was not a terminal, nothing was piped in and `--yes` was not given |
| 130 | interrupted with Ctrl-C; what had already been changed is printed |

### Checking a download by hand

The curl installer verifies the script against the release's checksums. To do
it yourself for a downloaded `sweep_and_secure.py`, from the folder it was
downloaded into:

```
curl -sSfL -O https://github.com/voxgig/sweep-and-secure/releases/download/v1.4.0/SHA256SUMS
```

```
grep ' sweep_and_secure.py$' SHA256SUMS | sha256sum -c -
```

On macOS use `shasum -a 256 -c -` in place of `sha256sum -c -`.

### Limitations

* TruffleHog only knows the credential formats it has detectors for; a plain
  `DB_PASSWORD=hunter2` in a `.env` file is listed under "other plaintext keys"
  and is encrypted only with `--env-all`.
* Several TruffleHog detectors match long random-looking strings, so package
  integrity hashes in `package-lock.json`, `yarn.lock`, `go.sum` and Python lock
  files show up as findings. Matches that sit inside such a hash are set aside
  and counted rather than treated as secrets. A lock file that still appears in
  the listing holds something outside a hash, such as a token in a registry URL,
  and `--verify` lets TruffleHog confirm a credential against its service.
* Secrets inside binaries, PDFs, lock files or base64-encoded text are never
  rewritten; such files can only be moved to the quarantine folder as a whole,
  and so can archives (TruffleHog looks inside them). The listing shows which
  files inside hold the secrets for zip, tar (any compression), gzip, bzip2 and
  xz archives, nested up to three deep and up to 512 MB of content; 7z, rar and
  zstd archives cannot be opened from here and are listed with their secrets
  only.
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
* An old TruffleHog release works but knows fewer credential formats, so a sweep
  with one may find less than a sweep with the current release.
* Python 3.8 or newer is needed. The script still carries Python 2.7
  compatibility code and may well work there, but only 3.8 to 3.13 are tested.

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
wheel, runs the console script and exercises `install.sh` with and without the
tools present.

To release: set `__version__` in `sweep_and_secure.py`, merge, then either push
a matching tag (`git tag v1.4.0 && git push origin v1.4.0`) or run the release
workflow from the Actions tab with the version, which creates the tag for you.
The workflow (`.github/workflows/release.yml`) checks that the tag matches the
version, runs the tests, builds the sdist and wheel, and publishes a GitHub
release carrying the script, `install.sh`, both packages and `SHA256SUMS`, which
is what the curl installer and `pipx install ...@vX.Y.Z` fetch.
