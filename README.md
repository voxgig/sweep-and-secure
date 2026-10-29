# sweep-and-secure

Find the API keys, tokens and passwords sitting in plaintext in a project
folder, and lock them away. One command scans the tree with
[TruffleHog](https://trufflesecurity.com/trufflehog), shows you everything it
found and what it intends to do, and, once you say yes, encrypts the secrets
with [dotenvx](https://dotenvx.com), replaces the plaintext in your files with
placeholders, and moves the files it cannot fix in place (archives, binaries,
PDFs, lock files, example env files, SSH keys without a passphrase) out of the
tree into an encrypted quarantine folder that remembers where each came from. A
private key file is never rewritten: a passphrase-protected one is left where it
is, and the run prints the `ssh-keygen` line that adds or upgrades a passphrase.
The keys are dotenvx's
to keep: a fresh private key goes into the operating system's secret store
where dotenvx can put it, into `.env.keys` where it cannot, and the run ends
with a short dotenvx primer, because from then on dotenvx is the tool you use;
this one sets things up as securely as the machine allows and gets out of the
way. It is one Python file with no dependencies of its own, runs on Linux, macOS
and Windows, keeps a log of every run, and is built so that no file is ever left
half-written: each file is changed completely or not at all, an interrupted run
says what it did, and running again finishes the job.

- [What it does](#what-it-does)
- [Install](#install)
- [Examples](#examples)
- [For agents and scripts](#for-agents-and-scripts)
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
   binary, a PDF, a lock file, an example env file, a private key file without a
   passphrase) is moved whole into a quarantine folder when you choose it,
   encrypted there with openssl under a passphrase that dotenvx keeps, and the
   folder's manifest and index record where it came from. A private key file is
   never rewritten, since ssh and servers read a key from its file; one with a
   passphrase is left alone, and the listing prints the `ssh-keygen` line that
   adds a passphrase to a bare key or upgrades one set with the legacy PEM cipher
   (see [SSH keys and other private key files](#ssh-keys-and-other-private-key-files)).
5. **dotenvx keeps the keys.** A fresh private key goes into the operating
   system's secret store (macOS Keychain, Windows Credential Manager, Linux
   Secret Service) through `dotenvx native up` where this dotenvx and machine
   allow, else into `.env.keys` next to the env file, and the run says which and
   why; an env file that already had a key pair keeps it. Nothing is ever
   written in plaintext to disk that was not there before.
6. **It tells you what is left to do, and hands over to dotenvx.** Change the
   code to read the variables, run your program through `dotenvx run`, keep
   `.env.keys` out of git, rotate the exposed credentials (with links to the
   rotation guides), check git history; and, the first time, a short primer:
   `dotenvx run`, `get`, `set`, `keypair`, where dotenvx looks for the key, and
   where the docs are. This tool is not needed day to day.

### What happens to each kind of finding

| where it was found | what is done |
| --- | --- |
| a dotenv file (`.env`, `.env.production`, `prod.env`, ...), as the value of `KEY=...` | `dotenvx encrypt -k KEY` encrypts that key in place: `KEY="encrypted:..."`. Every key whose value holds the secret is encrypted, not just the first |
| anywhere else (source code, JSON, YAML, Markdown, certificates, ...) | the value is added to the project's `.env` (`--env-file` to change) and encrypted there; the plaintext in the file is replaced by `${KEY}` (`--placeholder` to change) |
| a file that cannot be fixed in place: an archive TruffleHog looked inside (`.zip`, `.jar`, `.tar.gz`, ...), a binary, a PDF, a generated lock file (`package-lock.json`, `poetry.lock`, ...), an example env file (`.env.example`, `.env.sample`, ...), a file too large or unreadable, or a text file whose only secrets are encoded, shorter than `--min-length` or impossible for dotenvx to store exactly | listed in the "Files holding secrets that cannot be fixed in place" section with the reason, and for archives the files inside that hold each secret (zip, tar with any compression, gzip, bzip2 and xz are opened, nested ones too). The whole file is moved out of the tree into the quarantine folder (`.secrets-quarantine` in the swept folder, `--quarantine-dir` to change), keeping its relative path plus `.enc`: openssl encrypts it (AES-256) under a fresh passphrase, which dotenvx keeps encrypted in the folder's own `.env`, so no plaintext copy of the secret is left anywhere; the folder's `MANIFEST.txt` and `index.json` record where it came from, why, which files inside held secrets and how to get it back (`--restore`). An interactive run offers this as a numbered item, so `s` can leave a file in place; a `--yes` run moves files only when `--quarantine` is given |
| a private key file: nothing but PEM blocks, a private key among them (`id_ed25519`, `id_rsa`, a `.pem` or `.key` file, a certificate with its key) | never rewritten: ssh and servers read a key from its file, and `${KEY}` in it would break them. Listed in a "Private key files" section with whether a passphrase protects it, read from the file itself: `none`, `yes (OpenSSH format, aes256-ctr, bcrypt)`, `yes, legacy PEM cipher (AES-128-CBC)` or `yes (PKCS#8)`. One without a passphrase is offered to the quarantine like any file that cannot be fixed in place, unless it lies in a `.ssh` folder, where ssh needs it; one with a passphrase is left where it is. For every bare key the listing prints `ssh-keygen -p -a 100 -f KEY` (a PEM key gets `-o` too, which rewrites it in the OpenSSH format, so only for a key ssh uses), and for a legacy-cipher passphrase `ssh-keygen -p -o -a 100 -f KEY` |
| a text file some of whose secrets are fixed in place and one of which cannot be (encoded, too short, unstorable) | the fixable ones are handled; the file is listed with the other one for you to handle by hand, and is never moved, because moving it would undo the fixes |
| a symbolic link | listed; fix the file it points to |
| a match that sits inside a package integrity hash (`sha512-...` in `package-lock.json` or `yarn.lock`, `h1:...` in `go.sum`, `sha256:...` in a Python lock file), or that is a commit id or checksum where the file vouches for it: a dependency pinned to a commit in a manifest (`"cloudflare": "github:cloudflare/node-cloudflare#<commit>"` in `package.json`, `rev = "<commit>"` in `Cargo.toml`, `git+https://...git@<commit>` in `requirements.txt`, `?ref=<commit>` in a Terraform source), an action pinned to one in a workflow (`uses: owner/action@<commit>`), a `gitHead`, `shasum`, `rev`, `ref` or `commit` field, a URL's fragment or path (the sha1 fragment of a `resolved` URL in `yarn.lock`, a commit link in a changelog), and in a generated lock file also a checksum or reference field (`Cargo.lock`, `composer.lock`, `Gemfile.lock`), a `mix.lock` entry or a checksum section (`Podfile.lock`); or that is a run of a package archive's file name in a registry URL (`helper-explode-assignable-expression-7.18.6.tgz`, which an older TruffleHog's Signable detector took for a token because the word `assignable` stands just before it) or of the path segment that name repeats | set aside and counted, not treated as a secret: those are public identifiers that happen to match a detector's pattern, which TruffleHog's keyword detectors do whenever the word `cloudflare`, `sentry`, `datadog` and so on stands within 40 characters before them (every release from 3.6 to 3.99 does this). Only a digest of its algorithm's exact length counts, and outside lock files only one written in hex; a digest in a URL's user information (`user:secret@host`), after `=` (`?token=...`), after a word like `token` or `password`, or in any place the file does not vouch for stays a finding; and each set-aside is named in the run log |
| a match that TruffleHog's current detectors would not report, from an older release: a 3.5x release's PagerDuty pattern takes any 20-character run within 40 characters of the letters `pd` for a key, where 3.60 and later require the `u+` that PagerDuty user tokens carry; a Signable match after the word `assignable` or `designable`, which the detector now excludes itself; a finding of a detector TruffleHog has since removed (Etsy, which took any 24-character run near the word `etsy` for a key, and six others); and, from a release before 3.75, a match that TruffleHog's own false-positive filter drops: one holding a placeholder term (`example`, `sample`, `abcde`, ...) or one that reads as an identifier (common words joined camelCase or with `-` and `_`). Those releases ran the filter only while verifying, so with this tool's default `--no-verification` nothing was filtered; 3.75 and later run it whatever the flags | set aside and counted ("Set aside N finding(s) that TruffleHog's current detectors would not report"): the current detectors' behaviour is applied to the older release's findings and each is named in the run log; a finding that `--verify` confirmed live is never set aside |
| a match inside a base64 blob: the payload of a `data:` URI (an inline image or font in CSS or HTML), or a run of 128 or more base64 characters outside a URL, at least twice as long as the match, with the match well inside it | set aside and counted with the hashes: a pattern that lines up with encoded bytes is noise, and a secret inside such a blob is itself encoded, which TruffleHog reports decoded. A finding that `--verify` confirmed live is never set aside this way |
| a program or library: `.so`, `.dll`, `.dylib`, `.exe`, `.o`, `.a`, `.pyc`, `.class`, `.wasm`, ... or a file whose first bytes say ELF, PE, Mach-O or WebAssembly | not scanned, and counted: "Skipped N compiled file(s)". A secret compiled into a program cannot be fixed here, and moving the file would break whatever uses it; what an old TruffleHog matches in such files is mostly exported symbol names (TruffleHog 3.75 and later skip them itself). `--scan-compiled` lists what TruffleHog finds in them, each match with the string around it as `strings` would show it, and never rewrites or moves them |

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
- The private key (`DOTENV_PRIVATE_KEY`, one per env file) is in the operating
  system's secret store, kept by dotenvx, when dotenvx 2.3 or later could put it
  there (the macOS Keychain, the Windows Credential Manager, the Linux Secret
  Service of a desktop session). Otherwise it is in `.env.keys` next to the env
  file, which is added to `.gitignore` before anything is encrypted, and the run
  says why it is there (an older dotenvx, a server without a keyring,
  `--no-native`). Either way CI and other machines get it as the
  `DOTENV_PRIVATE_KEY` environment variable; `dotenvx keypair DOTENV_PRIVATE_KEY
  -f .env` prints it.
- Source files hold `${KEY}` where the secrets were. The code still has to be
  changed to read the variable (`os.environ["KEY"]`, `process.env.KEY`, ...);
  the placeholder removes the secret and marks the spot.
- `.secrets-quarantine/` holds the files that were moved, under their original
  relative paths plus `.enc` (`build/keys.zip` becomes `build/keys.zip.enc`; a
  numeric suffix such as `keys.zip.1.enc` when that name is already taken there,
  or would be one of the folder's own files). Each is AES-256 encrypted by
  openssl under a passphrase of its own, kept as `QUARANTINE_KEY_<n>` in the
  folder's `.env`, encrypted by dotenvx to the same key pair as the project's
  env file (or to a key pair of its own when the project has none). Its
  `MANIFEST.txt` starts with the restore recipe and has one line per file; its
  `index.json` has one record per file: the stored name, the original path
  (relative and absolute), when it was moved, why, the detectors, for archives
  the files inside that held secrets, and the key, cipher, SHA-256, size and
  mode of the original. The folder is git-ignored and never scanned.
  `sweep-and-secure --restore build/keys.zip` puts a file back, decrypted and
  checked against the recorded digest, once it no longer has to hold the secret.
- A log of the run is in the user's log folder (see below).
- Your program runs as `dotenvx run -- <command>`: dotenvx finds the private
  key (environment, `.env.keys`, secret store), decrypts the values and hands
  them to the program as ordinary environment variables. From here on dotenvx is
  the tool in use (`dotenvx get`, `dotenvx set`, ...); the run that set it up
  ends with a primer.

### Who keeps the keys

sweep-and-secure sets dotenvx up as securely as the machine allows and then
hands over; it keeps no keys and takes no part in day-to-day use.

- A fresh key pair's private key is dotenvx's to keep. dotenvx 2.3 and later
  can hold it in the operating system's secret store (the macOS Keychain, the
  Windows Credential Manager, the Linux Secret Service), protected by your login
  and with nothing left on disk; the run asks dotenvx to put it there
  (`dotenvx native up`) and reports `private key of .env: in the macOS Keychain,
  kept by dotenvx (nothing on disk)`. Where that is not possible (an older
  dotenvx, a server without a keyring, `--no-native`, `DOTENVX_NO_NATIVE=true`)
  the key stays in `.env.keys` next to the env file and the report says why:
  `private key file: .env.keys  (file custody: failed to save private key to
  Linux Secret Service)`. Later, `dotenvx native up -f .env` moves it into the
  store and `dotenvx native down -f .env` brings it back to the file.
- An env file that already had a key pair keeps it; the run never makes a
  second one for it. When its private key sits in a `.env.keys` file and
  dotenvx could keep it in the secret store, the run lists that under "Setup
  to tighten" and offers to move it there (`dotenvx native up`, checked by
  decrypting a value afterwards; `dotenvx native down` puts it back if that
  fails). `--yes` does it without asking; `--no-native` leaves it in the file.
  The same offer covers files an earlier version moved to the quarantine as
  they were: they are encrypted in place, their passphrases kept by dotenvx.
  A run with nothing to encrypt still says where each env file's key is.
- On CI (the `CI` variable set) keys stay in files, as dotenvx itself keeps
  them there: an ephemeral runner's secret store is gone with the runner.
- The quarantine's passphrases are encrypted to the project's key pair whenever
  its private key is at hand here, so one key opens everything; a project with
  nothing but files to quarantine gets one key pair for the quarantine, under
  the same rules.
- dotenvx looks for a private key in the `DOTENV_PRIVATE_KEY*` environment
  variables, then in `.env.keys` next to the env file, then in the secret store
  (and the password managers it supports), matching key to file by public key.
  That is how another machine or CI gets access: `dotenvx keypair
  DOTENV_PRIVATE_KEY -f .env` prints the key, and it goes into the CI's secret
  store as `DOTENV_PRIVATE_KEY`.
- Nothing in this tool is needed afterwards: `dotenvx run`, `dotenvx get` and
  `dotenvx set` do the daily work, and a run that created a key pair ends with a
  primer saying so. A dry run on a project that has no dotenvx yet ends with
  one line to the same effect.

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
`--log-dir DIR` choose another, `--no-log` writes none. The newest 100 of its
logs are kept; other files in the folder are never touched. Each run prints
`Log: <path>` as its second line.

A run that changes files leaves a second file that is never pruned: a run
record, in Markdown, so that whoever comes back to the project later, a person
or an agent, can see what that run did and how to live with the result. It
says what changed (which keys went into which env file, from where, what
replaced them, which files moved to quarantine and how they are encrypted),
where each private key is, the dotenvx commands that use the values from now
on, what to do when something is wrong (a value that does not decrypt, a key
needed on another machine, a quarantined file wanted back), and then the full
output of the run as the log has it, prompts, answers and tool commands
included, down to the exit code. Dry runs, declined runs and runs that found
nothing to do leave none. The folder is `~/.local/state/sweep-and-secure/runs`
on Linux, `~/Library/Application Support/sweep-and-secure/runs` on macOS and
`%LOCALAPPDATA%\sweep-and-secure\runs` on Windows; `SWEEP_AND_SECURE_RECORD_DIR`
or `--record-dir DIR` choose another, `--no-record` writes none. The run prints
`Run record: <path>` as its last lines. Like the log, a record never holds a
secret value.

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
value has been stored. A file goes to quarantine by being encrypted into place,
decrypted again into the staging folder and compared with the original, its
passphrase stored through the same staging-and-verify path, and only then is the
original removed; if any step fails the encrypted copy is deleted and the
original stays. (Without openssl the file is renamed, or copied and verified
when the quarantine folder is on another disk.) The move is recorded in the
folder's manifest and index.

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
- It does not edit binaries, PDFs, lock files or private key files, and it does
  not edit inside archives; such files are moved whole to quarantine, or left
  for you. It does not add a passphrase to a key either: that needs you to
  choose one, so it prints the `ssh-keygen` line instead.
- It does not scan programs and libraries unless asked (`--scan-compiled`), and
  it never changes them: a credential compiled into a program has to be rotated,
  and the program rebuilt without it.
- It does not hold the keys or take part in regular use. dotenvx keeps the
  private key (secret store or `.env.keys`) and decrypts at run time; this tool
  only sets that up, and runs again only when new secrets turn up.

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

To pin a release, append `@v1.7.0` to the git URL, or pass `-v v1.7.0` to the
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

openssl is optional: it encrypts the files moved to quarantine. Linux and macOS
ship it, and Git for Windows carries one that the tool finds on its own;
`--openssl PATH` names another. Without it quarantined files are moved as they
are, and the run says so.

### 3. Check the setup

```
sweep-and-secure --check-setup
```

This finds both tools (and git and openssl, which are optional) the way a run
does, prints their versions and locations, and tries each one out in a scratch
folder under the system temp folder: TruffleHog scans a file that holds no
secret, dotenvx encrypts a throw-away value and decrypts it back, and the report
says where its private key went on this machine: into the secret store and out
again, or into `.env.keys`, and why. Nothing in the current folder is read or
written.
Exit code 0 means a real run will work; 1 names what is missing or broken, with
install links, and every tool is checked before the verdict so one report lists
everything.

```
$ sweep-and-secure --check-setup
sweep-and-secure 1.7.0  (TruffleHog + dotenvx)
Log: /home/me/.local/state/sweep-and-secure/logs/2026-10-23T16-38-58Z-shop-48213.log
Python 3.13.16 (/usr/bin/python3) on Linux-6.8.0-x86_64-with-glibc2.39
  [ok] trufflehog  3.99.3     /usr/local/bin/trufflehog
  [ok] dotenvx     2.38.2     /usr/local/bin/dotenvx
  [ok] git         2.43.0     /usr/bin/git  (optional: keeps .env.keys out of commits)
  [ok] openssl     3.0.13     /usr/bin/openssl  (optional: encrypts quarantined files; key derivation pbkdf2)
  Scanned 1 file(s) in 0:03; TruffleHog reported 0 finding(s).
  [ok] trufflehog  ran in a scratch folder: exit status 0, 1 file(s) scanned, no findings
  [ok] dotenvx     ran in a scratch folder: encrypted a value, decrypted it back; the private key went to .env.keys (failed to save private key to Linux Secret Service)

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
sweep-and-secure 1.7.0  (TruffleHog + dotenvx)
Log: /home/me/.local/state/sweep-and-secure/logs/2026-10-23T16-39-04Z-shop-48213.log
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

Files holding secrets that cannot be fixed in place: 3  (a chosen file is moved whole to .secrets-quarantine, AES-256 encrypted, its passphrase kept by dotenvx; nothing in it is rewritten)
  #  File               Why / inside        Secrets                    Action
  2  .env.example       example env file    Stripe sk_l...23 (line 2)  move to .secrets-quarantine/.env.example.enc (encrypted)
  3  build/blob.txt.gz  gzip: blob.txt      Stripe sk_l...23           move to .secrets-quarantine/build/blob.txt.gz.enc (encrypted)
  4  build/keys.zip     zip: conf/prod.env  Stripe sk_l...fE           move to .secrets-quarantine/build/keys.zip.enc (encrypted)
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
  quarantine; `s` can leave any of them in place. The header says how they will
  be moved: encrypted, with the passphrase kept by dotenvx, or as they are when
  there is no openssl.
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
  [ok] .env.example: moved to .secrets-quarantine/.env.example.enc (encrypted)
  [ok] build/blob.txt.gz: moved to .secrets-quarantine/build/blob.txt.gz.enc (encrypted)
  [ok] build/keys.zip: moved to .secrets-quarantine/build/keys.zip.enc (encrypted)

  [ok] .secrets-quarantine/.env holds the quarantine's passphrases, encrypted to the key pair of .env
  [ok] private key file: .env.keys  (file custody: failed to save private key to Linux Secret Service)

Done: 5 secret(s) stored encrypted; 5 plaintext occurrence(s) removed from 3 file(s); 3 file(s) moved to .secrets-quarantine (encrypted)

Next steps
  1. Your files now contain placeholders such as ${SLACK_WEBHOOK} where secrets used to be. Change the code to
     read them from the environment instead (os.environ["SLACK_WEBHOOK"], process.env.SLACK_WEBHOOK, ...).
  2. Run your app through dotenvx so the values are decrypted at run time:
       dotenvx run -- <your command>
  3. 3 file(s) holding secrets were moved to .secrets-quarantine, AES-256 encrypted; the passphrase of each is kept in
     .secrets-quarantine/.env, encrypted by dotenvx with the key pair of .env. MANIFEST.txt and index.json map each file to where it came from.
     Put one back with  sweep-and-secure --restore <stored name>  once it no longer has to hold the secret, or delete it;
     never commit that folder. If a file was tracked by git, commit its removal.
  4. The private decryption key lives in .env.keys.
     NEVER commit it. Share it through a password manager or your CI's secret store
     (the DOTENV_PRIVATE_KEY* variables). The encrypted env files themselves are safe to commit.
  5. These secrets sat in plaintext, so treat them as exposed and rotate them.
     How-to guides:
       Stripe             https://howtorotate.com/docs/tutorials/stripe/
       SlackWebhook       https://howtorotate.com/docs/tutorials/slack-webhook/
     Rotate through the provider's console: AWS, Postgres
  6. Git history still holds the old plaintext. Check it with:  trufflehog git file://.

dotenvx from here on
  This tool has done its part: the secrets are encrypted in your env files, and the private key that
  decrypts them is in .env.keys next to each env file. Day to day you use dotenvx itself, not this tool:
    dotenvx run -- <your command>              runs a program with the decrypted values in its environment
    dotenvx get KEY                            prints one decrypted value; without KEY, all of them
    dotenvx set KEY "value"                    adds or changes a value, encrypted on the way in: the file never holds plaintext
    dotenvx keypair DOTENV_PRIVATE_KEY         prints the private key, to give another machine or CI as the DOTENV_PRIVATE_KEY variable
    dotenvx native up                          moves the private key from .env.keys into the Linux Secret Service, so that nothing is left on disk
    sweep-and-secure --restore <stored name>   puts a quarantined file back, decrypted (its passphrase is in .secrets-quarantine/.env)
  dotenvx looks for the private key in the DOTENV_PRIVATE_KEY* variables of the environment, then in .env.keys
  next to the env file, then in the Linux Secret Service. To add a secret found later, run this tool again or use dotenvx set.
  Docs: https://dotenvx.com/docs
```

The `.gitignore` lines are written before anything is encrypted, so even an
interrupted run cannot leave `.env.keys` exposed. Everything under "Encrypting"
happens through the staging-and-verify path described above. `[ok]` means the
change was made; `[--]` is a warning about a change that was made (for example
a value that could not be checked because the private key for that file is not
on this machine, or a byte order mark that was removed); `[!!]` is a failure:
that file was left untouched, and the reason follows.

The two lines after the changes say where the keys are. The quarantine's
passphrases are encrypted to `.env`'s key pair, and `.env`'s private key is in
`.env.keys` because this machine has no secret store running (it is a server);
on a desktop with dotenvx 2.3 or later the line reads `private key of .env: in
the macOS Keychain, kept by dotenvx (nothing on disk)` and no key file is
written. The run ends with the dotenvx primer because it created a key pair;
later runs end with a one-line pointer instead.

### What the files look like afterwards

```
$ cat .env
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY="02a1b2c3d4...e5f6"

# .env
PORT=3000
STRIPE_SECRET_KEY=encrypted:BB5MBc9JlobM...
APP_NAME=shop
SLACK_WEBHOOK='encrypted:BN99IYszFQ81...'
AWS_ACCESS_KEY_ID='encrypted:BE0SofVYmtdA...'
AWS_SECRET_ACCESS_KEY='encrypted:BGvbsoyIrk2z...'
DATABASE_URL='encrypted:BK1Pw6zWYZuv...'

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

$ cat .secrets-quarantine/.env
# The passphrase of each *.enc file in this quarantine, kept encrypted by dotenvx.
# Restore a file:  sweep-and-secure --restore <stored name>   (MANIFEST.txt has the openssl recipe)
DOTENV_PUBLIC_KEY="02a1b2c3d4...e5f6"
QUARANTINE_KEY_1='encrypted:BNcE76+n+jGe...'
QUARANTINE_KEY_2='encrypted:BAiIQHhrJEh9...'
QUARANTINE_KEY_3='encrypted:BJwq9UkVghIB...'

$ cat .secrets-quarantine/MANIFEST.txt
# Files moved here by sweep-and-secure, one line each: when, stored name <- original path, detectors, why.
# A *.enc file is AES-256 encrypted (openssl enc); its passphrase is the QUARANTINE_KEY_* named on its line,
# kept in .env here, encrypted by dotenvx. Restore one:  sweep-and-secure --restore <stored name>
# or by hand, from inside this folder with the private key at hand (the OS store, or -fk <path to .env.keys>):
#   dotenvx get QUARANTINE_KEY_N -f .env | openssl enc -d -aes-256-cbc -pbkdf2 -pass stdin -in NAME.enc -out NAME
# (leave out -pbkdf2 for a line that says kdf legacy)
2026-10-23T17:07:30Z  .env.example.enc  <- .env.example  (Stripe)  why: example env file  enc: QUARANTINE_KEY_1 (aes-256-cbc, kdf pbkdf2)
2026-10-23T17:07:30Z  build/blob.txt.gz.enc  <- build/blob.txt.gz  (Stripe)  why: gzip archive  inside: blob.txt  enc: QUARANTINE_KEY_2 (aes-256-cbc, kdf pbkdf2)
2026-10-23T17:07:31Z  build/keys.zip.enc  <- build/keys.zip  (Stripe)  why: zip archive  inside: conf/prod.env  enc: QUARANTINE_KEY_3 (aes-256-cbc, kdf pbkdf2)

$ cat .secrets-quarantine/index.json
[
  {
    "quarantined": ".env.example.enc",
    "original": ".env.example",
    "original_absolute": "/home/me/shop/.env.example",
    "moved_at": "2026-10-23T17:07:30Z",
    "why": "example env file",
    "detectors": [
      "Stripe"
    ],
    "inside": [],
    "mode": "0644",
    "encrypted": true,
    "key": "QUARANTINE_KEY_1",
    "cipher": "aes-256-cbc",
    "kdf": "pbkdf2",
    "sha256": "15059aaa3194959852c7f8d325fc37a19efd77bb3a0b7c76e033f39f48cd81a0",
    "size": 81
  },
  {
    "quarantined": "build/blob.txt.gz.enc",
    "original": "build/blob.txt.gz",
    "original_absolute": "/home/me/shop/build/blob.txt.gz",
    "moved_at": "2026-10-23T17:07:30Z",
    "why": "gzip archive",
    "detectors": [
      "Stripe"
    ],
    "inside": [
      "blob.txt"
    ],
    "mode": "0644",
    "encrypted": true,
    "key": "QUARANTINE_KEY_2",
    "cipher": "aes-256-cbc",
    "kdf": "pbkdf2",
    "sha256": "7cd768fd985a8a7345d2334f1d7ae1f20fbcf1638f89e1399a3eb5c25d867c94",
    "size": 82
  },
  {
    "quarantined": "build/keys.zip.enc",
    "original": "build/keys.zip",
    "original_absolute": "/home/me/shop/build/keys.zip",
    "moved_at": "2026-10-23T17:07:31Z",
    "why": "zip archive",
    "detectors": [
      "Stripe"
    ],
    "inside": [
      "conf/prod.env"
    ],
    "mode": "0644",
    "encrypted": true,
    "key": "QUARANTINE_KEY_3",
    "cipher": "aes-256-cbc",
    "kdf": "pbkdf2",
    "sha256": "40ca4526ccd640c5d032d30add3697897513a4b33836ff96b8aa961ed65a8b9b",
    "size": 287
  }
]
```

(The ciphertexts are shortened here; real ones are longer.) The `.env` file,
`src/settings.py` and `config/app.json` can be committed. `.env.keys` and
`.secrets-quarantine/` must not be, and are now ignored. The quarantined files
are `*.enc`, AES-256 encrypted by openssl; the manifest and the index map each
to where it came from and name its passphrase (`QUARANTINE_KEY_1`, ...), which
sits encrypted in `.secrets-quarantine/.env` under the same key pair as `.env`,
so the folder holds no plaintext secret at all. A file whose quarantine name was
already taken gets a numeric suffix (`keys.zip.1.enc`), and the records carry
the name actually used.

### Running it again

A second run finds nothing to do, shows what is protected and says where each
env file's private key is. Where an earlier run, or an earlier version, left a
private key in `.env.keys` that the secret store could hold, or files in the
quarantine as they were, it lists that under "Setup to tighten" and offers to
do it. Running after an interruption, or after adding one more secret to a
file, picks up exactly what is still in plaintext; values already stored are
recognised and never stored twice.

```
$ sweep-and-secure --dry-run
sweep-and-secure 1.7.0  (TruffleHog + dotenvx)
Log: /home/me/.local/state/sweep-and-secure/logs/2026-10-23T16-39-20Z-shop-48213.log
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

### Putting a quarantined file back

The quarantined files are encrypted, so moving one back by hand means
decrypting it (the manifest carries the `dotenvx get ... | openssl enc -d ...`
recipe). `--restore` does it for you: it gets the passphrase from dotenvx,
decrypts the file, checks the result against the digest recorded when the file
was moved, refuses to overwrite anything, marks the record as restored and adds
a line to the manifest. Do this once the file no longer has to hold the secret;
a file put back with its secret still inside is found again by the next run.

```
$ sweep-and-secure --restore build/keys.zip
sweep-and-secure 1.7.0  (TruffleHog + dotenvx)
Log: /home/me/.local/state/sweep-and-secure/logs/2026-10-23T16-39-24Z-shop-48213.log
Folder: /home/me/shop
  [ok] dotenvx     2.38.2     /usr/local/bin/dotenvx
  [ok] restored build/keys.zip from build/keys.zip.enc (decrypted)
$ ls build
keys.zip
```

### SSH keys and other private key files

TruffleHog's `PrivateKey` detector finds key blocks wherever they sit: key
files, a key pasted into YAML or JSON, a `.env` value with escaped newlines,
inside archives. A key *inside* another file is handled like any secret there
(stored encrypted, a placeholder left behind). A key *file*, nothing but PEM
blocks, is different: ssh and servers read the key from the file, so a
placeholder would break it, and the file is never rewritten. Instead the run
reads from the file how the key is protected and lists it:

```
Private key files: 4  (ssh and servers read a key from its file, so none is rewritten; a passphrase protects a key at rest, where the file lies does not)
  #  File                       Passphrase                                Action
  -  .ssh/id_ed25519            yes (OpenSSH format, aes256-ctr, bcrypt)  left as it is
  -  .ssh/id_rsa_old            yes, legacy PEM cipher (AES-128-CBC)      left as it is; upgrade its passphrase (below)
  3  deploy/id_ed25519          none (OpenSSH format)                     move to .secrets-quarantine/deploy/id_ed25519.enc (encrypted)
  4  certs/server.pem           none (PEM)                                move to .secrets-quarantine/certs/server.pem.enc (encrypted)
  Add a passphrase (ssh asks for it when the key is used, or ssh-agent remembers it):
    ssh-keygen -p -a 100 -f deploy/id_ed25519
    ssh-keygen -p -o -a 100 -f certs/server.pem   (rewrites the key in the OpenSSH format: only for a key ssh uses)
  A key that a server or program reads at start-up cannot take a passphrase: keep it out of the tree, and rotate it if it was ever committed.
  Upgrade a passphrase set with the legacy PEM cipher (a single round of MD5 derives its key):
    ssh-keygen -p -o -a 100 -f .ssh/id_rsa_old
```

**Is a passphrase enough?** It depends on the format, which the header of the
file tells:

- `-----BEGIN OPENSSH PRIVATE KEY-----` with a passphrase: the key is encrypted
  with AES-256 under a key derived by bcrypt (16 rounds by default, `-a 100`
  for more). With a decent passphrase this is sound protection at rest, and such
  a key is left where it is.
- `-----BEGIN RSA PRIVATE KEY-----` with `Proc-Type: 4,ENCRYPTED`: the legacy
  PEM form. A single round of MD5 derives its key from the passphrase, so a
  leaked file can be guessed at offline very fast. The run prints the
  `ssh-keygen -p -o -a 100 -f KEY` line that re-encrypts it in the OpenSSH
  format; or rotate the key.
- `-----BEGIN ENCRYPTED PRIVATE KEY-----` (PKCS#8): PBKDF2, fine with a strong
  passphrase. TruffleHog does not report these, so they are not listed.

A passphrase protects the key's contents, not its location. A key file inside a
project tree still ends up in git history, backups and archives, where it can be
attacked forever, so even a protected one belongs in `~/.ssh`, and one that was
ever committed should be rotated.

**A key without a passphrase** has two real fixes, and the run prints the
command for the first: add a passphrase with `ssh-keygen -p` (ssh asks for it
when the key is used; `ssh-agent` remembers it for a session), or rotate it:
`ssh-keygen -t ed25519 -a 100 -f ~/.ssh/<name>`, install the new `.pub` where
the old key was accepted, delete the old key. In a project tree such a key is
offered to the quarantine like any file that cannot be fixed in place
(`--quarantine` with `--yes`); in a `.ssh` folder it is left where ssh needs it,
with the `ssh-keygen` line. A key that a server or program reads at start-up (a
TLS key, a signing key) cannot take a passphrase: keep it out of the tree, and
rotate it if it was ever committed.

Sweeping `~/.ssh` itself works and changes nothing there: every key is listed
with its protection and the command to improve it.

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

  [ok] private key file: .env.keys  (file custody: failed to save private key to Linux Secret Service)

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
  #  File               Why / inside        Secrets                    Action
  -  .env.example       example env file    Stripe sk_l...23 (line 2)  stays in place (pass --quarantine to move it)
  -  build/blob.txt.gz  gzip: blob.txt      Stripe sk_l...23           stays in place (pass --quarantine to move it)
  -  build/keys.zip     zip: conf/prod.env  Stripe sk_l...fE           stays in place (pass --quarantine to move it)
...
Done: 5 secret(s) stored encrypted; 5 plaintext occurrence(s) removed from 3 file(s); 3 file(s) need manual attention (see above)
```

```
$ sweep-and-secure --yes --quarantine
...
  [ok] .env.example: moved to .secrets-quarantine/.env.example.enc (encrypted)
  [ok] build/blob.txt.gz: moved to .secrets-quarantine/build/blob.txt.gz.enc (encrypted)
  [ok] build/keys.zip: moved to .secrets-quarantine/build/keys.zip.enc (encrypted)

  [ok] .secrets-quarantine/.env holds the quarantine's passphrases, encrypted to the key pair of .env
  [ok] private key file: .env.keys  (file custody: failed to save private key to Linux Secret Service)

Done: 5 secret(s) stored encrypted; 5 plaintext occurrence(s) removed from 3 file(s); 3 file(s) moved to .secrets-quarantine (encrypted)
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

dotenvx finds the private key on its own: in the `DOTENV_PRIVATE_KEY*`
environment variables first, then in `.env.keys` next to the env file, then in
the operating system's secret store, matching key to file by public key. That
is how CI and servers get it: `dotenvx keypair DOTENV_PRIVATE_KEY -f .env`
prints the key from wherever dotenvx keeps it, and it goes into the CI's secret
store as `DOTENV_PRIVATE_KEY`; the same `dotenvx run` command then works there.
An env file in a sub-folder has its own key, named after the file
(`config/.env.production` gets `DOTENV_PRIVATE_KEY_PRODUCTION`), and its
`.env.keys` is written next to it, where dotenvx looks:

```
dotenvx run -f config/.env.production -- python src/app.py
```

The other everyday commands: `dotenvx get KEY` prints one decrypted value,
`dotenvx set NEW_KEY "value"` adds or changes one, encrypted on the way in, and
`dotenvx native up -f .env` moves a private key from `.env.keys` into the
secret store. The run that created the key pair ends with this primer; the full
reference is at https://dotenvx.com/docs. To add a secret found later, run
sweep-and-secure again or use `dotenvx set`.

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
- Put a quarantined file back: `sweep-and-secure --restore build/keys.zip` (the
  stored name or the original path, as `MANIFEST.txt` lists them).
- Keep a fresh private key in `.env.keys` even where dotenvx could put it in
  the secret store: `--no-native` (dotenvx's own `DOTENVX_NO_NATIVE=true` does
  the same).
- Name the openssl that encrypts quarantined files:
  `--openssl /opt/openssl/bin/openssl`.
- Ask TruffleHog to verify credentials against the issuing services (this
  sends them over the network): `--verify`; live ones are marked `*`.
- Sweep a folder other than the current one: `sweep-and-secure path/to/project`.
- See every command the script runs: `-v`. Keep the run's log somewhere else,
  or not at all: `--log-dir DIR`, `--no-log`. The same for the record of a run
  that changed files: `--record-dir DIR`, `--no-record`.

## For agents and scripts

This section is for whoever runs the tool without a person at the keyboard: a
shell script, a CI job, or an AI agent working in a repository on someone's
behalf. The tool asks nothing when `--yes` or `--dry-run` is given, prints a few
stable lines a caller can read, exits with a meaningful code, and leaves a
record of every run that changed files. [What it does](#what-it-does) gives the
model; this is the operating manual.

### The sequence

1. **Check the setup**: `sweep-and-secure --check-setup`. Exit 0 means Python,
   TruffleHog and dotenvx are in place and a trial run of both tools worked;
   exit 1 names what is missing, with install links. Nothing is scanned.
2. **Dry run**: `sweep-and-secure --dry-run PATH`. The report lists every
   plaintext secret with its file, line, detector and a masked preview, the
   action a real run would take, and the files that cannot be fixed in place.
   Nothing is changed. Exit 0, or 1 when the TruffleHog scan was cut short.
3. **Decide** whether the files that cannot be fixed in place (archives, lock
   files, example env files, SSH keys without a passphrase) should leave the
   tree. With `--yes` they stay where they are unless `--quarantine` is given.
4. **Run**: `sweep-and-secure --yes [--quarantine] PATH`. It encrypts, rewrites
   and moves as the report said, prints what it did, and ends with
   `Run record: <path>`.
5. **Read the run record**: what changed, where the private key is, the dotenvx
   commands that use the values, and what to do when something is wrong. Keep
   the path with the task's notes; the file stays until its owner removes it.
6. **From then on, dotenvx**: `dotenvx run -- <command>` runs a program with the
   decrypted values in its environment. Do not print values; `dotenvx get KEY`
   is for the one case where a value is really needed, and only when a human
   asked for it.

Run again any time: stored values are recognised and reused, not duplicated,
and a later run tightens an earlier setup (a key still in `.env.keys` moves into
the OS secret store where dotenvx can use it).

### Lines worth reading

Each of these is a line of its own with stable wording, in this order.

| line | meaning |
| --- | --- |
| `Log: <path>` | this run's log, the second line of the output |
| `[ok] trufflehog <version> <path>`, `[ok] dotenvx <version> <path>` | the tools in use; a `[!!]` line names a missing or unusable one |
| `Scanned N file(s) in M:SS; TruffleHog reported K finding(s).` | the scan is over (an old TruffleHog prints `Scan took M:SS; ...`) |
| `Plaintext secrets found: N in M file(s)` | the table of what is (or would be) encrypted follows |
| `Files holding secrets that cannot be fixed in place: N` | the table of files to move to quarantine, or to leave in place, follows |
| `Set aside N finding(s) ...` | checksums, identifiers and other non-secrets TruffleHog reported; each is named in the run log |
| `Nothing to encrypt.` | nothing to do; exit 0 |
| `Dry run: nothing was changed.` | a dry run ended; exit 0 |
| `Nothing encrypted.`, `Nothing changed.` | no confirmation was given; exit 2 |
| `Done: ...` | a real run ended; its parts count what was stored, rewritten, moved and what failed |
| `Stopped early (...)` | an interrupted or failed run; the state of the tree follows |
| `Run record: <path>` | the record of a run that changed files |

The [exit code](#exit-codes) is the verdict: 0 done or nothing to do, 1
something failed or the scan was incomplete, 2 no confirmation, 130
interrupted.

### What it leaves behind

In the project:

- the env files, every secret encrypted (`KEY="encrypted:..."`) under the
  `DOTENV_PUBLIC_KEY` header dotenvx adds; safe to commit;
- placeholders such as `${KEY}` where the plaintext sat in source files;
- `.env.keys` beside an env file when dotenvx could not use the OS secret
  store: the private key, added to `.gitignore`, never to be committed;
- `.secrets-quarantine/` when files were moved: `MANIFEST.txt` and
  `index.json` (what came from where), `.env` (the passphrases, encrypted to the
  project's key pair) and the `*.enc` files. `sweep-and-secure --restore
  <stored name>` puts one back.

Per user, in one place for the machine:

- a run log for every run, the newest 100 kept:
  `~/.local/state/sweep-and-secure/logs` on Linux,
  `~/Library/Logs/sweep-and-secure` on macOS,
  `%LOCALAPPDATA%\sweep-and-secure\logs` on Windows;
- a run record for every run that changed files, kept:
  `~/.local/state/sweep-and-secure/runs`,
  `~/Library/Application Support/sweep-and-secure/runs`,
  `%LOCALAPPDATA%\sweep-and-secure\runs`.

Neither ever holds a secret value.

### Rules of thumb for an agent

- Never print, paste or commit a secret value. The report, the log and the
  record show masked previews; `dotenvx get` is the only thing that prints a
  value.
- Never commit `.env.keys`, and never delete or move the quarantine's `.env`:
  it holds the passphrases of the quarantined files.
- Run the dry run first and read it; `--yes` acts on everything it listed.
- `--verify` sends the credentials to their services over the network: only
  with permission.
- Without a terminal and without the OS secret store (containers, CI), dotenvx
  keeps the private key in `.env.keys`; give CI the key as the
  `DOTENV_PRIVATE_KEY` secret. `--no-native` asks for a key file on purpose.
- When a run says `Stopped early`, run it again: each file is changed completely
  or not at all, and the next run finishes the job.
- The environment variables it reads: `TRUFFLEHOG_BIN` and `DOTENVX_BIN` (the
  tools), `SWEEP_AND_SECURE_LOG_DIR` and `SWEEP_AND_SECURE_RECORD_DIR` (the
  folders), `NO_COLOR`; dotenvx reads its own, such as `DOTENVX_NO_NATIVE`.

### Full command-line help

The output of `sweep-and-secure --help`, kept in step with the program by a
test:

<!-- help-start -->
```
usage: sweep-and-secure [-h] [-n] [-y] [--env-file PATH] [--env-all]
                        [--no-rewrite] [--quarantine] [--quarantine-dir DIR]
                        [--no-native] [--placeholder TEMPLATE] [--verify]
                        [--exclude REGEX] [--no-default-excludes]
                        [--scan-compiled] [--min-length N] [--restore FILE]
                        [--openssl PATH] [--trufflehog PATH] [--dotenvx PATH]
                        [--no-version-check] [--log-dir DIR] [--no-log]
                        [--record-dir DIR] [--no-record] [-v] [--no-color]
                        [--check-setup] [--version]
                        [path]

Scan a folder tree for API keys and secrets with TruffleHog, list what was found
(and what is already encrypted), then -- after you confirm -- encrypt them with dotenvx.

  secrets in dotenv files   -> encrypted in place        (KEY="encrypted:...")
  secrets in other files    -> moved into the project's .env, encrypted, and the
                               plaintext replaced by a placeholder like ${KEY}
  private key files         -> never rewritten: one without a passphrase can be moved to the
                               quarantine, and the ssh-keygen line that adds one is printed

positional arguments:
  path                  folder to sweep (default: current folder)

options:
  -h, --help            show this help message and exit
  -n, --dry-run, --list
                        scan and list only; change nothing
  -y, --yes             encrypt everything found without asking
  --env-file PATH       dotenv file that receives secrets moved out of other
                        files (default: .env inside the swept folder)
  --env-all             also encrypt every other plaintext key in dotenv
                        files, not only the ones TruffleHog flagged
  --no-rewrite          store secrets encrypted but leave the source files
                        untouched
  --quarantine          with --yes, also move every file that holds a secret
                        and cannot be fixed in place (archives, binaries,
                        PDFs, lock files, example env files, ...) out of the
                        tree into the quarantine folder, keeping relative
                        paths (interactive runs offer this anyway)
  --quarantine-dir DIR  the quarantine folder (default: .secrets-quarantine
                        inside the swept folder); implies --quarantine
  --no-native           keep new private keys in .env.keys files instead of
                        letting dotenvx put them in the OS secret store (macOS
                        Keychain, Windows Credential Manager, Linux Secret
                        Service)
  --placeholder TEMPLATE
                        text that replaces a secret in source files; NAME
                        becomes the key (default: ${NAME})
  --verify              let TruffleHog verify each secret against its service
                        (needs network access)
  --exclude REGEX       skip paths matching this regular expression
                        (repeatable)
  --no-default-excludes
                        also scan .git, node_modules, virtualenvs and friends
                        (.env.keys and staging files stay excluded)
  --scan-compiled       also scan compiled code (.so, .dll, .exe, .pyc,
                        .class, ... and files whose first bytes say ELF, PE,
                        Mach-O or WebAssembly) and list what TruffleHog finds
                        there; such files are never rewritten or moved.
                        Skipped by default: TruffleHog 3.75 and later skip
                        them anyway, and older releases match symbol names in
                        them
  --min-length N        ignore secrets shorter than N characters (default: 8)
  --restore FILE        put FILE back from the quarantine folder of PATH,
                        decrypting it (FILE is the stored name or the original
                        path as MANIFEST.txt lists them); nothing is scanned
  --openssl PATH        openssl executable that encrypts quarantined files
                        (default: search PATH, and on Windows Git's copy)
  --trufflehog PATH     trufflehog executable (default: search PATH)
  --dotenvx PATH        dotenvx executable (default: search PATH)
  --no-version-check    use a tool even if its --version could not be read
  --log-dir DIR         where this run's log goes (default: the user's state
                        folder, see --help's notes; SWEEP_AND_SECURE_LOG_DIR
                        overrides it)
  --no-log              do not write a run log
  --record-dir DIR      where the record of a run that changes files goes
                        (default: the user's state folder, see --help's notes;
                        SWEEP_AND_SECURE_RECORD_DIR overrides it)
  --no-record           do not write a run record
  -v, --verbose         show the commands run and tool output
  --no-color            plain output
  --check-setup         check that Python, TruffleHog and dotenvx are in place
                        and run both tools in a scratch folder; exit 0 if a
                        real run would work, 1 otherwise; nothing is scanned
  --version             show program's version number and exit

exit codes: 0 done (or nothing to do), 1 missing tool / scan incomplete or failed / encryption failed,
            2 you said no or gave no answer (stdin not a terminal, nothing piped, no --yes), 130 interrupted

A log of every run is kept in ~/.local/state/sweep-and-secure/logs
(--log-dir to change, --no-log to skip; the newest 100 are kept); it holds what was printed, the
prompts and the tool commands, never secret values. A run that changes files also leaves a record in
~/.local/state/sweep-and-secure/runs
(--record-dir, --no-record; kept until you remove it): what changed, where the keys are and how to
use them, what to do when something is wrong, and the run's full output. Scripts and agents: the
README's 'For agents and scripts' section lists the output lines worth reading and the exit codes.

TruffleHog: https://trufflesecurity.com/trufflehog     dotenvx: https://dotenvx.com
```
<!-- help-end -->

## Reference

### Options

`sweep-and-secure --help` prints the short form of this reference.

**Where to scan**

- `path`: the folder to sweep, default the current folder. Every sub-folder is
  included. This folder is also where the default `.env` lives, where the
  quarantine folder is made, and where the script stages files while it works.
- `--exclude REGEX`: skip paths matching a regular expression; repeat the option
  for several. Patterns are matched against the whole path as TruffleHog sees
  it, so on Windows write `[/\\]` rather than `/` for a separator, for example
  `--exclude '(^|[/\\])fixtures([/\\]|$)'`. These add to the built-in excludes.
- `--no-default-excludes`: also scan `.git`, `.hg`, `.svn`, `node_modules`,
  `__pycache__`, `.venv`, `venv` and `.tox`, which are skipped by default. The
  dotenvx key files (`.env.keys*`), legacy `.env.vault` files and the script's
  own staging files are never scanned or rewritten, whatever you pass.
- `--scan-compiled`: also scan programs and libraries (`.so`, `.dll`, `.dylib`,
  `.exe`, `.o`, `.a`, `.pyc`, `.class`, `.wasm`, ... and any file whose first
  bytes say ELF, PE, Mach-O or WebAssembly) and list what TruffleHog finds in
  them in a section of their own, each match with the printable string around
  it as `strings` would show it (on the screen only, never in the run log) and
  with `*` when `--verify` confirmed it. Such files are never rewritten or moved.
  Off by default: a secret compiled into a program cannot be fixed by this tool,
  and what an old TruffleHog matches in compiled code is mostly exported symbol
  names; TruffleHog 3.75 and later skip compiled files themselves, so with one
  of those the option only lists what that TruffleHog still reads. Without the
  option the run says how many compiled files it skipped.
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
  and CI. It also tightens an earlier setup without asking: a private key in
  `.env.keys` goes into the secret store where dotenvx can keep it there, and
  files the quarantine holds as they are get encrypted (the latter only with
  `--quarantine`). Archives that hold secrets are moved to quarantine only if
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
  keeping its relative path plus `.enc` (`build/keys.zip` becomes
  `.secrets-quarantine/build/keys.zip.enc`, with a numeric suffix if that name
  is taken or is one of the folder's own files). Each file is AES-256 encrypted
  with openssl under a passphrase of its own, stored as `QUARANTINE_KEY_<n>` in
  the folder's `.env`, encrypted by dotenvx to the project's key pair when its
  private key is at hand, else to a key pair made for the quarantine; the
  encrypted copy is decrypted again and compared before the original is removed.
  Without a working openssl the files are moved as they are, and the listing,
  the summary (`[--]`) and the manifest say so. The folder's `MANIFEST.txt`
  starts with the restore recipe and gets a line per file, its `index.json` a
  record per file: the time, the stored name, the original path, the reason, the
  detectors, for archives the files inside that held the secrets, and the key,
  cipher, key derivation, SHA-256, size and mode of the original (`--restore`
  gives a file its mode back). The folder is added to `.gitignore` before
  anything is moved and is never scanned afterwards. An
  interactive run offers this without the flag: the files appear as numbered
  items ("move to ..."), `y` includes them and `s` lets you leave them out.
  Every run, with or without the flag, lists these files in their own section
  with the reason, so you can see what you would be moving. A text file some of
  whose secrets are fixed in place is never moved; symbolic links are never
  moved.

- `--quarantine-dir DIR`: use DIR as the quarantine folder instead (relative to
  the swept folder, or absolute, including a folder outside the tree); implies
  `--quarantine`. A folder inside the tree is excluded from the scan for that
  run. Reserved names and the swept folder itself are refused.
- `--restore FILE`: put FILE back from the quarantine folder (`--quarantine-dir`
  names another), decrypting it with the passphrase dotenvx kept and checking
  the SHA-256 recorded when it was moved. FILE is the stored name or the
  original path as `MANIFEST.txt` lists them (`build/keys.zip.enc` or
  `build/keys.zip`). It refuses to overwrite a file at the original path, marks
  the record as restored and adds a line to the manifest; nothing is scanned,
  and only dotenvx (and openssl) are needed. A file that was moved without
  encryption is moved back as it is.
- `--no-native`: keep private keys in `.env.keys` files, a fresh one and any
  an earlier run left there, even where dotenvx could put them in the
  operating system's secret store. `DOTENVX_NO_NATIVE=true` in the environment
  has the same effect (dotenvx itself honours it too), and so does a set `CI`
  variable. `dotenvx native up -f .env` moves a key into the store later.
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
- `--openssl PATH`: the openssl that encrypts quarantined files. By default the
  one on the `PATH` is used, and on Windows the copy that Git for Windows or the
  OpenSSL installer put under `Program Files` is found too. openssl is optional:
  without a working one quarantined files are moved as they are, and the run
  says so.
- `--no-version-check`: use a tool even when its `--version` output cannot be
  read. That is normally refused because it usually means the file cannot be
  executed from here (a POSIX shell script found on Windows, for instance), and
  the failure would otherwise surface half way through a run.
- `--check-setup`: report the Python in use, find both tools (and git and
  openssl) as a run would, run each in a scratch folder under the system temp
  folder, and exit: 0 when a real run would work, 1 when something is missing or
  broken, with install links. The dotenvx line says where a fresh private key
  goes on this machine: into the secret store (and out again), or into
  `.env.keys`, and why. Nothing is scanned and nothing in the folder is touched.

**Output**

- `-v`, `--verbose`: print every command run (TruffleHog, `dotenvx encrypt`, and
  the `dotenvx get` calls that verify each stored value) and the tools' output.
  Secret values are never printed, only key names and masked previews.
- `--log-dir DIR`: write this run's log into DIR instead of the user's log folder
  (`~/.local/state/sweep-and-secure/logs`, `~/Library/Logs/sweep-and-secure`,
  `%LOCALAPPDATA%\sweep-and-secure\logs`; `SWEEP_AND_SECURE_LOG_DIR` also
  overrides it). `--no-log`: write no log. The newest 100 of this tool's logs
  are kept; other files in the folder are never removed.
- `--record-dir DIR`: write the record of a run that changes files into DIR
  instead of the user's run-record folder
  (`~/.local/state/sweep-and-secure/runs`,
  `~/Library/Application Support/sweep-and-secure/runs`,
  `%LOCALAPPDATA%\sweep-and-secure\runs`; `SWEEP_AND_SECURE_RECORD_DIR` also
  overrides it). `--no-record`: write no record. Records are never pruned.
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
curl -sSfL -O https://github.com/voxgig/sweep-and-secure/releases/download/v1.7.0/SHA256SUMS
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
  files show up as findings, and their keyword detectors take a commit id or
  checksum that stands within 40 characters after the word `cloudflare`,
  `sentry`, `datadog` and so on for a token: the sha1 URL fragment of such a
  package in `yarn.lock`, and in a manifest a dependency pinned to a commit
  (`"cloudflare": "github:cloudflare/node-cloudflare#<commit>"` in
  `package.json`, `rev = "<commit>"` in `Cargo.toml`, `uses:
  cloudflare/wrangler-action@<commit>` in a workflow) or a `gitHead` field.
  Measured, every release from 3.6 to 3.99 does this, the newest no less than
  the old ones, and 3.75 to 3.88 also report a commit id after the word
  `github` in some layouts. Older releases also took `-explode-assignable-expression-7`,
  a run of `@babel/helper-explode-assignable-expression`'s tarball URL, for a
  Signable token, since the word `assignable` stands just before it (TruffleHog
  skips that package by name since its issue 1517). Matches that sit inside such
  a hash, and commit ids, checksums or package names that the file vouches for
  (a dependency or action pinned to a commit, a `rev`, `ref`, `commit` or
  checksum field, a URL's fragment or path, a run of a package archive's file
  name in a registry URL or of the path segment that name repeats, and in a
  generated lock file also a `mix.lock` entry or a checksum section), are set
  aside and counted rather than treated as secrets, and the run log names each
  one. A string counts as a hash only at its algorithm's exact
  length (88 characters for `sha512-`, 44 for `h1:`, 40, 64 or 128 hex digits
  for a bare digest, and outside lock files only hex), so a shorter or longer
  random string is never taken for one, and a digest in a URL's user
  information, after `=` or a word like `token`, or in a place the file does
  not vouch for, stays a finding. A file that still appears in the listing
  holds something like that, such as a token in a registry URL; its row names
  the detector, the line, the match's length and the field it sits in
  (`CloudflareApiToken 2e85...ee (line 7, 40 chars, in "resolved")`), and
  `--verify` lets TruffleHog confirm a credential against its service.
* An older TruffleHog has looser patterns than the current one for some
  detectors, and updating it is the real fix. Where TruffleHog later corrected
  itself, this tool holds the old release's findings to the current pattern: a
  3.5x release's PagerDuty detector takes any 20-character run within 40
  characters of the letters `pd` (also inside `upd`, `pdf` or a base64 blob) for
  a key, where 3.60 and later require the `u+` that PagerDuty user tokens carry;
  a Signable match after the word `assignable` or `designable` is excluded by the
  detector itself since 3.6x. A release before 3.75 ran TruffleHog's own
  false-positive filter only while verifying a match, so under this tool's default
  `--no-verification` it filtered nothing, and an identifier or a placeholder near
  a vendor's name became that vendor's key (3.55.1 reports
  `createWorkerRequestContextHandlerFactory` after the word `cloudflare` as a
  Cloudflare token; 3.75 and later run the filter in the engine whatever the flags
  and report nothing). For such a release the tool applies the filter itself: a
  match holding a placeholder term (`example`, `sample`, `abcde`, ...) is set
  aside, and so is one that reads as an identifier by the tool's own test (at
  least two words from its list of about a thousand common words of code and the
  web, making up at least half the letters, joined camelCase, snake_case or
  kebab-case, no digits), except for the detectors whose current versions never drop a finding this way (a
  URL with a password, a JDBC string, a private key, a Slack webhook, a GCP service
  account). Findings of detectors TruffleHog has since removed (Etsy, which
  took any 24-character run near the word `etsy` for a key; NYTimes, Opengraphr,
  Prospect.io, Abbysale, Integromat, RoninApp) are set aside whatever the
  release. All of these are counted and named in the run log, as are matches
  inside a base64 blob (the payload of a `data:` URI
  in CSS or HTML, a run of 128 or more base64 characters outside a URL, at
  least twice as long as the match, with the match well inside it): a pattern
  that lines up with encoded bytes is noise, and a secret inside such a blob is
  encoded, which TruffleHog reports decoded. A long base64 secret standing
  alone, or a token in a URL path, is not a blob, and a finding that `--verify`
  confirmed live is never set aside by any of these rules.
* TruffleHog reports a private key only when it can parse it: an RSA, EC or DSA
  key in the PEM or PKCS#8 form, an OpenSSH-format key with or without a
  passphrase (3.88 leaves passphrase-protected keys out). A PKCS#8
  `ENCRYPTED PRIVATE KEY`, an ed25519 key in the PKCS#8 form or a toy key is not
  reported, so it is not listed; the first is passphrase-protected anyway.
* Programs and libraries (`.so`, `.dll`, `.exe`, `.pyc`, ...) are not scanned
  unless `--scan-compiled` is given, and are never changed. TruffleHog releases
  before 3.75 read them as raw bytes and match exported symbol names: in a test
  over 60 system libraries, TruffleHog 3.70 reported 34 "secrets", all C++
  symbol names in LLVM; 3.75 and later skip such files themselves. A credential
  really compiled into a program has to be rotated and the program rebuilt.
* Secrets inside data binaries, PDFs, lock files or base64-encoded text are never
  rewritten; such files can only be moved to the quarantine folder as a whole,
  and so can archives (TruffleHog looks inside them). The listing shows which
  files inside hold the secrets for zip, tar (any compression), gzip, bzip2 and
  xz archives, nested up to three deep and up to 512 MB of content; 7z, rar and
  zstd archives cannot be opened from here and are listed with their secrets
  only.
* The files moved to quarantine are encrypted with openssl (1.1.1 or later uses
  PBKDF2 key derivation; an older one uses the legacy derivation, and the
  manifest says which). Without openssl they are moved as they are, which the
  listing, the summary and the manifest all say.
* The operating system's secret store is used through dotenvx 2.3 or later. On
  Linux it needs a running Secret Service (a desktop keyring); on a server
  without one, or with an older dotenvx, the private key stays in `.env.keys`
  next to the env file, and the run says so. A key pair that already existed
  stays where it is.
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

The end-to-end tests run the script against a throw-away project with stand-ins
for `trufflehog`, `dotenvx` and `openssl` from `tests/fakebin`, so they need
none of the tools installed. The stand-in dotenvx follows the real tool's
quoting, key-naming and key-lookup rules as measured against dotenvx 2.38, its
OS secret store included (`native up` and `down`); the stand-in openssl is no
cryptography at all, only the command line and the round trip. With
`SWEEP_TEST_REAL_TOOLS=1` and the real tools on your `PATH` an extra tier runs
the script against them. CI (`.github/workflows/test.yml`) runs the suite on
Linux, macOS and Windows with Python 3.8 to 3.13, the real-tools tier on Linux
with the current TruffleHog and dotenvx, and a packaging job that builds the
wheel, runs the console script and exercises `install.sh` with and without the
tools present. One test checks that the README's "Full command-line help" block
is `--help`'s output; after changing an option, regenerate the block with

```
COLUMNS=80 SWEEP_AND_SECURE_LOG_DIR='~/.local/state/sweep-and-secure/logs' \
SWEEP_AND_SECURE_RECORD_DIR='~/.local/state/sweep-and-secure/runs' \
python3 -c "import sys; sys.argv = ['sweep-and-secure', '--help']; import sweep_and_secure; sweep_and_secure.parse_args(['--help'])"
```


To release: set `__version__` in `sweep_and_secure.py`, merge, then either push
a matching tag (`git tag v1.7.0 && git push origin v1.7.0`) or run the release
workflow from the Actions tab with the version, which creates the tag for you.
The workflow (`.github/workflows/release.yml`) checks that the tag matches the
version, runs the tests, builds the sdist and wheel, and publishes a GitHub
release carrying the script, `install.sh`, both packages and `SHA256SUMS`, which
is what the curl installer and `pipx install ...@vX.Y.Z` fetch.
