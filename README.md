# sweep-and-secure

`sweep_and_secure.py` sweeps a folder tree for API keys and secrets, shows you
what it found, and -- once you say yes -- encrypts them with
[dotenvx](https://dotenvx.com). The finding is done by
[TruffleHog](https://trufflesecurity.com/trufflehog).

```
$ python sweep_and_secure.py
sweep-and-secure 1.0.0  (TruffleHog + dotenvx)
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

Encrypting ...
  [ok] .env: encrypted 4 key(s): STRIPE_SECRET_KEY, SLACK_WEBHOOK, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  [ok] config/app.json: replaced 1 occurrence(s) of 1 secret(s) with placeholders (SLACK_WEBHOOK)
  [ok] docs/notes.md: replaced 1 occurrence(s) of 1 secret(s) with placeholders (SLACK_WEBHOOK)
  [ok] src/settings.py: replaced 2 occurrence(s) of 2 secret(s) with placeholders (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

  [ok] private key file: .env.keys
  [ok] added .env.keys* to /home/me/shop/.gitignore

Done: 5 secret(s) encrypted, 1 need manual attention (see above)

Next steps
  ...
```

## Requirements

* Python 2.7 or any Python 3 (no packages to install).
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

## Usage

```
cd your/project
python sweep_and_secure.py            # scan, list, ask, encrypt
python sweep_and_secure.py --dry-run  # scan and list only
python sweep_and_secure.py --yes      # no questions (scripts, CI)
python sweep_and_secure.py some/dir   # sweep a different folder
```

`chmod +x sweep_and_secure.py && ./sweep_and_secure.py` works too.

The run is interactive: it first lists every secret TruffleHog found (the
detector type, the key or variable name it will use, a masked preview, where it
is, and what will happen to it), then the keys that are already encrypted with
dotenvx, then asks. Answer `y` to encrypt everything listed, `n` to stop, or
`s` to pick items by number (`1 3 5-7`).

### What happens to a secret

| where it was found | what is done |
| --- | --- |
| a dotenv file (`.env`, `.env.production`, `prod.env`, ...), as the value of `KEY=...` | `dotenvx encrypt -f <file> -k KEY` encrypts that key in place: `KEY="encrypted:..."` |
| anywhere else (source code, JSON, YAML, Markdown, certificates, ...) | the value is added to the project's `.env` (`--env-file` to change) and encrypted there; the plaintext in the file is replaced by `${KEY}` (`--placeholder` to change) |
| a binary or archive file, a symlink, a secret TruffleHog had to decode first | listed under "cannot fix automatically" for you to deal with by hand |

Variable names come from the code around the secret (`AWS_SECRET_ACCESS_KEY = "..."`,
`"apiKey": "..."`, `password: ...`), made specific with the detector name when
they are too generic (`token` found by the GitHub detector becomes
`GITHUB_TOKEN`), and fall back to the detector name plus a short hash
(`PRIVATE_KEY_28AF08`). The same secret found in several files gets one name.
Nothing is rewritten until dotenvx has confirmed the value is stored encrypted;
if dotenvx fails, the env file is restored and the source files are left alone.

dotenvx writes the private key to `.env.keys` (dotenvx 2.x puts it in the swept
folder; 1.x next to each env file). The script asks `git check-ignore` whether
that file is ignored, appends `.env.keys*` to your `.gitignore` if it is not,
and warns loudly if the file is already tracked by git. Files are rewritten
atomically, and an interrupted run restores any env file it was changing.

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
-v, --verbose           show the commands run and the tools' output
--no-color              plain output
```

Exit codes: `0` done or nothing to do, `1` a tool is missing, the scan failed
or was cut short, or an encryption failed, `2` you said no (or stdin was not a
terminal and `--yes` was not given).

## After a run

1. Replace the placeholders in your code with real environment lookups
   (`os.environ["AWS_ACCESS_KEY_ID"]`, `process.env.AWS_ACCESS_KEY_ID`, ...).
2. Start your program through dotenvx so the values are decrypted at run time:
   `dotenvx run -- <your command>` (or `dotenvx run -f config/.env.production -- ...`).
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
* Secrets inside binaries, archives (TruffleHog looks inside them) or
  base64/UTF-16 encoded text are reported but not rewritten.
* Replacing a literal with `${KEY}` removes the secret but does not make the
  program read the variable; that is the follow-up work the script lists.
* Only the working tree is changed, never git history.

## Development

```
python -m unittest discover -s tests -v      # Python 2.7 or 3.x
```

The end-to-end tests run the script against a throw-away project with
stand-ins for `trufflehog` and `dotenvx` from `tests/fakebin`, so they need
neither tool installed. The script itself has also been run against the real
TruffleHog 3.99 and dotenvx 2.38 under Python 2.7, 3.8 and 3.13.
