# ReCheck

Verify file integrity from the terminal with **SHA-256** or **MD5**.
nmap-style command line, no dependencies, runs on Linux, macOS, and Windows.

```console
$ recheck -f ./sample_file.txt
ReCheck report for ./sample_file.txt
Size: 3 B   Time: 0.00 s   Throughput: 28.1 KB/s
sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
ReCheck done: 1 file hashed in 0.00 seconds
```

Once installed, `recheck` works from any directory.

---

## Installation

Requires **Python 3.9** or newer. Don't have it? Get it from
[python.org/downloads](https://www.python.org/downloads/). On Windows, tick
**"Add python.exe to PATH"** during setup.

### 1. Install pipx

`pipx` gives each application its own virtualenv, so your system Python is left
alone. This is the right approach on distros that lock down the system Python
(PEP 668 — Kali, Fedora, Debian 12+, Ubuntu 23.10+).

| Platform | Command |
|---|---|
| Debian / Ubuntu / Kali | `sudo apt install pipx && pipx ensurepath` |
| Fedora | `sudo dnf install pipx` |
| Arch | `sudo pacman -S pipx` |
| macOS | `brew install pipx && pipx ensurepath` |
| Windows | `pipx install pipx && pipx ensurepath` |

### 2. Install ReCheck

The same command on **Linux, macOS, and Windows**:

```bash
pipx install git+https://github.com/1RenXc/ReCheck-Integrity.git
```

>`pipx ensurepath` adds the script folder to `PATH`. Run it once, then close and
>reopen your terminal.

### Verify

```console
$ recheck -V
recheck 1.0.2 ( https://github.com/1RenXc/ReCheck-Integrity )
```

If that prints, ReCheck is ready.

---

## Usage

Three steps: **hash** the files → **save** to a manifest → **verify** later.

```console
# 1. Record a baseline when you first trust the files
$ recheck -f ./folder -c baseline.sha256

# 2. Later, confirm nothing changed
$ recheck -v baseline.sha256
ReCheck report for ./folder/a.txt
Size: 3 B   Time: 0.00 s   Throughput: 41.7 KB/s
sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
MATCH: integrity confirmed

ReCheck done: 1 file verified in 0.00 seconds
ReCheck summary: all 1 file verified
$ echo $?
0
```

### Run summary

Every verify run ends with a tally and the names of the files that failed, so
you do not have to scroll back or grep for them:

```console
$ recheck -f ./Downloads -v downhash.txt
... one report per file ...

ReCheck done: 27 files verified in 4.10 seconds
ReCheck summary: 26 of 27 files verified, 1 MISMATCH
MISMATCH: ./Downloads/haha.txt
$ echo $?
1
```

| Line | Meaning |
|---|---|
| `all N files verified` | Every checked file matched |
| `N of M verified, K MISMATCH(ES)` | K files really changed |
| `N of M verified, K ERROR(S)` | K files could not be read, or were not listed in the manifest |
| `no files checked` | The target held no files (for example an empty directory) |

Each `MISMATCH:` and `ERROR:` line repeats the path from the report above it, so
`ERROR:` lines carry the reason in parentheses. Nothing else changes: the
per-file reports stay exactly as they were, and a run with no failures simply
adds the one-line summary.

---

## Options

```
recheck -f <file|directory> [Options]
```

| Option | Meaning |
|---|---|
| `-f <path>` | Target file or directory. Repeatable. Directories are walked recursively |
| `-c <file>` | Write the computed hash(es) to a manifest file |
| `-v <file\|hash>` | Verify against a manifest **or** an inline hash value |
| `-a <alg>` | Algorithm for both generation and comparison. Default `sha256` |
| `-V` | Version number |
| `-h`, `--help` | Full help |

Long names `--file`, `--create`, `--verify`, `--algorithm`, `--version`,
`--help` also work.

### Algorithms

| Name | Width | Notes |
|---|---|---|
| `sha256` | 256-bit | **Default.** The right choice for integrity checks |
| `md5` | 128-bit | Legacy compatibility only. Not for security |

This list is read from the code, so `recheck -h` is always accurate.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All files matched |
| `1` | A hash did not match, or the hash you passed was not a valid digest (`MISMATCH`) |
| `2` | Usage error (unknown option, `-c` together with `-v`, etc.) |
| `3` | File not found or I/O error |

Ready for scripts and CI:

```bash
if recheck -v baseline.sha256; then
    echo "integrity verified"
else
    echo "WARNING: integrity problem"
    exit 1
fi
```

---

## Examples

```bash
# Print a hash to stdout
recheck -f ./sample_file.txt

# Label the hash so you don't have to remember the length
recheck -f ./sample_file.txt -v 'md5:900150983cd24fb0d6963f7d28e17f72' -a md5

# Generate with md5
recheck -f ./sample_file.txt -a md5 -c sample_file.md5.txt

# Verify a whole folder, recursively
recheck -f ./folder -c baseline.sha256
recheck -v baseline.sha256

# Several files at once
recheck -f a.bin -f b.bin -c checksums.txt
```

Find out which file changed — either from the summary block at the end, or
straight from the reports:

```bash
recheck -v baseline.sha256 | tail -5
recheck -v baseline.sha256 | grep -B4 MISMATCH
```

---

## Interoperability

ReCheck manifests use the GNU coreutils format, so `sha256sum` can read them —
and the other way around:

```bash
# ReCheck manifest -> coreutils
recheck -f iso.img -c iso.sha256
sha256sum -c --strict iso.sha256

# coreutils manifest -> ReCheck
sha256sum iso.img > iso.sha256
recheck -v iso.sha256
```

Works with `md5sum` too. Useful when your pipeline already depends on
`sha256sum -c`, for example in a Dockerfile, Jenkins, or GitHub Actions.

---

## Update

```bash
pipx install --force git+https://github.com/1RenXc/ReCheck-Integrity.git
```

## Uninstall

```bash
pipx uninstall recheck
```

---

## Troubleshooting

### `recheck: command not found`

The package is installed but its script folder isn't on `PATH`. Run once:

```bash
pipx ensurepath
```

Then **open a new terminal** — `PATH` is only read when the terminal starts.

### `error: externally-managed-environment`

Your distro protects the system Python from raw package installs (PEP 668).
That is exactly why ReCheck goes through `pipx`, which uses a separate
virtualenv and leaves the system Python untouched.

### `Permission denied` while hashing

Hashing needs read access. For root-owned files:

```bash
sudo recheck -f /etc/shadow
```

### `MISMATCH: the hash does not match`

Two different problems produce this line. The `note:` underneath tells them
apart — read it first.

`the expected value is not a valid sha256 digest` means the hash you pasted
cannot match anything, because a character is not a hex digit or the length is
wrong. Compare `expected:` with `actual:` to spot the typo, or let ReCheck
record the right value:

```bash
recheck -f ./file.txt -c baseline.sha256
```

`the hash does not match` with no `note:` means both values are valid digests
and the file really did change. That is the answer you want from a check.

### Hashes differ between machines

They should. SHA-256 produces the same value for the same input on every
platform. If they differ, the files genuinely differ — ReCheck is not wrong.

---

## License

[MIT](LICENSE) © Dearen Kansil
