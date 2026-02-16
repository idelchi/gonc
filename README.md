# gonc

[![Go Reference](https://pkg.go.dev/badge/github.com/idelchi/gonc.svg)](https://pkg.go.dev/github.com/idelchi/gonc)
[![Go Report Card](https://goreportcard.com/badge/github.com/idelchi/gonc)](https://goreportcard.com/report/github.com/idelchi/gonc)
[![Build Status](https://github.com/idelchi/gonc/actions/workflows/github-actions.yml/badge.svg)](https://github.com/idelchi/gonc/actions/workflows/github-actions.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`gonc` is a simple command-line utility that provides secure file encryption,
with support for deterministic and non-deterministic modes.

## Installation

```sh
curl -sSL https://raw.githubusercontent.com/idelchi/gonc/refs/heads/main/install.sh | sh -s -- -d ~/.local/bin
```

## Usage

```sh
gonc [flags] command [flags] [paths...]
```

### Configuration

| Flag                    | Env                        | Description                             | Default   |
| ----------------------- | -------------------------- | --------------------------------------- | --------- |
| `-s, --show`            | -                          | Show configuration and exit             | -         |
| `-j, --parallel`        | `GONC_PARALLEL`            | Number of parallel workers              | CPU count |
| `-q, --quiet`           | `GONC_QUIET`               | Suppress output                         | `false`   |
| `--delete`              | `GONC_DELETE`              | Delete originals after processing       | `false`   |
| `-k, --key`             | `GONC_KEY`                 | Encryption key (hex-encoded)            | -         |
| `-f, --key-file`        | `GONC_KEY_FILE`            | Path to encryption key file             | -         |
| `--encrypt-ext`         | `GONC_ENCRYPT_EXT`         | Suffix for encrypted files              | `.enc`    |
| `--decrypt-ext`         | `GONC_DECRYPT_EXT`         | Suffix for decrypted files              | `""`      |
| `--include`             | `GONC_INCLUDE`             | Patterns to narrow walked results       | -         |
| `--exclude`             | `GONC_EXCLUDE`             | Patterns to exclude from walked results | -         |
| `--include-from`        | `GONC_INCLUDE_FROM`        | JSONC file with include patterns        | -         |
| `--exclude-from`        | `GONC_EXCLUDE_FROM`        | JSONC file with exclude patterns        | -         |
| `--dry`                 | `GONC_DRY`                 | Preview without processing              | `false`   |
| `--preserve-timestamps` | `GONC_PRESERVE_TIMESTAMPS` | Preserve file modification times        | `false`   |
| `--stats`               | `GONC_STATS`               | Print processing statistics             | `false`   |
| `-h, --help`            | -                          | Help for gonc                           | -         |
| `-v, --version`         | -                          | Version for gonc                        | -         |

### File Selection

Positional arguments are **paths** — files or directories. No arguments defaults to `.` (current directory).

```text
Pipeline:
1. Each positional arg is classified as file or directory
2. Files → added directly to the result set (bypass all filtering)
3. Directories → walked recursively with filepath.WalkDir
   → each discovered file is tested against --include/--exclude patterns
4. Deduplicate
5. Process
```

Paths must be within the current working directory. Absolute paths and `../` are rejected.

### Pattern Syntax

Patterns use `find -path` semantics ([fnmatch(3)](https://man7.org/linux/man-pages/man3/fnmatch.3.html) without `FNM_PATHNAME`):

| Wildcard | Meaning                                         |
| -------- | ----------------------------------------------- |
| `*`      | Matches any characters **including** `/`        |
| `?`      | Matches exactly one character **including** `/` |
| `[...]`  | Matches one character from the set              |
| `[!...]` | Matches one character NOT in the set            |
| `\`      | Escapes the next character                      |

This differs from shell globbing and Go's `filepath.Match` where `*` and `?` do not cross `/`.

`--include` narrows walked results (only matching files pass). `--exclude` removes matching files.
Excludes always win. Both are ignored for explicit file paths.

`--include-from` and `--exclude-from` load patterns from a JSONC file (JSON with comments):

```jsonc
[
  "doc/*", // everything under doc/
  "tools/canlib/*", // everything under tools/canlib/
  "path/to/file.c", // exact file
]
```

### Examples

```sh
# Encrypt everything in current directory
gonc -k <key> encrypt

# Encrypt a specific directory
gonc -k <key> encrypt ./secrets

# Encrypt specific files (bypass filtering)
gonc -k <key> encrypt file1.txt file2.txt

# Walk directory with exclusions
gonc -k <key> encrypt . --exclude "doc/*" --exclude "test/*"

# Walk directory with inclusions (only matching files)
gonc -k <key> encrypt . --include "src/*"

# Using pattern files
gonc -k <key> encrypt . --include-from whitelist.jsonc --exclude-from blacklist.jsonc

# Preserve timestamps (output file gets same mtime as input)
gonc -k <key> encrypt --preserve-timestamps .

# Dry run — preview what would be processed
gonc --dry encrypt .

# Show stats after processing
gonc -k <key> encrypt --stats .

# Delete originals after encryption
gonc -k <key> --delete encrypt .
```

### Commands

#### `encrypt` (alias: `enc`) - Encrypt files

Encrypt files using the specified key.

Examples:

```sh
# Encrypt with deterministic mode
gonc -k <key> encrypt -d file1.txt file2.txt
# Output: file1.txt.enc, file2.txt.enc

# Encrypt with custom extension
gonc -k <key> --encrypt-ext .encrypted encrypt file1.txt
# Output: file1.txt.encrypted
```

| Flag                  | Environment Variable | Description                  | Default |
| --------------------- | -------------------- | ---------------------------- | ------- |
| `-d, --deterministic` | `GONC_DETERMINISTIC` | Use deterministic encryption | `false` |

#### `decrypt` (alias: `dec`) - Decrypt files

Decrypt encrypted files using the specified key. The embedded header
indicates whether deterministic or randomized mode was used, so no additional flag
is required.

When walking directories, decrypt automatically filters by `--encrypt-ext`
(default `*.enc`). Explicit `--include` or `--include-from` overrides this.

Examples:

```sh
# Decrypt all .enc files in current directory (auto-filtered)
gonc -k <key> decrypt .

# Decrypt specific files (bypass filtering)
gonc -k <key> decrypt file1.txt.enc file2.txt.enc
# Output: file1.txt, file2.txt

# Decrypt with custom extension
gonc -k <key> --decrypt-ext .decrypted decrypt file1.txt.enc
# Output: file1.txt.decrypted

# Custom encrypt-ext — auto-filters by it
gonc -k <key> --encrypt-ext .sensitive.enc decrypt .
# Only processes *.sensitive.enc files
```

#### `redact` (alias: `red`) - Replace file contents

Replace file contents with a fixed string. No encryption — a one-way
destructive operation. Output files get `--encrypt-ext` suffix.
Does not require `--key`.

Examples:

```sh
# Redact all files in current directory
gonc redact .
# Output: file1.txt.enc contains "<REDACTED>"

# Redact with custom content
gonc redact --content "CLASSIFIED" ./secrets
# Output: each file.enc contains "CLASSIFIED"

# Redact and delete originals
gonc --delete redact .

# Preview what would be redacted
gonc --dry redact .
```

| Flag        | Env            | Description         | Default      |
| ----------- | -------------- | ------------------- | ------------ |
| `--content` | `GONC_CONTENT` | Replacement content | `<REDACTED>` |

### Key Format

- Keys must be hex-encoded
- Supported lengths: 32 bytes (64 hex characters) or 64 bytes (128 hex characters)
- Can be provided directly via `--key` or in a file via `--key-file`

### Encryption Modes

| Mode          | Description                                      | Use Case                            |
| ------------- | ------------------------------------------------ | ----------------------------------- |
| Standard      | Non-deterministic encryption using unique nonces | Default mode, maximum security      |
| Deterministic | Same input produces same output                  | When detecting changes is important |

For detailed help:

```sh
gonc --help
gonc <command> --help
```
