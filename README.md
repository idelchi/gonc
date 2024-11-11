# gonc

[![Go Reference](https://pkg.go.dev/badge/github.com/idelchi/gonc.svg)](https://pkg.go.dev/github.com/idelchi/gonc)
[![Go Report Card](https://goreportcard.com/badge/github.com/idelchi/gonc)](https://goreportcard.com/report/github.com/idelchi/gonc)
[![Build Status](https://github.com/idelchi/gonc/actions/workflows/github-actions.yml/badge.svg)](https://github.com/idelchi/gonc/actions/workflows/github-actions.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`gonc` is a simple command-line utility that provides secure file encryption,
with support for deterministic and non-deterministic modes.

## Installation

### From source

```sh
go install github.com/idelchi/gonc@latest
```

### From installation script

```sh
curl -sSL https://raw.githubusercontent.com/idelchi/gonc/refs/heads/dev/install.sh | sh -s -- -d ~/.local/bin
```

## Usage

```sh
gonc [flags] command [flags] [paths...]
```

### Global Flags and Environment Variables

| Flag                  | Environment Variable | Description                  | Default   | Valid Values    |
| --------------------- | -------------------- | ---------------------------- | --------- | --------------- |
| `-k, --key`           | `GONC_KEY`           | Encryption key (hex-encoded) | -         | 32/64 bytes     |
| `-f, --key-file`      | `GONC_KEY_FILE`      | Path to encryption key file  | -         | 32/64 bytes key |
| `-j, --parallel`      | `GONC_PARALLEL`      | Number of parallel workers   | CPU count | > 0             |
| `--decrypt-ext`       | `GONC_DECRYPT_EXT`   | Suffix for decrypted files   | `""`      | -               |
| `--encrypt-ext`       | `GONC_ENCRYPT_EXT`   | Suffix for encrypted files   | `.enc`    | -               |
| `-d, --deterministic` | `GONC_DETERMINISTIC` | Use deterministic encryption | `false`   | -               |
| `-q, --quiet`         | `GONC_QUIET`         | Suppress output              | `false`   | -               |
| `-h, --help`          | -                    | Help for gonc                | -         | -               |
| `-v, --version`       | -                    | Version for gonc             | -         | -               |

### Commands

#### `encrypt` (alias: `enc`) - Encrypt files

Encrypt one or more files using the specified key.

Examples:

```sh
# Encrypt files with deterministic mode
gonc -k <key> -d encrypt file1.txt file2.txt
# Output: file1.txt.enc, file2.txt.enc

# Encrypt files with custom extension
gonc -k <key> --encrypt-ext .encrypted encrypt file1.txt
# Output: file1.txt.encrypted
```

#### `decrypt` (alias: `dec`) - Decrypt files

Decrypt one or more encrypted files using the specified key.

Examples:

```sh
# Decrypt files
gonc -k <key> decrypt file1.txt.enc file2.txt.enc
# Output: file1.txt, file2.txt

# Decrypt with custom extension
gonc -k <key> --decrypt-ext .decrypted decrypt file1.txt.enc
# Output: file1.txt.decrypted
```

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
