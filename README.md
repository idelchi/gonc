# gonc

`gonc` is a simple command-line utility that provides secure file encryption,
with support for deterministic and non-deterministic modes.

It provides commands for encryption and decryption.

## Installation

### From source

```sh
go install github.com/idelchi/gonc/cmd/gonc@latest
```

### From installation script

```sh
curl -sSL https://raw.githubusercontent.com/idelchi/gonc/refs/heads/dev/install.sh | sh -s -- -d ~/.local/bin
```

## Usage

```sh
gonc [flags] <command> [flags] [paths...]
```

Run `gonc` with the desired flags. The available flags include:

```sh
Flags:
  -k, --key string            Encryption key (32/64 bytes, hex-encoded)
  -f, --key-file string       Path to a file containing the encryption key (32/64 bytes, hex-encoded)
  -j, --parallel int          Number of parallel workers (defaults to the number of CPUs)
      --decrypt-ext string    Suffix to append to decrypted files, after stripping the encrypted suffix (default "")
      --encrypt-ext string    Suffix to append to encrypted files (default ".enc")
  -d, --deterministic         Use deterministic encryption mode. Valid for "generate" and "encrypt" commands
  -h, --help                  help for gonc
  -v, --version               version for gonc
```

The utility supports the following commands:

```sh
Available Commands:
  encrypt       Encrypt files (aliases: enc)
  decrypt       Decrypt files (aliases: dec)
  help          Help about any command
```

Example:

```sh
# Encrypt files
gonc -k <key> encrypt file1.txt file2.txt

# Decrypt files
gonc -k <key> decrypt file1.txt.enc file2.txt.enc
```

For more details on usage and configuration, run:

```sh
gonc --help
```

This will display a comprehensive list of flags and their descriptions.
