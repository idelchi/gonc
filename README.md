# gonc

`gonc` is a simple command-line utility that provides secure file encryption with support for deterministic and non-deterministic modes.

It provides commands for key generation, encryption, and decryption.

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
      --decrypt-ext string   Suffix to append to decrypted files. If empty, the suffix will be removed
      --encrypt-ext string   Suffix to append to encrypted files (default ".enc")
  -h, --help                 help for gonc
  -k, --key string          Encryption key (32 bytes, hex-encoded)
  -j, --parallel int        Number of parallel workers (default 16)
  -v, --version             version for gonc
```

The utility supports the following commands:

```sh
Available Commands:
  decrypt     Decrypt files
  encrypt     Encrypt files
  generate    Generate a new encryption key
  help        Help about any command
```

Example:

```sh
# Generate a new encryption key
gonc generate

# Encrypt files with the generated key
gonc encrypt -k <your-key> file1.txt file2.txt

# Decrypt files
gonc decrypt -k <your-key> file1.txt.enc file2.txt.enc
```

For more details on usage and configuration, run:

```sh
gonc --help
```

This will display a comprehensive list of flags and their descriptions.
