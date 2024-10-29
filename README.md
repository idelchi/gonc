# gonc

`gonc` is a simple command-line utility that

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
gonc [flags] [paths...]
```

Run `gonc` with the desired flags. The available flags include:

```sh
--include: Specify one or more include patterns (can be used multiple times)
--exclude: Specify one or more exclude patterns (can be used multiple times)
```

Example:

```sh
gonc
```

For more details on usage and configuration, run:

```sh
gonc --help
```

This will display a comprehensive list of flags and their descriptions.
