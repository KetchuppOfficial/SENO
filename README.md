# Symbolic Execution for Neutralizing Overflow

## Requirements

Installed nix package manager (can be install with apt on debian-like distributions).

## How to use

### Create development environment

```bash
nix develop
```

You may need to pass additional options to nix in case you do not have corresponding features set
in nix.conf.

```bash
nix develop --extra-experimental-features nix-command --extra-experimental-features flakes
```

### Create virtual environment

```bash
python3 -m venv .venv
```

### Install dependencies

```bash
.venv/bin/pip3 install .
```

### Build test binary

- x86-64

```bash
cmake -S examples -B build -DBUFFER_SIZE=16
cmake --build build
```

- AArch64

```bash
cmake -S examples -B build-aarch64 -DBUFFER_SIZE=16 -DCMAKE_C_COMPILER=aarch64-unknown-linux-gnu-gcc
cmake --build build-aarch64
```

### Run the script

```bash
# usage: seno [-h] [--argv-count ARGV_COUNT] [--log LOG] input
#
# SENO: Symbolic Execution for Neutralizing Overflow. A tool finding various cases of overflow in x86-64 and AArch64 ELF binaries
#
# positional arguments:
#   input                 input ELF file for x86-64 or AArch64 platform
#
# options:
#   -h, --help            show this help message and exit
#   --argv-count ARGV_COUNT
#                         the number of arguments that main function of the binary expects
#   --log LOG             name of the log file
```
