# duckpass

`duckpass` is a command-line password manager.

## Prerequisites

- Compiler supporting C++20
- CMake 3.16 or higher
- OpenSSL (including development headers)
- libargon2 (including development headers)

### System Requirements (Linux)

To utilize the OpenSSL Secure Heap and prevent memory swapping to disk, the executable requires the `CAP_IPC_LOCK` capability. If the initialization of the secure heap fails, the application will exit immediately to prevent potential data exposure in memory.

## Build Instructions

```bash
mkdir build
cd build
cmake ..
make
```

## Available Commands

`duckpass` implements the following subcommands:

- `init`: Initialize a new vault.
- `add`: Add a new entry to the vault.
- `get`: Retrieve an entry from the vault.
- `list`: Display a list of all stored entries.
- `delete`: Remove a specific entry.
- `generate`: Generate a random password.
- `rekey`: Change the master password.
- `export`: Export the contents of the vault.
- `shell`: Start an interactive shell mode.
- `completion`: Generate autocompletion scripts for the shell.

## Technical Details

- **Memory Allocation**: Uses `CRYPTO_secure_malloc_init` (64KB limit, 32-byte fragmentation) to allocate locked memory for sensitive operations.
- **Cryptography**: Uses OpenSSL for core cryptographic operations.
- **Key Derivation**: Uses Argon2.
- **Argument Parsing**: Handled via CLI11.
