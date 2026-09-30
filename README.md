# DuckPass 🦆

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B20)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#building--testing)
[![Tests](https://img.shields.io/badge/tests-47%20passed-success.svg)](#running-tests)

**DuckPass** is an enterprise-grade, privacy-first command-line password manager and credential vault written in modern C++20. Designed with a zero-compromise security architecture, DuckPass combines state-of-the-art cryptography, strict kernel-level memory isolation, transactional crash-safety, and an autonomous background agent daemon for effortless CLI ergonomics.

---

## Key Features

- **End-to-End Cryptography**: Powered by **Argon2id** password hashing and **AES-256-GCM** authenticated encryption with format version binding.
- **Hardware-Isolated & Locked Memory**: Uses OpenSSL Secure Heap (`mmap(MAP_LOCKED)`) with guard pages to prevent secrets from touching swap or core dumps.
- **Multi-Tier Process Isolation**: Executes memory-intensive password entropy analysis (`zxcvbn-c`) in a dedicated, sandboxed worker process to guarantee zero heap residue in the parent process.
- **Background Session Agent (`duckpass-agent`)**: High-performance UNIX domain socket daemon caching credentials in memory-locked pages with configurable auto-lock timeouts and multi-client synchronization.
- **Transactional & Crash-Safe Storage**: Atomic file writes, kernel file locking (`flock(LOCK_EX)`), and two-phase atomic rekeying guaranteeing consistent rollback on power loss or disk failure.
- **Integrated 2FA / TOTP Authenticator**: Built-in RFC 6238 Time-Based One-Time Password generator with Base32 decoding and clipboard copying.
- **Deep Security Audits**: Offline entropy checks, password reuse detection, staleness tracking, and optional online breach audits via **Have I Been Pwned** using $k$-Anonymity.
- **Export & Import Protection**: Formula injection shielding for CSV exports (mitigating spreadsheet macro attacks) and strict RFC 8259 JSON escaping with `0600` file permissions.
- **Interactive Shell & Auto-Completion**: Interactive REPL with readline-style tab completion and pre-generated shell completion scripts for Bash and Zsh.

---

## Architectural & Security Blueprint

```
+---------------------------------------------------------------------------------+
|                                 DuckPass CLI                                    |
|                                                                                 |
|  [ Commands: add | get | list | delete | rekey | otp | audit | export | shell ]  |
+--------------------------+------------------------------+-----------------------+
                           |                              |
            UNIX Socket IPC| (21-byte wire protocol)      | UNIX Socket IPC
            (Framed binary)|                              | (Length-prefixed binary)
                           v                              v
            +------------------------------+  +-------------------------------+
            |    duckpass-entropy-worker   |  |        duckpass-agent         |
            |------------------------------|  |-------------------------------|
            | - Sandboxed subprocess       |  | - Background session daemon   |
            | - 1 MB OpenSSL Secure Heap   |  | - Memory-locked session cache |
            | - zxcvbn-c library           |  | - Auto-lock timeout loop      |
            | - Zero parent memory residue |  | - Mutex & cache sync beacons  |
            +------------------------------+  +-------------------------------+
```

### 1. Cryptographic Design

- **Key Derivation (KDF)**: Argon2id with 64 MB memory cost ($m=65536$), 3 iterations ($t=3$), 4 parallelism lanes ($p=4$), and cryptographically secure 16-byte random salts.
- **Vault Encryption**: AES-256-GCM with a 12-byte random IV and 16-byte authentication tag. The Additional Authenticated Data (AAD) binds the header version tag (`DUCKPASS_V1`) to prevent ciphertext substitution.
- **In-Memory Protection**: Sensitive fields in transit use `duckpass::ProtectedString` with dynamic per-instance XOR masking, random canaries, and automatic zeroization (`OPENSSL_cleanse`) on destruction.

### 2. Transactional Rekey & Crash Safety

Rekeying a vault is an atomic, crash-safe transaction:

1. **Advisory Locking**: Acquires a fail-fast exclusive lock (`flock(LOCK_EX)`) with `EINTR` retry handling.
2. **Merge Disk State**: Merges any concurrent disk writes using the current master password.
3. **One-Shot Encryption**: Derives the new key and encrypts the vault payload into a single payload buffer.
4. **Backup Staging**: Writes directly to `.duckvault.bak` without recursive backups.
5. **Canonical Commit**: Atomically writes to `.duckvault` via temporary files (`.tmp.<pid>.<uuid>`) with `fsync()` and `rename()`. A RAII `TempFileGuard` ensures temporary files are destroyed if an error occurs.
6. **RAM State Update**: Only after both disk writes succeed is the in-memory master password updated.

### 3. Worker Process Isolation (`zxcvbn-c`)

To eliminate plaintext remnants left by third-party C libraries:

- `zxcvbn` is decoupled from `duckpass_core` and linked strictly to `duckpass-entropy-worker`.
- Communication occurs across unidirectional pipes using a canonical 21-byte Little-Endian protocol (`std::bit_cast<uint64_t>` for `double` fields).
- A custom RAII `SigpipeBlocker` consumes pending `SIGPIPE` signals with `sigtimedwait()` on broken pipes before restoring masks, preventing unexpected process crashes.
- An overall 5-second deadline strictly covers pipe writes, reads, and child reaping (`waitpid(WNOHANG)` / `SIGKILL`).

---

## Prerequisites & Installation

### Build Dependencies

- **C++ Compiler**: Supporting C++20 (GCC 11+ or Clang 13+)
- **Build System**: CMake 3.16+ and Ninja (or Make)
- **Core Libraries**:
  - OpenSSL (libcrypto development headers $\ge$ 1.1.1)
  - libargon2 (development headers)
  - libcurl (development headers)
- **Optional Tools**: `xclip` / `xsel` (X11) or `wl-clipboard` (Wayland) for clipboard copying.

#### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build \
    libssl-dev libargon2-dev libcurl4-openssl-dev xclip
```

#### Fedora / RHEL

```bash
sudo dnf install -y gcc-c++ cmake ninja-build \
    openssl-devel libargon2-devel libcurl-devel xclip
```

#### Arch Linux

```bash
sudo pacman -S base-devel cmake ninja openssl argon2 curl xclip
```

### Linux Secure Heap Requirement (`CAP_IPC_LOCK`)

To lock memory pages and prevent secrets from paging to disk:

```bash
# Optional but recommended for production binaries:
sudo setcap cap_ipc_lock=+ep ./build/duckpass
sudo setcap cap_ipc_lock=+ep ./build/duckpass-agent
sudo setcap cap_ipc_lock=+ep ./build/duckpass-entropy-worker
```

_(If capabilities are not configured or memory locking is restricted, DuckPass falls back to secure heap without mlock, issuing a diagnostic warning)._

---

## Building & Testing

### 1. Build the Binaries

```bash
# Configure build directory with Ninja
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release

# Compile all targets
cmake --build build
```

This compiles:

- `build/duckpass`: Main CLI client.
- `build/duckpass-agent`: Background session daemon.
- `build/duckpass-entropy-worker`: Isolated entropy evaluation worker.
- `build/duckpass_unit_tests`: Comprehensive GoogleTest suite.

### 2. Run the Test Suite

DuckPass includes 47 unit and integration tests covering cryptography, storage reliability, IPC, TOTP test vectors, transaction rollback, and deadlock prevention:

```bash
ctest --test-dir build --output-on-failure
```

Or run the binary directly:

```bash
./build/duckpass_unit_tests
```

### 3. Verify Clean Dependency Boundary

Verify that `duckpass` and `duckpass-agent` are completely isolated from `zxcvbn`:

```bash
nm build/duckpass | grep -i zxcvbn || echo "duckpass is CLEAN"
nm build/duckpass-agent | grep -i zxcvbn || echo "duckpass-agent is CLEAN"
```

---

## Command-Line Usage

### 1. Initialize a New Vault

```bash
duckpass init
```

Initializes a new encrypted vault at `~/.duckvault` (or custom path set via `DUCKPASS_VAULT_PATH`).

### 2. Manage Entries

```bash
# Add an entry (prompts for password and optional TOTP secret securely)
duckpass add github octocat@github.com

# Retrieve password (copies to clipboard by default)
duckpass get github

# Display password on terminal stdout
duckpass get github --show

# List all stored entries
duckpass list

# Fuzzy search entries
duckpass list git

# Delete an entry
duckpass delete github
```

### 3. Time-Based One-Time Passwords (2FA / TOTP)

```bash
# Generate current 6-digit TOTP code
duckpass otp github

# Generate and copy directly to clipboard
duckpass otp github --copy
```

### 4. Background Session Agent

Eliminates repetitive password entry while working in terminal sessions:

```bash
# Start the background daemon
duckpass agent start

# Unlock the session (caches master key in locked memory)
duckpass agent unlock

# Check daemon health and session status
duckpass agent status

# CLI commands now automatically use the active agent session!
duckpass get github
duckpass list

# Lock session and purge keys from memory
duckpass agent lock

# Terminate the agent process
duckpass agent stop
```

### 5. Security Audit

Perform deep offline security evaluations and optional online breach checks:

```bash
# Offline audit: checks entropy (via isolated worker), reuse, and stale passwords
duckpass audit

# Specify stale password age threshold (default: 365 days)
duckpass audit --stale-days 180

# Online audit: check against Have I Been Pwned database using k-Anonymity
duckpass audit --online
```

### 6. Rekey Vault (Change Master Password)

```bash
duckpass rekey
```

Prompts for current and new master passwords, executes the transactional rekey sequence, and updates `.duckvault` and `.duckvault.bak`.

### 7. Export Vault

```bash
# Export to CSV (with formula injection defense)
duckpass export -o backup.csv -f csv

# Export to formatted JSON
duckpass export -o backup.json -f json
```

### 8. Interactive Shell & Autocompletion

```bash
# Launch interactive REPL with tab auto-completion
duckpass shell

# Generate Bash completion script
duckpass completion bash > ~/.bash_completion.d/duckpass

# Generate Zsh completion script
duckpass completion zsh > ~/.zsh/completion/_duckpass
```

---

## Project Structure

```
duckpass/
├── include/duckpass/        # Public API headers
│   ├── crypto.h             # Argon2id, AES-256-GCM, and PRNG primitives
│   ├── protected_string.h   # Ephemeral XOR-masked secure memory string
│   ├── vault.h              # Vault data structures & serialization
│   ├── vault_service.h      # Transactional vault operations & rekey engine
│   ├── local_storage.h      # Atomic file I/O & fail-fast flock guards
│   ├── audit_engine.h       # Password reuse & staleness auditor
│   ├── entropy_evaluator.h  # IPC client for entropy worker
│   ├── totp.h               # RFC 6238 TOTP engine & Base32 decoder
│   ├── ipc.h                # Binary IPC framing protocol
│   └── agent_server.h       # Unix socket agent daemon architecture
├── src/                     # Source implementations
│   ├── main.cpp             # CLI entrypoint
│   ├── daemon_main.cpp      # duckpass-agent entrypoint
│   ├── entropy_worker_main.cpp # Standalone zxcvbn isolated worker
│   └── ...                  # Subcommand & core modules
├── vendor/                  # Embedded vendor libraries
│   ├── CLI11.hpp            # Header-only CLI argument parser
│   ├── json.hpp             # nlohmann/json parser
│   └── zxcvbn-c/            # C password strength estimation engine
├── tests/                   # GoogleTest unit & regression test suites
├── completions/             # Shell completion definitions
├── CMakeLists.txt           # Modern CMake build definitions
├── format.sh                # Pre-commit clang-format automation script
└── LICENSE                  # MIT License
```

---

## Development & Code Quality

DuckPass enforces clean code principles, strict POSIX signal handling, and zero memory leaks.

```bash
# Format C++ code with clang-format
./format.sh

# Build with AddressSanitizer and UndefinedBehaviorSanitizer
cmake -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

---

## License

DuckPass is licensed under the [MIT License](LICENSE).
Copyright (c) 2026 Pham Minh Duc.
