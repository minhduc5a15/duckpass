#include <openssl/crypto.h>

#include <iostream>
#include <string>

#include "CLI/CLI.hpp"

// Command headers
#include "duckpass/add_command.h"
#include "duckpass/completion_command.h"
#include "duckpass/delete_command.h"
#include "duckpass/export_command.h"
#include "duckpass/generate_command.h"
#include "duckpass/get_command.h"
#include "duckpass/init_command.h"
#include "duckpass/list_command.h"
#include "duckpass/rekey_command.h"
#include "duckpass/shell_command.h"

int main(int argc, char** argv) {
    // 1. Initialize OpenSSL Secure Heap
    // Allocate 64KB (65536 bytes) for the Secure Heap, with a minimum fragmentation size of 32 bytes.
    if (CRYPTO_secure_malloc_init(65536, 32) != 1) {
        std::cerr << "Critical Security Warning: Failed to initialize OpenSSL Secure Heap.\n"
                  << "This might be due to insufficient permissions (CAP_IPC_LOCK on Linux) " << "or OS limitations.\n"
                  << "DuckPass will terminate to prevent sensitive data leakage in memory.\n";
        return 1;
    }

    CLI::App app{"duckpass: A modular command-line password manager", "duckpass"};
    app.require_subcommand(1);

    // --- Setup All Commands using CLI11 Callbacks ---
    init_command::setup(app);
    rekey_command::setup(app);
    add_command::setup(app);
    list_command::setup(app);
    get_command::setup(app);
    delete_command::setup(app);
    generate_command::setup(app);
    export_command::setup(app);
    duckpass::shell::setup(app);
    completion_command::setup(app);

    // --- Parsing and Execution ---
    int exit_code = 0;
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        exit_code = app.exit(e);
    }

    // Done with secure memory
    // OPENSSL_secure_malloc_done(); // Optional but clean

    return exit_code;
}
