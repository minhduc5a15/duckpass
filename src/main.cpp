#include <openssl/crypto.h>

#include <iostream>
#include <string>

#include "CLI/CLI.hpp"

// Command headers
#include <curl/curl.h>

#include "duckpass/add_command.h"
#include "duckpass/audit_command.h"
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
    // Allocate 1MB (1048576 bytes) for the Secure Heap, with a minimum fragmentation size of 32 bytes.
    if (CRYPTO_secure_malloc_init(1048576, 32) != 1) {
        std::cerr << "Critical Security Warning: Failed to initialize OpenSSL Secure Heap.\n"
                  << "This might be due to insufficient permissions (CAP_IPC_LOCK on Linux) " << "or OS limitations.\n"
                  << "DuckPass will terminate to prevent sensitive data leakage in memory.\n";
        return 1;
    }

    // 2. Initialize CURL
    curl_global_init(CURL_GLOBAL_ALL);

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
    audit::setup_audit_command(app);
    duckpass::shell::setup(app);
    completion_command::setup(app);

    // --- Parsing and Execution ---
    int exit_code = 0;
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        exit_code = app.exit(e);
    }

    curl_global_cleanup();

    return exit_code;
}
