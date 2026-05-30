#include <iostream>
#include <memory>
#include <string>

#include "CLI/CLI.hpp"

// Command headers
#include "duckpass/add_command.h"
#include "duckpass/list_command.h"
#include "duckpass/get_command.h"
#include "duckpass/delete_command.h"
#include "duckpass/generate_command.h"
#include "duckpass/export_command.h"

int main(int argc, char** argv) {
    CLI::App app{"duckpass: A modular command-line password manager"};
    app.require_subcommand(1);

    // --- Setup All Commands using CLI11 Callbacks ---
    add_command::setup(app);
    list_command::setup(app);
    get_command::setup(app);
    delete_command::setup(app);
    generate_command::setup(app);
    export_command::setup(app);

    // --- Parsing and Execution ---
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }

    return 0;
}
