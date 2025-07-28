#include <iostream>
#include <memory>
#include <termios.h>
#include <unistd.h>

#include "CLI/CLI.hpp"
#include "duckpass/command_registry.h"
#include "duckpass/add_command.h"

int main(int argc, char **argv) {
    CLI::App app{"duckpass: A modular command-line password manager"};
    app.require_subcommand(1);

    command_registry registry;

    // --- Setup and Register All Commands ---
    add_command::setup(app);
    // get_command::setup(app);

    registry.register_command("add", [](CLI::App *cmd_app) {
        return std::make_unique<add_command>(cmd_app);
    });
    // registry.register_command("get", ...);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }

    std::unique_ptr<i_command> command = registry.create_command(&app);

    if (command) {
        command->execute();
    }
    else {
        std::cerr << "Error: Unknown or missing command." << std::endl;
        return 1;
    }

    return 0;
}
