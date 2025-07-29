#include <iostream>
#include <memory>
#include <string>

#include "CLI/CLI.hpp"
#include "duckpass/command_registry.h"

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

    command_registry registry;

    // --- Setup and Register All Commands ---
    add_command::setup(app);
    list_command::setup(app);
    get_command::setup(app);
    delete_command::setup(app);
    generate_command::setup(app);
    export_command::setup(app);

    registry.register_command("add", [](CLI::App* cmd_app){
        return std::make_unique<add_command>(cmd_app);
    });
    registry.register_command("list", [](CLI::App* cmd_app){
        return std::make_unique<list_command>(cmd_app);
    });
    registry.register_command("get", [](CLI::App* cmd_app){
        return std::make_unique<get_command>(cmd_app);
    });
    registry.register_command("delete", [](CLI::App* cmd_app){
        return std::make_unique<delete_command>(cmd_app);
    });
    registry.register_command("generate", [](CLI::App* cmd_app){
        return std::make_unique<generate_command>(cmd_app);
    });
    registry.register_command("export", [](CLI::App* cmd_app){
        return std::make_unique<export_command>(cmd_app);
    });

    // --- Parsing and Execution ---
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }

    std::unique_ptr<i_command> command = registry.create_command(&app);

    if (command) {
        command->execute();
    } else {
        std::cerr << "Error: Unknown or missing command." << std::endl;
        return 1;
    }

    return 0;
}