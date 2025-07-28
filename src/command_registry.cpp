#include "duckpass/command_registry.h"
#include "CLI/CLI.hpp"

void command_registry::register_command(const std::string &name, command_factory factory) {
    command_factories_[name] = std::move(factory);
}

std::unique_ptr<i_command> command_registry::create_command(CLI::App *app) {
    for (const auto &pair: command_factories_) {
        if (app->get_subcommand(pair.first)->parsed()) {
            return pair.second(app->get_subcommand(pair.first));
        }
    }
    return nullptr;
}
