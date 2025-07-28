#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>

#include "icommand.h"

namespace CLI {
    class App;
}

// A type alias for a function that creates a command
using command_factory = std::function<std::unique_ptr<i_command>(CLI::App *)>;

class command_registry {
public:
    void register_command(const std::string &name, command_factory factory);

    std::unique_ptr<i_command> create_command(const CLI::App *app) const;

private:
    std::map<std::string, command_factory> command_factories_;
};
