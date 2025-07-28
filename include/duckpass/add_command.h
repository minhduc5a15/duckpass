#pragma once

#include "duckpass/icommand.h"
#include <string>

namespace CLI {
    class App;
}

class add_command : public i_command {
public:
    explicit add_command(CLI::App *app);

    void execute() override;

    static CLI::App *setup(CLI::App &app);

private:
    std::string name_;
    std::string username_;
    std::string password_;
};
