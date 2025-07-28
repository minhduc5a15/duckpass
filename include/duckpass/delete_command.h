#pragma once
#include "duckpass/icommand.h"
#include <string>

namespace CLI {
    class App;
}

class delete_command : public i_command {
public:
    explicit delete_command(CLI::App *app);

    void execute() override;

    static CLI::App *setup(CLI::App &app);

private:
    std::string name_;
};
