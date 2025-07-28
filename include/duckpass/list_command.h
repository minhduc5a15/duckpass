#pragma once
#include "duckpass/icommand.h"

namespace CLI {
    class App;
}

class list_command : public i_command {
public:
    explicit list_command(CLI::App *app);

    void execute() override;

    static CLI::App *setup(CLI::App &app);
};
