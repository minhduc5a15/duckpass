#pragma once
#include "duckpass/icommand.h"

namespace CLI {
    class App;
}

class generate_command : public i_command {
public:
    explicit generate_command(CLI::App *app);

    void execute() override;

    static CLI::App *setup(CLI::App &app);

private:
    int length_;
};
