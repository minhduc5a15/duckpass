#pragma once
#include "duckpass/icommand.h"
#include <string>

namespace CLI {
    class App;
}

class get_command : public i_command {
public:
    explicit get_command(CLI::App *app);

    void execute() override;

    static CLI::App *setup(CLI::App &app);

private:
    std::string name_;
    bool copy_to_clipboard_;
};
