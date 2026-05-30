#pragma once

#include <string>

namespace CLI {
    class App;
}

class delete_command {
public:
    static void setup(CLI::App &app);
};

