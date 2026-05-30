#pragma once

#include <string>
#include "duckpass/secure_allocator.h"

namespace CLI {
    class App;
}

class add_command {
public:
    static void setup(CLI::App &app);
};
