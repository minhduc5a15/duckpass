#pragma once

#include <string>
#include <filesystem>
#include "duckpass/json_secure.h"

namespace CLI {
    class App;
}

class export_command {
public:
    static void setup(CLI::App &app);

private:
    static std::string to_csv(const duckpass::SecureJson &j);
    static std::string escape_csv_field(const std::string &field);
};
