#pragma once

#include <string>
#include <filesystem>
#include "nlohmann/json.hpp"

namespace CLI {
    class App;
}

class export_command {
public:
    static void setup(CLI::App &app);

private:
    static std::string to_csv(const nlohmann::json &j);
    static std::string escape_csv_field(const std::string &field);
};