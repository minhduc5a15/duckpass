#pragma once

#include <filesystem>
#include <string>

#include "duckpass/vault.h"

namespace CLI {
    class App;
}

class export_command {
public:
    static void setup(CLI::App &app);

private:
    static std::string to_csv(const vault_handler::Vault &vault);
    static std::string escape_csv_field(const std::string &field);
};
