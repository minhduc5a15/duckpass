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
    static void write_csv(std::ostream &os, const vault_handler::Vault &vault);
    static void write_csv_field(std::ostream &os, const duckpass::SecureString &field);
    static void write_json(std::ostream &os, const vault_handler::Vault &vault);
    static void write_json_string(std::ostream &os, const duckpass::SecureString &str);
};
