#pragma once
#include "duckpass/icommand.h"
#include "nlohmann/json.hpp"
#include <string>
#include <filesystem>

namespace CLI {
    class App;
}

class export_command : public i_command {
public:
    explicit export_command(CLI::App* app);
    void execute() override;
    static CLI::App* setup(CLI::App& app);

private:
    std::filesystem::path output_path_;
    std::string format_;
    bool pretty_print_;

    // Helper method to format data to CSV
    static std::string to_csv(const nlohmann::json& j);
    // Helper method to escape a single CSV field
    static std::string escape_csv_field(const std::string& field);
};