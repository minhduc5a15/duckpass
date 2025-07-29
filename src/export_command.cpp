#include "duckpass/export_command.h"
#include "duckpass/config_handler.h"
#include "duckpass/utils.h"
#include "duckpass/vault.h"
#include "CLI/CLI.hpp"
#include <iostream>
#include <fstream>

CLI::App *export_command::setup(CLI::App &app) {
    CLI::App *export_cmd = app.add_subcommand("export", "Export the vault to a plain text file (CSV or JSON)");

    export_cmd->add_option("-o,--output", "The path to the output file")->required();
    export_cmd->add_option("-f,--format", "The output format (csv, json)")->default_val("csv");
    export_cmd->add_flag("--pretty", "Pretty-print JSON output");

    return export_cmd;
}

export_command::export_command(CLI::App *app) {
    app->get_option("--output")->results(output_path_);
    app->get_option("--format")->results(format_);
    pretty_print_ = app->get_option("--pretty")->as<bool>();
}

void export_command::execute() {
    config_handler config;
    auto vault_path = config.get_vault_path();

    if (!vault_handler::vault_exists(vault_path)) {
        std::cerr << "Error: Vault file not found. Nothing to export." << std::endl;
        return;
    }

    // 1. Get password and decrypt vault
    std::string master_password = get_password_silent("Enter master password to export: ");
    nlohmann::json vault_data;
    try {
        vault_data = vault_handler::load_vault(vault_path, master_password);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return;
    }

    if (vault_data.empty()) {
        std::cout << "Info: Vault is empty. Nothing to export." << std::endl;
        return;
    }

    // 2. Format data
    std::string output_data;
    if (format_ == "csv") {
        output_data = to_csv(vault_data);
    }
    else if (format_ == "json") {
        if (pretty_print_) {
            output_data = vault_data.dump(4);
        }
        else {
            output_data = vault_data.dump();
        }
    }
    else {
        std::cerr << "Error: Invalid format '" << format_ << "'. Please use 'csv' or 'json'." << std::endl;
        return;
    }

    // 3. Write to file
    std::ofstream output_file(output_path_);
    if (!output_file) {
        std::cerr << "Error: Could not open file for writing: " << output_path_ << std::endl;
        return;
    }
    output_file << output_data;
    output_file.close();

    // 4. Print success and security warning
    std::cout << "Success: Vault has been exported to " << output_path_ << std::endl;
    std::cout << "\n#################################################################" << std::endl;
    std::cout << "# WARNING: SECURITY RISK                                      #" << std::endl;
    std::cout << "# The file '" << output_path_.filename().string() << "' IS NOT ENCRYPTED and contains all your #" << std::endl;
    std::cout << "# passwords in plain text.                                    #" << std::endl;
    std::cout << "# Please store it in a secure location and delete it when     #" << std::endl;
    std::cout << "# it is no longer needed.                                     #" << std::endl;
    std::cout << "#################################################################" << std::endl;
}

// Helper implementation to escape a single field for CSV
std::string export_command::escape_csv_field(const std::string &field) {
    std::string result = "\"";
    for (char c: field) {
        if (c == '\"') {
            result += "\"\"";
        }
        else {
            result += c;
        }
    }
    result += "\"";
    return result;
}

// Helper implementation to convert JSON to CSV string
std::string export_command::to_csv(const nlohmann::json &j) {
    std::string csv_string = "name,username,password\n";

    for (auto &el: j.items()) {
        const std::string &name = el.key();
        const std::string &username = el.value().value("username", "");
        const std::string &password = el.value().value("password", "");

        csv_string += escape_csv_field(name) + ",";
        csv_string += escape_csv_field(username) + ",";
        csv_string += escape_csv_field(password) + "\n";
    }

    return csv_string;
}
