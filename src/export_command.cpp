#include "duckpass/export_command.h"

#include <fstream>
#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/utils.h"
#include "duckpass/vault.h"

void export_command::setup(CLI::App &app) {
    auto export_cmd = app.add_subcommand("export", "Export the vault to a plain text file (CSV or JSON)");

    auto output_path = std::make_shared<std::filesystem::path>();
    auto format = std::make_shared<std::string>("csv");
    auto pretty_print = std::make_shared<bool>(false);

    export_cmd->add_option("-o,--output", *output_path, "The path to the output file")->required();
    export_cmd->add_option("-f,--format", *format, "The output format (csv, json)")->default_val("csv");
    export_cmd->add_flag("--pretty", *pretty_print, "Pretty-print JSON output");

    export_cmd->callback([output_path, format, pretty_print]() {
        config_handler config;
        auto vault_path = config.get_vault_path();

        if (!vault_handler::vault_exists(vault_path)) {
            std::cerr << "Error: Vault has not been initialized.\n"
                      << "Please run 'duckpass init' to create a new storage.\n";
            return;
        }

        // 1. Get password and decrypt vault
        duckpass::SecureString master_password = utils::get_password_silent("Enter master password to export: ");
        vault_handler::Vault vault;
        try {
            vault = vault_handler::load_vault(vault_path, master_password);
        } catch (const duckpass::wrong_password_error &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return;
        } catch (const duckpass::vault_corrupted_error &e) {
            std::cerr << "Critical Error: " << e.what() << std::endl;
            return;
        } catch (const duckpass::vault_io_error &e) {
            std::cerr << "I/O Error: " << e.what() << std::endl;
            return;
        } catch (const std::exception &e) {
            std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
            return;
        }

        if (vault.get_all_entries().empty()) {
            std::cout << "Info: Vault is empty. Nothing to export." << std::endl;
            return;
        }

        // 2. Open file for writing
        std::ofstream output_file(*output_path);
        if (!output_file) {
            std::cerr << "Error: Could not open file for writing: " << *output_path << std::endl;
            return;
        }

        // 3. Write data directly to stream
        if (*format == "csv") {
            write_csv(output_file, vault);
        } else if (*format == "json") {
            output_file << "[\n";
            const auto &entries = vault.get_all_entries();
            for (size_t i = 0; i < entries.size(); ++i) {
                const auto &entry = entries[i];
                output_file << "  {\n";
                output_file << "    \"service\": \"";
                output_file.write(entry.service.data(), entry.service.size());
                output_file << "\",\n";
                output_file << "    \"username\": \"";
                output_file.write(entry.username.data(), entry.username.size());
                output_file << "\",\n";
                output_file << "    \"password\": \"";
                output_file.write(entry.password.data(), entry.password.size());
                output_file << "\"\n";
                output_file << "  }";
                if (i < entries.size() - 1) output_file << ",";
                output_file << "\n";
            }
            output_file << "]";
        } else {
            std::cerr << "Error: Invalid format '" << *format << "'. Please use 'csv' or 'json'." << std::endl;
            output_file.close();
            return;
        }

        output_file.close();

        // 4. Print success and security warning
        std::cout << "Success: Vault has been exported to " << *output_path << std::endl;
        std::cout << "\n#################################################################" << std::endl;
        std::cout << "# WARNING: SECURITY RISK                                      #" << std::endl;
        std::cout << "# The file '" << output_path->filename().string() << "' IS NOT ENCRYPTED and contains all your #" << std::endl;
        std::cout << "# passwords in plain text.                                    #" << std::endl;
        std::cout << "# Please store it in a secure location and delete it when     #" << std::endl;
        std::cout << "# it is no longer needed.                                     #" << std::endl;
        std::cout << "#################################################################" << std::endl;
    });
}

void export_command::write_csv_field(std::ostream &os, const duckpass::SecureString &field) {
    os << "\"";
    for (char c : field) {
        if (c == '\"') {
            os << "\"\"";
        } else {
            os << c;
        }
    }
    os << "\"";
}

void export_command::write_csv(std::ostream &os, const vault_handler::Vault &vault) {
    os << "service,username,password\n";

    for (const auto &entry : vault.get_all_entries()) {
        write_csv_field(os, entry.service);
        os << ",";
        write_csv_field(os, entry.username);
        os << ",";
        write_csv_field(os, entry.password);
        os << "\n";
    }
}
