#include "duckpass/otp_command.h"

#include <chrono>
#include <iostream>

#include "duckpass/clipboard_handler.h"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/ipc.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/vault_service.h"

namespace otp_command {

    void setup(CLI::App& app) {
        const auto otp_cmd = app.add_subcommand("otp", "Generate 2FA One-Time Password for a service");

        auto service_name = std::make_shared<std::string>();
        auto copy_to_clipboard = std::make_shared<bool>(false);

        otp_cmd->add_option("service", *service_name, "Name of the service to generate OTP for")->required();
        otp_cmd->add_flag("-c,--copy", *copy_to_clipboard, "Copy OTP to clipboard instead of just printing");

        otp_cmd->callback([service_name, copy_to_clipboard]() {
            const duckpass::SecureString s_name(service_name->begin(), service_name->end());

            // 1. Try DuckPass Agent if active
            duckpass::ipc::IpcClient client;
            if (client.is_agent_available()) {
                auto status = client.get_status();
                if (status && !status->is_unlocked) {
                    const duckpass::SecureString master_password = terminal_utils::read_password("Agent is locked. Enter master password: ");
                    std::string unlock_err;
                    if (!client.unlock(master_password, unlock_err)) {
                        std::cerr << "Error: " << unlock_err << std::endl;
                        return;
                    }
                }

                std::string err;
                auto res = client.get_totp(s_name, err);
                if (!res) {
                    std::cerr << "Error: " << err << std::endl;
                    return;
                }

                std::cout << "2FA Code for '" << *service_name << "': \033[1;32m" << res->code << "\033[0m" << " (expires in "
                          << res->remaining_seconds << "s)\n";

                if (*copy_to_clipboard) {
                    duckpass::SecureString code_sec(res->code.c_str());
                    if (clipboard_handler::set_text(code_sec)) {
                        std::cout << "[✓] 2FA code copied to clipboard (will be cleared in 15s).\n";
                        clipboard_handler::clear_after_delay(std::chrono::seconds(15));
                    } else {
                        std::cerr << "[!] Could not copy to clipboard.\n";
                    }
                }
                return;
            }

            // 2. Standalone fallback
            const config_handler config;
            const auto vault_path = config.get_vault_path();

            if (!vault_handler::vault_exists(vault_path)) {
                std::cerr << "Error: Vault has not been initialized.\n"
                          << "Please run 'duckpass init' to create a new storage.\n";
                return;
            }

            const duckpass::SecureString master_password = terminal_utils::read_password("Enter master password: ");

            try {
                const duckpass::service::VaultService vault_service(vault_path, master_password);
                const duckpass::SecureString s_name(service_name->begin(), service_name->end());

                uint32_t remaining = 0;
                std::string code = vault_service.get_totp_code(s_name, &remaining);

                std::cout << "2FA Code for '" << *service_name << "': \033[1;32m" << code << "\033[0m" << " (expires in " << remaining << "s)\n";

                if (*copy_to_clipboard) {
                    duckpass::SecureString code_sec(code.c_str());
                    if (clipboard_handler::set_text(code_sec)) {
                        std::cout << "[✓] 2FA code copied to clipboard (will be cleared in 15s).\n";
                        clipboard_handler::clear_after_delay(std::chrono::seconds(15));
                    } else {
                        std::cerr << "[!] Could not copy to clipboard.\n";
                    }
                }
            } catch (const duckpass::wrong_password_error& e) {
                std::cerr << "Error: " << e.what() << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
            }
        });
    }

}  // namespace otp_command
