#include "duckpass/generate_command.h"

#include <iostream>
#include <string>

#include "CLI/CLI.hpp"
#include "duckpass/crypto.h"
#include "duckpass/secure_allocator.h"

void generate_command::setup(CLI::App &app) {
    const auto gen_cmd = app.add_subcommand("generate", "Generate a random password");

    auto length = std::make_shared<int>(16);
    gen_cmd->add_option("-l,--length", *length, "The desired password length")->default_val(16);

    gen_cmd->callback([length]() {
        try {
            const duckpass::SecureString password = crypto_handler::generate_password(*length);
            std::cout << "Generated Password: ";
            std::cout.write(password.data(), password.size());
            std::cout << std::endl;
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    });
}
