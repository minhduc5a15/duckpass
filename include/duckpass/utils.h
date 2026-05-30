#pragma once

#include <string>
#include <filesystem>
#include "duckpass/secure_allocator.h"

// Declares our shared utility function.
duckpass::SecureString get_password_silent(const std::string &prompt);
std::filesystem::path get_config_directory();
