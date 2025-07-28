#pragma once

#include <string>
#include <filesystem>

// Declares our shared utility function.
std::string get_password_silent(const std::string &prompt);
std::filesystem::path get_config_directory();
