#pragma once

#include <string>
#include "nlohmann/json.hpp"

// Use a namespace for better organization
namespace command_handler {

    // Returns true if data was modified, false otherwise.
    bool handle_add(nlohmann::json& vault_data, const std::string& name, const std::string& username, const std::string& password);

    void handle_get(const nlohmann::json& vault_data, const std::string& name, bool copy_to_clipboard);

    void handle_list(const nlohmann::json& vault_data);

    // Returns true if data was modified, false otherwise.
    bool handle_delete(nlohmann::json& vault_data, const std::string& name);

    void handle_generate(int length);

} // namespace command_handler