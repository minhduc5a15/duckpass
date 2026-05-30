#pragma once

#include "nlohmann/json.hpp"
#include "duckpass/secure_allocator.h"

namespace duckpass {

    // We use a JSON type that uses our secure_allocator for all internal allocations.
    // We keep std::string as the StringType to avoid internal library conversion errors,
    // but we will store sensitive values (passwords) as Binary types (SecureBytes) 
    // to ensure they are wiped.
    
    using SecureJson = nlohmann::basic_json<
        std::map,
        std::vector,
        std::string,
        bool,
        std::int64_t,
        std::uint64_t,
        double,
        secure_allocator,
        nlohmann::adl_serializer,
        SecureBytes
    >;

} // namespace duckpass
