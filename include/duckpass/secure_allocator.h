#pragma once

#include <openssl/crypto.h>

#include <memory>
#include <string>
#include <vector>

namespace duckpass {

    template <typename T>
    struct secure_allocator {
        using value_type = T;

        secure_allocator() noexcept = default;

        template <typename U>
        explicit secure_allocator(const secure_allocator<U>&) noexcept {}

        T* allocate(const std::size_t& n) {
            if (n > static_cast<std::size_t>(-1) / sizeof(T)) throw std::bad_alloc();
            if (auto p = static_cast<T*>(std::malloc(n * sizeof(T)))) return p;
            throw std::bad_alloc();
        }

        static void deallocate(T* p, const std::size_t& n) noexcept {
            if (p) {
                OPENSSL_cleanse(p, n * sizeof(T));
                std::free(p);
            }
        }

        bool operator==(const secure_allocator&) const noexcept { return true; }
        bool operator!=(const secure_allocator&) const noexcept { return false; }
    };

    // Type aliases for easier usage
    using SecureString = std::basic_string<char, std::char_traits<char>, secure_allocator<char>>;

    template <typename T>
    using SecureVector = std::vector<T, secure_allocator<T>>;

    using SecureBytes = SecureVector<unsigned char>;

}  // namespace duckpass
