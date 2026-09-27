#include "duckpass/protected_string.h"

#include <mutex>
#include <string_view>

#include "duckpass/crypto.h"

namespace duckpass {

    namespace {
        // Global Session Key residing in OpenSSL Secure Heap
        SecureBytes g_session_key;
        std::once_flag g_session_key_flag;
    }  // namespace

    void ProtectedString::ensure_session_key_initialized() {
        std::call_once(g_session_key_flag, []() {
            auto raw_key = crypto_handler::generate_random_bytes(crypto_handler::KEY_BYTES);
            g_session_key.assign(raw_key.begin(), raw_key.end());
            OPENSSL_cleanse(raw_key.data(), raw_key.size());
        });
    }

    void ProtectedString::initialize_session_key() { ensure_session_key_initialized(); }

    void ProtectedString::cleanse_session_key() {
        if (!g_session_key.empty()) {
            OPENSSL_cleanse(g_session_key.data(), g_session_key.size());
            g_session_key.clear();
        }
    }

    ProtectedString::ProtectedString() { ensure_session_key_initialized(); }

    ProtectedString::ProtectedString(const SecureString& plaintext) {
        ensure_session_key_initialized();
        if (plaintext.empty()) return;

        iv_ = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);

        const std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());

        ciphertext_ = crypto_handler::encrypt_data(pt_span, g_session_key, iv_);
    }

    ProtectedString::ProtectedString(const std::string_view plaintext) {
        ensure_session_key_initialized();
        if (plaintext.empty()) return;

        iv_ = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);

        const std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());

        ciphertext_ = crypto_handler::encrypt_data(pt_span, g_session_key, iv_);
    }

    SecureString ProtectedString::unprotect() const {
        if (ciphertext_.empty()) {
            return {};
        }

        const SecureBytes decrypted_bytes = crypto_handler::decrypt_data(ciphertext_, g_session_key, iv_);

        SecureString result;
        result.reserve(decrypted_bytes.size());
        result.assign(reinterpret_cast<const char*>(decrypted_bytes.data()), decrypted_bytes.size());

        // Zero out decrypted_bytes before freeing (though SecureBytes should do it automatically)
        return result;
    }

    bool ProtectedString::empty() const { return ciphertext_.empty(); }

}  // namespace duckpass
