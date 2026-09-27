#include <curl/curl.h>
#include <gtest/gtest.h>
#include <openssl/crypto.h>

#include <iostream>

class DuckpassTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        // Initialize OpenSSL Secure Heap (1MB) matching main.cpp
        if (CRYPTO_secure_malloc_init(1048576, 32) != 1) {
            std::cerr << "[Warning] CRYPTO_secure_malloc_init returned non-1 in test environment.\n";
        }
        curl_global_init(CURL_GLOBAL_ALL);
    }

    void TearDown() override { curl_global_cleanup(); }
};

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new DuckpassTestEnvironment);
    return RUN_ALL_TESTS();
}
