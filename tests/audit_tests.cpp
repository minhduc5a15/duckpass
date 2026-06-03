#include "duckpass/crypto.h"
#include "duckpass/entropy_evaluator.h"
#include "duckpass/audit_engine.h"
#include "duckpass/vault.h"
#include "zxcvbn.h"

#include <iostream>
#include <cassert>
#include <vector>
#include <ctime>

void test_hashing() {
    std::cout << "Running test_hashing..." << std::endl;
    duckpass::SecureString password("password123");
    
    std::string sha1 = crypto_handler::compute_sha1(password);
    if (sha1 != "CBFDAC6008F9CAB4083784CBD1874F76618D2A97") {
        std::cerr << "SHA1 mismatch: " << sha1 << std::endl;
    }
    assert(sha1 == "CBFDAC6008F9CAB4083784CBD1874F76618D2A97");

    std::string sha256 = crypto_handler::compute_sha256(password);
    if (sha256 != "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f") {
        std::cerr << "SHA256 mismatch: " << sha256 << std::endl;
    }
    assert(sha256 == "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f");
    
    std::cout << "test_hashing passed!" << std::endl;
}

void test_entropy() {
    std::cout << "Running test_entropy..." << std::endl;
    
    auto score_weak = audit::EntropyEvaluator::evaluate(duckpass::SecureString("123"));
    assert(score_weak.score < 3);
    assert(score_weak.is_weak == true);

    auto score_strong = audit::EntropyEvaluator::evaluate(duckpass::SecureString("CorrectHorseBatteryStaple123!"));
    assert(score_strong.score >= 0);
    
    std::cout << "test_entropy passed!" << std::endl;
}

void test_audit_engine() {
    std::cout << "Running test_audit_engine..." << std::endl;
    vault_handler::Vault vault;
    
    vault_handler::VaultEntry e1;
    e1.service = duckpass::SecureString("service1");
    e1.username = duckpass::SecureString("user1");
    e1.password = duckpass::SecureString("pass123");
    e1.last_updated = 100; // Very old
    
    vault_handler::VaultEntry e2;
    e2.service = duckpass::SecureString("service2");
    e2.username = duckpass::SecureString("user2");
    e2.password = duckpass::SecureString("pass123"); // Reused!
    e2.last_updated = static_cast<uint64_t>(std::time(nullptr));
    
    vault.add_entry(e1);
    vault.add_entry(e2);
    
    audit::AuditEngine::Config config;
    config.check_online = false;
    config.stale_threshold_seconds = 3600; // 1 hour
    
    auto report = audit::AuditEngine::run_audit(vault, config);
    
    assert(report.total_entries == 2);
    assert(report.reused_passwords == 1);
    assert(report.entries[0].is_reused == true);
    assert(report.entries[1].is_reused == true);
    assert(report.stale_passwords == 1);
    assert(report.entries[0].is_stale == true);
    assert(report.entries[1].is_stale == false);
    
    std::cout << "test_audit_engine passed!" << std::endl;
}

void test_vault_compatibility() {
    std::cout << "Running test_vault_compatibility..." << std::endl;
    
    std::vector<uint8_t> old_vault_data;
    auto add_uint32 = [&](uint32_t v) {
        old_vault_data.push_back(v & 0xFF);
        old_vault_data.push_back((v >> 8) & 0xFF);
        old_vault_data.push_back((v >> 16) & 0xFF);
        old_vault_data.push_back((v >> 24) & 0xFF);
    };
    auto add_string = [&](const std::string& s) {
        add_uint32(static_cast<uint32_t>(s.length()));
        for (char c : s) old_vault_data.push_back(static_cast<uint8_t>(c));
    };

    add_uint32(1); 
    add_string("old_service");
    add_string("old_user");
    add_string("old_pass");

    auto vault = vault_handler::Vault::deserialize(old_vault_data);
    
    assert(vault.get_all_entries().size() == 1);
    auto entry = vault.get_entry(duckpass::SecureString("old_service"));
    assert(entry.has_value());
    assert(entry->username == duckpass::SecureString("old_user"));
    assert(entry->password == duckpass::SecureString("old_pass"));
    assert(entry->last_updated > 0); // Vault::add_entry sets it to now if 0

    std::cout << "test_vault_compatibility passed!" << std::endl;
}

int main() {
    try {
        if (!ZxcvbnInit("zxcvbn.dict")) {
            std::cerr << "Warning: Could not initialize zxcvbn.dict. Tests will run with limited entropy evaluation." << std::endl;
        }
        test_hashing();
        test_entropy();
        test_audit_engine();
        test_vault_compatibility();
        ZxcvbnUnInit();
        std::cout << "\nALL TESTS PASSED!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED with exception: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
