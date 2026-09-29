#include "duckpass/ipc.h"

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <future>
#include <thread>
#include <vector>

#include "duckpass/agent_server.h"

class IpcTest : public ::testing::Test {
protected:
    std::filesystem::path test_sock;

    void SetUp() override {
        test_sock = std::filesystem::temp_directory_path() /
                    ("duckpass_ipc_test_" + std::to_string(std::time(nullptr)) + "_" + std::to_string(rand()) + ".sock");
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove(test_sock, ec);
    }
};

TEST_F(IpcTest, PacketSerializationAndFraming) {
    std::vector<uint8_t> payload = {'T', 'E', 'S', 'T', '1', '2', '3'};
    auto packet = duckpass::ipc::serialize_packet(static_cast<uint8_t>(duckpass::ipc::CommandOpcode::PING), payload);

    // 4 bytes length + 1 byte opcode + 7 bytes payload = 12 bytes
    ASSERT_EQ(packet.size(), 12);
    EXPECT_EQ(packet[4], static_cast<uint8_t>(duckpass::ipc::CommandOpcode::PING));

    uint32_t len = 0;
    std::memcpy(&len, packet.data(), 4);
    EXPECT_EQ(ntohl(len), 7);
}

TEST_F(IpcTest, SocketPathResolution) {
    auto path = duckpass::ipc::get_socket_path();
    EXPECT_FALSE(path.empty());
    EXPECT_TRUE(path.is_absolute());
}

TEST_F(IpcTest, ClientServerPingAndStatusLifecycle) {
    // 1. Client fails to connect when server is not running
    duckpass::ipc::IpcClient client(test_sock);
    EXPECT_FALSE(client.is_agent_available());
    EXPECT_FALSE(client.ping());

    // 2. Launch AgentServer in background thread
    auto server = std::make_shared<duckpass::ipc::AgentServer>(test_sock, 10);
    std::thread server_thread([server]() { server->run(); });

    // Wait up to 1 second for socket to be ready
    bool ready = false;
    for (int i = 0; i < 20; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (client.is_agent_available()) {
            ready = true;
            break;
        }
    }
    ASSERT_TRUE(ready);

    // 3. Ping succeeds
    EXPECT_TRUE(client.ping());

    // 4. Query status (locked initially)
    auto status = client.get_status();
    ASSERT_TRUE(status.has_value());
    EXPECT_FALSE(status->is_unlocked);
    EXPECT_EQ(status->total_entries, 0);

    // 5. Lock command succeeds on locked vault
    EXPECT_TRUE(client.lock());

    // 6. Stop agent
    EXPECT_TRUE(client.stop_agent());

    if (server_thread.joinable()) {
        server_thread.join();
    }

    // 7. Verify agent stopped
    EXPECT_FALSE(client.is_agent_available());
}

TEST_F(IpcTest, StalledClientTimeoutDoesNotBlockOthers) {
    auto server = std::make_shared<duckpass::ipc::AgentServer>(test_sock, 10);
    std::thread server_thread([server]() { server->run(); });

    duckpass::ipc::IpcClient client(test_sock);
    for (int i = 0; i < 20; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (client.is_agent_available()) break;
    }
    ASSERT_TRUE(client.is_agent_available());

    // Connect a stalled client that sends 1 byte and stops
    int bad_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, test_sock.c_str(), sizeof(addr.sun_path) - 1);
    ASSERT_GE(connect(bad_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    char byte = 0x42;
    ASSERT_EQ(write(bad_fd, &byte, 1), 1);

    // Another client should not be blocked indefinitely (wait_for 750ms)
    auto future = std::async(std::launch::async, [this]() {
        duckpass::ipc::IpcClient c(test_sock);
        return c.ping();
    });

    ASSERT_EQ(future.wait_for(std::chrono::milliseconds(750)), std::future_status::ready);
    EXPECT_TRUE(future.get());

    close(bad_fd);
    EXPECT_TRUE(client.stop_agent());
    if (server_thread.joinable()) server_thread.join();
}

TEST_F(IpcTest, ConcurrentClientsStress) {
    auto server = std::make_shared<duckpass::ipc::AgentServer>(test_sock, 10);
    std::thread server_thread([server]() { server->run(); });

    duckpass::ipc::IpcClient client(test_sock);
    for (int i = 0; i < 20; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (client.is_agent_available()) break;
    }
    ASSERT_TRUE(client.is_agent_available());

    constexpr int kNumThreads = 8;
    constexpr int kRequestsPerThread = 15;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < kNumThreads; ++i) {
        threads.emplace_back([this, &success_count]() {
            duckpass::ipc::IpcClient c(test_sock);
            for (int j = 0; j < kRequestsPerThread; ++j) {
                if (c.ping()) {
                    auto st = c.get_status();
                    if (st.has_value()) {
                        success_count++;
                    }
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(success_count.load(), kNumThreads * kRequestsPerThread);

    EXPECT_TRUE(client.stop_agent());
    if (server_thread.joinable()) server_thread.join();
}

TEST_F(IpcTest, FuzzAndMalformedPackets) {
    auto server = std::make_shared<duckpass::ipc::AgentServer>(test_sock, 10);
    std::thread server_thread([server]() { server->run(); });

    duckpass::ipc::IpcClient client(test_sock);
    for (int i = 0; i < 20; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (client.is_agent_available()) break;
    }
    ASSERT_TRUE(client.is_agent_available());

    auto send_raw = [this](const void* data, size_t size) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, test_sock.c_str(), sizeof(addr.sun_path) - 1);
        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            write(fd, data, size);
        }
        close(fd);
    };

    // 1. Oversized payload length (> 10MB sanity check)
    uint32_t huge_len = htonl(50 * 1024 * 1024);
    send_raw(&huge_len, 4);

    // 2. Partial 2-byte header
    uint16_t partial = 0x1234;
    send_raw(&partial, 2);

    // 3. Invalid opcode with zero payload
    uint8_t invalid_op_packet[] = {0x00, 0x00, 0x00, 0x00, 0xFF};
    send_raw(invalid_op_packet, sizeof(invalid_op_packet));

    // 4. Integer overflow attempt in string extraction (len = 0xFFFFFFFF)
    uint8_t malformed_extract[] = {0x00, 0x00, 0x00, 0x08, static_cast<uint8_t>(duckpass::ipc::CommandOpcode::GET_ENTRY), 0xFF, 0xFF, 0xFF, 0xFF,
                                   0xAA, 0xBB, 0xCC, 0xDD};
    send_raw(malformed_extract, sizeof(malformed_extract));

    // 5. Verify server is still alive and responsive after malicious inputs
    EXPECT_TRUE(client.ping());
    EXPECT_TRUE(client.stop_agent());
    if (server_thread.joinable()) server_thread.join();
}

TEST_F(IpcTest, UnknownOpcodeReturnsErrorPacket) {
    auto server = std::make_shared<duckpass::ipc::AgentServer>(test_sock, 10);
    std::thread server_thread([server]() { server->run(); });

    duckpass::ipc::IpcClient client(test_sock);
    for (int i = 0; i < 20; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (client.is_agent_available()) break;
    }
    ASSERT_TRUE(client.is_agent_available());

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, test_sock.c_str(), sizeof(addr.sun_path) - 1);
    ASSERT_EQ(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    uint8_t packet[] = {0x00, 0x00, 0x00, 0x00, 0xEE};
    ASSERT_EQ(write(fd, packet, sizeof(packet)), sizeof(packet));

    uint8_t resp_opcode = 0;
    std::vector<uint8_t> resp_payload;
    ASSERT_TRUE(duckpass::ipc::read_packet(fd, resp_opcode, resp_payload));
    close(fd);

    EXPECT_EQ(resp_opcode, static_cast<uint8_t>(duckpass::ipc::ResponseStatus::ERROR));

    EXPECT_TRUE(client.ping());
    EXPECT_TRUE(client.stop_agent());
    if (server_thread.joinable()) server_thread.join();
}
