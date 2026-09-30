#include "duckpass/entropy_evaluator.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bit>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <vector>

namespace audit {

    class SigpipeBlocker {
    public:
        SigpipeBlocker() {
            sigset_t pending;
            sigpending(&pending);
            was_pending_before_ = (sigismember(&pending, SIGPIPE) == 1);

            sigset_t set;
            sigemptyset(&set);
            sigaddset(&set, SIGPIPE);
            if (pthread_sigmask(SIG_BLOCK, &set, &old_set_) == 0) {
                blocked_ = true;
            }
        }

        ~SigpipeBlocker() {
            if (!blocked_) return;

            // Consume SIGPIPE if it was newly generated during our scope
            if (!was_pending_before_) {
                sigset_t pending_now;
                sigpending(&pending_now);
                if (sigismember(&pending_now, SIGPIPE) == 1) {
                    sigset_t sigpipe_set;
                    sigemptyset(&sigpipe_set);
                    sigaddset(&sigpipe_set, SIGPIPE);
                    struct timespec timeout {
                        0, 0
                    };
                    sigtimedwait(&sigpipe_set, nullptr, &timeout);
                }
            }

            pthread_sigmask(SIG_SETMASK, &old_set_, nullptr);
        }

    private:
        sigset_t old_set_{};
        bool blocked_{false};
        bool was_pending_before_{false};
    };

    namespace {

        std::filesystem::path resolve_worker_binary() {
            std::error_code ec;
#if defined(__linux__)
            auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
            if (!ec) {
                auto candidate = self.parent_path() / "duckpass-entropy-worker";
                if (std::filesystem::exists(candidate)) {
                    return candidate;
                }
            }
#endif
            if (std::filesystem::exists("build/duckpass-entropy-worker")) {
                return "build/duckpass-entropy-worker";
            }
            if (std::filesystem::exists("./duckpass-entropy-worker")) {
                return "./duckpass-entropy-worker";
            }
            if (std::filesystem::exists("/usr/local/bin/duckpass-entropy-worker")) {
                return "/usr/local/bin/duckpass-entropy-worker";
            }
            if (std::filesystem::exists("/usr/bin/duckpass-entropy-worker")) {
                return "/usr/bin/duckpass-entropy-worker";
            }
            return "duckpass-entropy-worker";
        }

        void set_nonblocking(int fd) {
            int const flags = fcntl(fd, F_GETFL, 0);
            if (flags != -1) {
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            }
        }

        struct PipeCloser {
            int in_fd = -1;
            int out_fd = -1;

            ~PipeCloser() {
                if (in_fd != -1) close(in_fd);
                if (out_fd != -1) close(out_fd);
            }
        };

    }  // namespace

    EntropyScore EntropyEvaluator::evaluate(const SecureString& password) {
        if (password.empty()) {
            return {0, 0.0, 0.0, true};
        }

        std::filesystem::path const worker_path = resolve_worker_binary();

        int in_pipe[2];
        if (pipe(in_pipe) != 0) {
            throw std::runtime_error("Failed to create input pipe for entropy worker");
        }

        int out_pipe[2];
        if (pipe(out_pipe) != 0) {
            close(in_pipe[0]);
            close(in_pipe[1]);
            throw std::runtime_error("Failed to create output pipe for entropy worker");
        }

        pid_t const pid = fork();
        if (pid < 0) {
            close(in_pipe[0]);
            close(in_pipe[1]);
            close(out_pipe[0]);
            close(out_pipe[1]);
            throw std::runtime_error("Failed to fork entropy evaluator worker process");
        }

        if (pid == 0) {
            // Child process: Map pipes to STDIN and STDOUT
            close(in_pipe[1]);
            close(out_pipe[0]);

            if (dup2(in_pipe[0], STDIN_FILENO) == -1 || dup2(out_pipe[1], STDOUT_FILENO) == -1) {
                _exit(126);
            }

            close(in_pipe[0]);
            close(out_pipe[1]);

            execl(worker_path.c_str(), worker_path.c_str(), nullptr);
            _exit(127);
        }

        // Parent process
        close(in_pipe[0]);
        close(out_pipe[1]);

        PipeCloser closer{in_pipe[1], out_pipe[0]};

        set_nonblocking(in_pipe[1]);
        set_nonblocking(out_pipe[0]);

        SigpipeBlocker const sigpipe_guard;

        // Prepare write buffer: [4 bytes len LE] + [password bytes]
        auto const pwd_len = static_cast<uint32_t>(password.size());
        std::vector<uint8_t> write_buf(4 + pwd_len);
        write_buf[0] = static_cast<uint8_t>(pwd_len & 0xFF);
        write_buf[1] = static_cast<uint8_t>((pwd_len >> 8) & 0xFF);
        write_buf[2] = static_cast<uint8_t>((pwd_len >> 16) & 0xFF);
        write_buf[3] = static_cast<uint8_t>((pwd_len >> 24) & 0xFF);
        std::memcpy(write_buf.data() + 4, password.data(), pwd_len);

        size_t write_offset = 0;
        std::vector<uint8_t> read_buf(21, 0);
        size_t read_offset = 0;
        bool in_pipe_closed = false;

        auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);

        while (read_offset < 21) {
            auto const now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                kill(pid, SIGKILL);
                waitpid(pid, nullptr, 0);
                throw std::runtime_error("Entropy evaluator worker execution timed out (overall 5s deadline)");
            }

            auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            if (remaining_ms < 1) remaining_ms = 1;

            pollfd fds[2]{};
            int nfds = 0;

            int in_idx = -1;
            if (!in_pipe_closed && closer.in_fd != -1) {
                in_idx = nfds++;
                fds[in_idx].fd = closer.in_fd;
                fds[in_idx].events = POLLOUT;
                fds[in_idx].revents = 0;
            }

            int const out_idx = nfds++;
            fds[out_idx].fd = closer.out_fd;
            fds[out_idx].events = POLLIN | POLLHUP;
            fds[out_idx].revents = 0;

            int const poll_res = poll(fds, nfds, static_cast<int>(remaining_ms));
            if (poll_res < 0) {
                if (errno == EINTR) continue;
                kill(pid, SIGKILL);
                waitpid(pid, nullptr, 0);
                throw std::runtime_error("poll() failed on entropy worker pipes");
            }
            if (poll_res == 0) {
                kill(pid, SIGKILL);
                waitpid(pid, nullptr, 0);
                throw std::runtime_error("Entropy evaluator worker execution timed out (overall 5s deadline)");
            }

            // Check write channel
            if (in_idx != -1 && (fds[in_idx].revents & (POLLOUT | POLLERR | POLLHUP))) {
                if (fds[in_idx].revents & POLLOUT) {
                    ssize_t const w = write(closer.in_fd, write_buf.data() + write_offset, write_buf.size() - write_offset);
                    if (w > 0) {
                        write_offset += w;
                        if (write_offset >= write_buf.size()) {
                            close(closer.in_fd);
                            closer.in_fd = -1;
                            in_pipe_closed = true;
                        }
                    } else if (w < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                        close(closer.in_fd);
                        closer.in_fd = -1;
                        in_pipe_closed = true;
                    }
                } else {
                    close(closer.in_fd);
                    closer.in_fd = -1;
                    in_pipe_closed = true;
                }
            }

            // Check read channel
            if (fds[out_idx].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t const r = read(closer.out_fd, read_buf.data() + read_offset, 21 - read_offset);
                if (r > 0) {
                    read_offset += r;
                } else if (r == 0) {
                    break;  // EOF
                } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    break;
                }
            }
        }

        // Close write pipe if still open
        if (closer.in_fd != -1) {
            close(closer.in_fd);
            closer.in_fd = -1;
        }

        // Wait for child process exit within the remaining overall deadline
        int status = 0;
        bool exited = false;
        while (std::chrono::steady_clock::now() < deadline) {
            pid_t const wr = waitpid(pid, &status, WNOHANG);
            if (wr == pid) {
                exited = true;
                break;
            }
            if (wr < 0 && errno != EINTR) {
                break;
            }
            usleep(1000);
        }

        if (!exited) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            throw std::runtime_error("Entropy evaluator worker execution timed out waiting for process termination");
        }

        if (read_offset != 21 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("Entropy evaluator worker execution failed or returned invalid response");
        }

        // Deserialize Canonical Wire Protocol (21 bytes):
        // [0..3]: int32_t score (LE)
        uint32_t const u_score = static_cast<uint32_t>(read_buf[0]) | (static_cast<uint32_t>(read_buf[1]) << 8) |
                                 (static_cast<uint32_t>(read_buf[2]) << 16) | (static_cast<uint32_t>(read_buf[3]) << 24);
        int32_t const score = static_cast<int32_t>(u_score);

        // [4..11]: double entropy_bits (std::bit_cast<uint64_t> LE)
        uint64_t entropy_u64 = 0;
        for (int i = 0; i < 8; ++i) {
            entropy_u64 |= static_cast<uint64_t>(read_buf[4 + i]) << (i * 8);
        }
        double const entropy = std::bit_cast<double>(entropy_u64);

        // [12..19]: double crack_time_seconds (std::bit_cast<uint64_t> LE)
        uint64_t crack_u64 = 0;
        for (int i = 0; i < 8; ++i) {
            crack_u64 |= static_cast<uint64_t>(read_buf[12 + i]) << (i * 8);
        }
        double const crack_time_seconds = std::bit_cast<double>(crack_u64);

        // [20]: uint8_t is_weak
        bool const is_weak = (read_buf[20] != 0);

        return {score, entropy, crack_time_seconds, is_weak};
    }

}  // namespace audit
