#pragma once

#include <openssl/crypto.h>

#include <cstring>
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

        static T* allocate(const std::size_t& n) {
            if (n > static_cast<std::size_t>(-1) / sizeof(T)) throw std::bad_alloc();
            void* p = OPENSSL_secure_malloc(n * sizeof(T));
            if (!p) {
                throw std::bad_alloc();
            }
            return static_cast<T*>(p);
        }

        static void deallocate(T* p, const std::size_t& n) noexcept {
            (void)n;
            if (p) {
                OPENSSL_secure_free(p);
            }
        }

        bool operator==(const secure_allocator&) const noexcept { return true; }
        bool operator!=(const secure_allocator&) const noexcept { return false; }
    };

    // Type aliases for easier usage
    // using SecureString = std::basic_string<char, std::char_traits<char>, secure_allocator<char>>;
    class SecureString {
    private:
        std::vector<char, secure_allocator<char>> m_buffer;

    public:
        using value_type = char;
        using size_type = std::size_t;

        SecureString() {
            m_buffer.push_back('\0');  // Ensure null-termination
        }
        explicit SecureString(const char* s) {
            if (s) {
                m_buffer.assign(s, s + std::strlen(s));
            }
            m_buffer.push_back('\0');  // Ensure null-termination
        }
        explicit SecureString(const char* s, std::size_t count) {
            if (s) {
                m_buffer.assign(s, s + count);
            }
            m_buffer.push_back('\0');  // Ensure null-termination
        }
        explicit SecureString(const std::size_t& count, const char& ch) : m_buffer(count, ch) {
            m_buffer.push_back('\0');  // Ensure null-termination
        }

        template <typename InputIt>
        SecureString(InputIt first, InputIt last) : m_buffer(first, last) {
            m_buffer.push_back('\0');  // Ensure null-termination
        }

        SecureString(const SecureString& other) = default;
        SecureString(SecureString&& other) noexcept = default;
        SecureString& operator=(const SecureString& other) {
            if (this != &other) {
                if (m_buffer.capacity() > 0) {
                    OPENSSL_cleanse(m_buffer.data(), m_buffer.capacity() * sizeof(char));
                }
                m_buffer = other.m_buffer;
            }
            return *this;
        }

        SecureString& operator=(const char* s) {
            if (s && s >= m_buffer.data() && s < m_buffer.data() + m_buffer.capacity()) {
                SecureString temp(s);
                return *this = std::move(temp);
            }
            if (m_buffer.capacity() > 0) {
                OPENSSL_cleanse(m_buffer.data(), m_buffer.capacity() * sizeof(char));
            }
            m_buffer.clear();
            if (s) {
                m_buffer.assign(s, s + std::strlen(s));
            }
            m_buffer.push_back('\0');
            return *this;
        }

        SecureString& operator=(SecureString&& other) noexcept {
            if (this != &other) {
                if (m_buffer.capacity() > 0) {
                    OPENSSL_cleanse(m_buffer.data(), m_buffer.capacity() * sizeof(char));
                }
                m_buffer = std::move(other.m_buffer);
            }
            return *this;
        }
        ~SecureString() = default;

        const char* c_str() const noexcept { return m_buffer.data(); }
        const char* data() const noexcept { return m_buffer.data(); }
        char* data() noexcept { return m_buffer.data(); }

        std::size_t size() const noexcept { return m_buffer.empty() ? 0 : m_buffer.size() - 1; }
        std::size_t length() const noexcept { return size(); }
        bool empty() const noexcept { return size() == 0; }

        char& operator[](std::size_t pos) { return m_buffer[pos]; }
        const char& operator[](std::size_t pos) const { return m_buffer[pos]; }

        char* begin() noexcept { return m_buffer.data(); }
        const char* begin() const noexcept { return m_buffer.data(); }
        char* end() noexcept { return m_buffer.data() + size(); }
        const char* end() const noexcept { return m_buffer.data() + size(); }

        void clear() noexcept {
            if (m_buffer.capacity() > 0) {
                OPENSSL_cleanse(m_buffer.data(), m_buffer.capacity() * sizeof(char));
            }
            m_buffer.clear();
            m_buffer.push_back('\0');  // Ensure null-termination
        }

        void reserve(std::size_t new_cap) { m_buffer.reserve(new_cap + 1); }

        void push_back(char ch) {
            if (!m_buffer.empty()) m_buffer.pop_back();
            m_buffer.push_back(ch);
            m_buffer.push_back('\0');
        }

        void pop_back() {
            if (!empty()) {
                m_buffer.pop_back();  // remove \0
                m_buffer.back() = 0;
                OPENSSL_cleanse(&m_buffer.back(), sizeof(char));
                m_buffer.pop_back();  // remove last char
                m_buffer.push_back('\0');
            }
        }

        template <typename InputIt>
        void assign(InputIt first, InputIt last) {
            if (first != last) {
                const char* f_ptr = reinterpret_cast<const char*>(&*first);
                if (f_ptr >= m_buffer.data() && f_ptr < m_buffer.data() + m_buffer.capacity()) {
                    SecureString temp(first, last);
                    *this = std::move(temp);
                    return;
                }
            }
            if (m_buffer.capacity() > 0) {
                OPENSSL_cleanse(m_buffer.data(), m_buffer.capacity() * sizeof(char));
            }
            m_buffer.assign(first, last);
            m_buffer.push_back('\0');
        }

        void assign(const char* s, std::size_t count) {
            if (s && s >= m_buffer.data() && s < m_buffer.data() + m_buffer.capacity()) {
                SecureString temp(s, count);
                *this = std::move(temp);
                return;
            }
            if (m_buffer.capacity() > 0) {
                OPENSSL_cleanse(m_buffer.data(), m_buffer.capacity() * sizeof(char));
            }
            m_buffer.assign(s, s + count);
            m_buffer.push_back('\0');
        }

        template <typename InputIt>
        void append(InputIt first, InputIt last) {
            if (first != last) {
                const char* f_ptr = reinterpret_cast<const char*>(&*first);
                if (f_ptr >= m_buffer.data() && f_ptr < m_buffer.data() + m_buffer.capacity()) {
                    SecureString temp(first, last);
                    append(temp.begin(), temp.begin() + temp.size());
                    return;
                }
            }
            if (!m_buffer.empty()) m_buffer.pop_back();
            m_buffer.insert(m_buffer.end(), first, last);
            m_buffer.push_back('\0');
        }

        void append(const char* s) {
            if (s) {
                if (s >= m_buffer.data() && s < m_buffer.data() + m_buffer.capacity()) {
                    SecureString temp(s);
                    append(temp.begin(), temp.end());
                    return;
                }
                append(s, s + std::strlen(s));
            }
        }

        void erase(char* first, char* last) {
            if (first < m_buffer.data() || last > m_buffer.data() + m_buffer.size()) return;
            m_buffer.erase(m_buffer.begin() + (first - m_buffer.data()), m_buffer.begin() + (last - m_buffer.data()));
            if (m_buffer.empty() || m_buffer.back() != '\0') {
                m_buffer.push_back('\0');
            }
            const std::size_t unused_capacity = m_buffer.capacity() - m_buffer.size();
            if (unused_capacity > 0) {
                OPENSSL_cleanse(m_buffer.data() + m_buffer.size(), unused_capacity * sizeof(char));
            }
        }

        void erase(const char* first, const char* last) { erase(const_cast<char*>(first), const_cast<char*>(last)); }

        SecureString& operator+=(const SecureString& other) {
            if (this == &other) {
                // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
                const SecureString temp(other);
                return *this += temp;
            }

            if (!m_buffer.empty()) m_buffer.pop_back();
            m_buffer.insert(m_buffer.end(), other.begin(), other.end());
            m_buffer.push_back('\0');
            return *this;
        }

        SecureString& operator+=(const char* s) {
            if (s) {
                const std::size_t len = std::strlen(s);
                if (len == 0) return *this;

                if (s >= m_buffer.data() && s < m_buffer.data() + m_buffer.size()) {
                    const SecureString temp(s, len);
                    return *this += temp;
                }

                if (!m_buffer.empty()) m_buffer.pop_back();
                m_buffer.insert(m_buffer.end(), s, s + len);
                m_buffer.push_back('\0');
            }
            return *this;
        }

        SecureString& operator+=(char ch) {
            push_back(ch);
            return *this;
        }

        bool operator==(const SecureString& other) const noexcept {
            if (size() != other.size()) return false;
            return CRYPTO_memcmp(c_str(), other.c_str(), size()) == 0;
        }

        bool operator!=(const SecureString& other) const noexcept { return !(*this == other); }

        auto rbegin() noexcept { return std::reverse_iterator<char*>(end()); }
        auto rbegin() const noexcept { return std::reverse_iterator<const char*>(end()); }
        auto rend() noexcept { return std::reverse_iterator<char*>(begin()); }
        auto rend() const noexcept { return std::reverse_iterator<const char*>(begin()); }
    };

    template <typename T>
    using SecureVector = std::vector<T, secure_allocator<T>>;

    using SecureBytes = SecureVector<unsigned char>;

}  // namespace duckpass
