#include "duckpass/hibp_checker.h"
#include "duckpass/crypto.h"
#include <curl/curl.h>
#include <algorithm>
#include <string_view>
#include <chrono>
#include <thread>

namespace audit {

    size_t HibpChecker::write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    HibpResult HibpChecker::check_password(const SecureString& password) {
        HibpResult result{false, 0, ""};
        
        std::string sha1 = crypto_handler::compute_sha1(password);
        if (sha1.length() < 5) {
            result.error_message = "Invalid SHA-1 hash.";
            return result;
        }

        std::string_view sha1_view(sha1);
        std::string_view prefix = sha1_view.substr(0, 5);
        std::string_view suffix = sha1_view.substr(5);

        CURL* curl = curl_easy_init();
        if (!curl) {
            result.error_message = "Failed to initialize CURL.";
            return result;
        }

        std::string url = "https://api.pwnedpasswords.com/range/";
        url.append(prefix);

        int retry_count = 0;
        const int max_retries = 3;

        while (retry_count <= max_retries) {
            std::string response_data;

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "duckpass/1.0");
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                result.error_message = "CURL request failed: " + std::string(curl_easy_strerror(res));
                break;
            }

            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code == 429) { // Rate Limit
                retry_count++;
                if (retry_count > max_retries) {
                    result.error_message = "HIBP Rate Limit Exceeded after retries.";
                    break;
                }
                // Exponential backoff: 2s, 4s, 8s
                std::this_thread::sleep_for(std::chrono::seconds(1 << retry_count));
                continue; 
            }

            if (response_code != 200) {
                result.error_message = "API returned error code: " + std::to_string(response_code);
                break;
            }

            // ZERO-ALLOCATION PARSING using string_view
            std::string_view buffer(response_data);
            size_t pos = 0;
            while (pos < buffer.size()) {
                // Find end of line (\r or \n) using find_first_of for robustness
                size_t line_end = buffer.find_first_of("\r\n", pos);
                if (line_end == std::string_view::npos) {
                    line_end = buffer.size();
                }

                std::string_view line = buffer.substr(pos, line_end - pos);
                if (!line.empty()) {
                    size_t colon_pos = line.find(':');
                    if (colon_pos != std::string_view::npos) {
                        std::string_view res_suffix = line.substr(0, colon_pos);
                        if (res_suffix == suffix) {
                            result.is_pwned = true;
                            std::string_view count_str = line.substr(colon_pos + 1);
                            
                            // Parse count manually to avoid creating std::string
                            result.breach_count = 0;
                            for (char c : count_str) {
                                if (c >= '0' && c <= '9') {
                                    result.breach_count = result.breach_count * 10 + (c - '0');
                                } else if (c == '\r' || c == '\n') {
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }

                // Advance to next line
                pos = line_end;
                while (pos < buffer.size() && (buffer[pos] == '\r' || buffer[pos] == '\n')) {
                    pos++;
                }
            }
            break; // Success or non-retryable error
        }

        curl_easy_cleanup(curl);
        return result;
    }

}  // namespace audit
