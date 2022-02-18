#include "hash.h"

#include "blake2.h"

#include <spdlog/spdlog.h>

#include <vector>

namespace gpcache
{

auto hash_to_hex(const auto &hash) -> std::string
{
    static const char digits[] = "0123456789ABCDEF";

    const auto hash_size = hash.size();
    std::string result;
    result.resize(2 * hash_size);
    for (size_t i = 0; i < hash_size; ++i)
    {
        result[i * 2] = digits[hash[i] >> 4];
        result[i * 2 + 1] = digits[hash[i] & 0xF];
    }
    return result;
}

auto calculate_hash_of_str(const std::string_view string, const int digest_size) -> std::string
{
    if (digest_size < 1 || digest_size > 64)
        throw "invalid digest_size";

    std::vector<uint8_t> hash;
    hash.resize(digest_size);

    int x = blake2b(hash.data(), digest_size, string.data(), string.length(), nullptr, 0);
    if (x != 0)
    {
        spdlog::warn("Hash Error");
        spdlog::warn("digest_size: {}", digest_size);
        spdlog::warn("string: {}", string);
        spdlog::warn("string.length(): {}", string.length());
        throw "hash error";
    }

    return hash_to_hex(hash);
}

auto calculate_hash_of_file(const std::filesystem::path file, const int digest_size) -> std::string
{
    std::vector<uint8_t> hash;
    hash.resize(digest_size);

    blake2b_state state;
    blake2b_init(&state, digest_size);
    // iterate and call update for each read block?!
    blake2b_update(&state, file.c_str(), file.string().length());
    blake2b_final(&state, hash.data(), digest_size);

    return hash_to_hex(hash);
}

} // namespace gpcache
