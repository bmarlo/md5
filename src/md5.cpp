#include "marlo/md5.hpp"
#include <array>

namespace marlo {

md5::md5() : _state{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}, _msglen(0)
{
    _hash.reserve(md5::hash_size + md5::block_size);
    _hash.resize(md5::hash_size);
}

md5& md5::reset() noexcept
{
    _state[0] = 0x67452301;
    _state[1] = 0xefcdab89;
    _state[2] = 0x98badcfe;
    _state[3] = 0x10325476;
    _msglen = 0;
    _hash.resize(md5::hash_size);
    return *this;
}

constexpr std::array<std::uint32_t, 64> magic_table = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

template<typename fn_t>
void round_impl(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, fn_t what, std::uint32_t x, std::uint8_t s, std::uint8_t t)
{
    auto rotl = [](std::uint32_t val, std::uint8_t shifts) {
        return (val << shifts) | (val >> (32 - shifts));
    };

    a = b + rotl((a + what(b, c, d) + x + magic_table[t]), s);
}

template<typename fn_t>
void hash_impl(std::uint32_t state[4], std::size_t blocks, fn_t get_data)
{
    auto alice = [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) | (~x & z);
    };

    auto bob = [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & z) | (y & ~z);
    };

    auto dave = [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return x ^ y ^ z;
    };

    auto eve = [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return y ^ (x | ~z);
    };

    while (blocks--) {
        std::array<std::uint32_t, 16> words;
        get_data(words);
        std::uint32_t tmp[4] = {
            state[0], state[1], state[2], state[3]
        };

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], alice, words[0], 7, 0);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], alice, words[1], 12, 1);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], alice, words[2], 17, 2);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], alice, words[3], 22, 3);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], alice, words[4], 7, 4);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], alice, words[5], 12, 5);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], alice, words[6], 17, 6);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], alice, words[7], 22, 7);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], alice, words[8], 7, 8);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], alice, words[9], 12, 9);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], alice, words[10], 17, 10);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], alice, words[11], 22, 11);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], alice, words[12], 7, 12);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], alice, words[13], 12, 13);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], alice, words[14], 17, 14);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], alice, words[15], 22, 15);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], bob, words[1], 5, 16);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], bob, words[6], 9, 17);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], bob, words[11], 14, 18);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], bob, words[0], 20, 19);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], bob, words[5], 5, 20);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], bob, words[10], 9, 21);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], bob, words[15], 14, 22);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], bob, words[4], 20, 23);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], bob, words[9], 5, 24);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], bob, words[14], 9, 25);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], bob, words[3], 14, 26);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], bob, words[8], 20, 27);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], bob, words[13], 5, 28);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], bob, words[2], 9, 29);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], bob, words[7], 14, 30);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], bob, words[12], 20, 31);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], dave, words[5], 4, 32);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], dave, words[8], 11, 33);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], dave, words[11], 16, 34);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], dave, words[14], 23, 35);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], dave, words[1], 4, 36);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], dave, words[4], 11, 37);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], dave, words[7], 16, 38);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], dave, words[10], 23, 39);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], dave, words[13], 4, 40);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], dave, words[0], 11, 41);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], dave, words[3], 16, 42);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], dave, words[6], 23, 43);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], dave, words[9], 4, 44);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], dave, words[12], 11, 45);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], dave, words[15], 16, 46);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], dave, words[2], 23, 47);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], eve, words[0], 6, 48);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], eve, words[7], 10, 49);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], eve, words[14], 15, 50);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], eve, words[5], 21, 51);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], eve, words[12], 6, 52);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], eve, words[3], 10, 53);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], eve, words[10], 15, 54);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], eve, words[1], 21, 55);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], eve, words[8], 6, 56);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], eve, words[15], 10, 57);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], eve, words[6], 15, 58);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], eve, words[13], 21, 59);

        round_impl(tmp[0], tmp[1], tmp[2], tmp[3], eve, words[4], 6, 60);
        round_impl(tmp[3], tmp[0], tmp[1], tmp[2], eve, words[11], 10, 61);
        round_impl(tmp[2], tmp[3], tmp[0], tmp[1], eve, words[2], 15, 62);
        round_impl(tmp[1], tmp[2], tmp[3], tmp[0], eve, words[9], 21, 63);

        state[0] += tmp[0];
        state[1] += tmp[1];
        state[2] += tmp[2];
        state[3] += tmp[3];
    }
}

md5& md5::update(const std::uint8_t* data, std::size_t size) noexcept
{
    _msglen += size;
    const std::uint8_t* src;
    auto get_data = [&](auto& words) {
        for (std::size_t k = 0; k < words.size(); k++) {
            std::uint32_t val = 0;
            val |= *src++;
            val |= *src++ << 8;
            val |= *src++ << 16;
            val |= *src++ << 24;
            words[k] = val;
        }
    };

    if (_hash.size() > md5::hash_size) {    // consume buffered data
        auto space = _hash.capacity() - _hash.size();
        std::size_t copied = size > space ? space : size;
        std::string_view tmp(reinterpret_cast<const char*>(data), copied);
        _hash.append(tmp);
        data += copied;
        size -= copied;
        if (copied == space) {      // got a full block
            src = reinterpret_cast<const std::uint8_t*>(&_hash[md5::hash_size]);
            hash_impl(_state, 1, get_data);
            _hash.resize(md5::hash_size);
        }
    }

    if (auto rem = size % md5::block_size) {
        std::string_view tmp(reinterpret_cast<const char*>(data + size - rem), rem);
        _hash.append(tmp);
    }

    src = data;
    hash_impl(_state, size / md5::block_size, get_data);
    return *this;
}

const std::string& md5::finalize(const std::uint8_t* data, std::size_t size) noexcept
{
    _msglen += size;
    if (_hash.size() > md5::hash_size) {
        auto space = _hash.capacity() - _hash.size();
        std::size_t copied = size > space ? space : size;
        std::string_view tmp(reinterpret_cast<const char*>(data), copied);
        _hash.append(tmp);
        if (copied == space) {
            data += copied;
            size -= copied;
            auto src = reinterpret_cast<const std::uint8_t*>(&_hash[md5::hash_size]);
            auto get_data = [&](auto& words) {
                for (std::size_t k = 0; k < words.size(); k++) {
                    std::uint32_t val = 0;
                    val |= *src++;
                    val |= *src++ << 8;
                    val |= *src++ << 16;
                    val |= *src++ << 24;
                    words[k] = val;
                }
            };
            hash_impl(_state, 1, get_data);
            _hash.resize(md5::hash_size);
        } else {
            data = reinterpret_cast<const std::uint8_t*>(&_hash[md5::hash_size]);
            size = _hash.size() - md5::hash_size;
        }
    }

    std::array<std::uint8_t, 72> padding {};
    std::size_t rem = size % md5::block_size;
    std::size_t pads = rem > 56 ? 120 - rem : 56 - rem;     // [1, 64] bytes
    pads = !pads ? md5::block_size : pads;

    padding[0] = 0x80;
    std::size_t shifts = 0;
    std::uint64_t bit_size = _msglen * 8;
    for (std::size_t i = 0; i < 8; i++) {   // 0xffeebbaa99881100 -> 00118899aabbeeff
        padding[pads + i] = static_cast<std::uint8_t>(bit_size >> shifts);
        shifts += 8;
    }

    std::size_t offset = 0;
    auto get_data = [&](auto& words) {
        for (std::size_t k = 0; k < words.size(); k++) {
            std::uint32_t val = 0;
            if (offset + 3 < size) {
                val |= data[offset++];
                val |= data[offset++] << 8;
                val |= data[offset++] << 16;
                val |= data[offset++] << 24;
            } else {
                const std::uint8_t* src;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src << 8;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src << 16;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src << 24;
            }
            words[k] = val;
        }
    };

    std::size_t blocks = (size + pads + 8) / md5::block_size;
    hash_impl(_state, blocks, get_data);

    static constexpr char hex_table[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    offset = 0;
    for (std::size_t i = 0; i < 4; i++) {
        shifts = 0;
        std::uint32_t val = _state[i];
        for (std::size_t k = 0; k < 4; k++) {
            auto tmp = static_cast<std::uint8_t>(val >> shifts);
            _hash[offset++] = static_cast<char>(hex_table[tmp >> 4]);
            _hash[offset++] = static_cast<char>(hex_table[tmp & 0x0f]);
            shifts += 8;
        }
    }

    reset();
    return _hash;
}

}
