#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <cmath>
#include <stdexcept>

namespace smartwan {

    // ─────────────────────────────────────────────────────────────────────────────
    //  MurmurHash3 – 128-bit output (x64 variant)
    //  Produces two 64-bit halves from arbitrary data.
    // ─────────────────────────────────────────────────────────────────────────────
    namespace murmur3 {

        inline uint64_t fmix64(uint64_t k) noexcept {
            k ^= k >> 33;
            k *= 0xff51afd7ed558ccdULL;
            k ^= k >> 33;
            k *= 0xc4ceb9fe1a85ec53ULL;
            k ^= k >> 33;
            return k;
        }

        inline void hash128(const void* key, int len, uint32_t seed,
                            uint64_t& h1_out, uint64_t& h2_out) noexcept {
                                const uint8_t* data = reinterpret_cast<const uint8_t*>(key);
                                const int nblocks = len / 16;

                                uint64_t h1 = seed, h2 = seed;
                                const uint64_t c1 = 0x87c37b91114253d5ULL;
                                const uint64_t c2 = 0x4cf5ad432745937fULL;

                                const uint64_t* blocks = reinterpret_cast<const uint64_t*>(data);
                                for (int i = 0; i < nblocks; ++i) {
                                    uint64_t k1, k2;
                                    std::memcpy(&k1, blocks + i*2,     8);
                                    std::memcpy(&k2, blocks + i*2 + 1, 8);

                                    k1 *= c1; k1 = (k1<<31)|(k1>>33); k1 *= c2; h1 ^= k1;
                                    h1 = (h1<<27)|(h1>>37); h1 += h2; h1 = h1*5 + 0x52dce729;
                                    k2 *= c2; k2 = (k2<<33)|(k2>>31); k2 *= c1; h2 ^= k2;
                                    h2 = (h2<<31)|(h2>>33); h2 += h1; h2 = h2*5 + 0x38495ab5;
                                }

                                const uint8_t* tail = data + nblocks*16;
                                uint64_t k1=0, k2=0;
                                switch (len & 15) {
                                    case 15: k2 ^= uint64_t(tail[14])<<48; [[fallthrough]];
                                    case 14: k2 ^= uint64_t(tail[13])<<40; [[fallthrough]];
                                    case 13: k2 ^= uint64_t(tail[12])<<32; [[fallthrough]];
                                    case 12: k2 ^= uint64_t(tail[11])<<24; [[fallthrough]];
                                    case 11: k2 ^= uint64_t(tail[10])<<16; [[fallthrough]];
                                    case 10: k2 ^= uint64_t(tail[ 9])<< 8; [[fallthrough]];
                                    case  9: k2 ^= uint64_t(tail[ 8]);
                                    k2 *= c2; k2=(k2<<33)|(k2>>31); k2 *= c1; h2 ^= k2; [[fallthrough]];
                                    case  8: k1 ^= uint64_t(tail[ 7])<<56; [[fallthrough]];
                                    case  7: k1 ^= uint64_t(tail[ 6])<<48; [[fallthrough]];
                                    case  6: k1 ^= uint64_t(tail[ 5])<<40; [[fallthrough]];
                                    case  5: k1 ^= uint64_t(tail[ 4])<<32; [[fallthrough]];
                                    case  4: k1 ^= uint64_t(tail[ 3])<<24; [[fallthrough]];
                                    case  3: k1 ^= uint64_t(tail[ 2])<<16; [[fallthrough]];
                                    case  2: k1 ^= uint64_t(tail[ 1])<< 8; [[fallthrough]];
                                    case  1: k1 ^= uint64_t(tail[ 0]);
                                    k1 *= c1; k1=(k1<<31)|(k1>>33); k1 *= c2; h1 ^= k1;
                                }

                                h1 ^= len; h2 ^= len;
                                h1 += h2; h2 += h1;
                                h1 = fmix64(h1); h2 = fmix64(h2);
                                h1 += h2; h2 += h1;
                                h1_out = h1; h2_out = h2;
                            }

    } // namespace murmur3

    // ─────────────────────────────────────────────────────────────────────────────
    //  BloomFilter<T>
    //  Probabilistic set membership with configurable false-positive rate.
    //  Uses k independent hash functions derived from two MurmurHash3 seeds.
    //
    //  Theory:  k = (m/n) * ln2,  m = -n*ln(p) / (ln2)^2
    //  Where:   n = expected items, p = desired false-positive rate
    // ─────────────────────────────────────────────────────────────────────────────
    template<typename T>
    class BloomFilter {
    public:
        // Construct with expected_items and desired false_positive_rate (0–1)
        BloomFilter(size_t expected_items, double false_positive_rate = 0.01) {
            if (false_positive_rate <= 0.0 || false_positive_rate >= 1.0)
                throw std::invalid_argument("false_positive_rate must be in (0,1)");

            double ln2   = std::log(2.0);
            double ln2_2 = ln2 * ln2;
            m_bits  = static_cast<size_t>(
                -static_cast<double>(expected_items) * std::log(false_positive_rate) / ln2_2
            );
            m_bits  = std::max(m_bits, size_t(64));
            m_k     = static_cast<size_t>(
                (static_cast<double>(m_bits) / expected_items) * ln2
            );
            m_k     = std::max(m_k, size_t(1));
            m_k     = std::min(m_k, size_t(32));

            size_t words = (m_bits + 63) / 64;
            m_table.assign(words, 0ULL);
            m_count = 0;
        }

        // Insert a raw byte blob
        void insert_raw(const void* data, size_t len) {
            auto [h1, h2] = hash_pair(data, len);
            for (size_t i = 0; i < m_k; ++i) {
                size_t bit = (h1 + i * h2) % m_bits;
                m_table[bit / 64] |= (1ULL << (bit % 64));
            }
            ++m_count;
        }

        // Query membership (may return false positives)
        bool contains_raw(const void* data, size_t len) const {
            auto [h1, h2] = hash_pair(data, len);
            for (size_t i = 0; i < m_k; ++i) {
                size_t bit = (h1 + i * h2) % m_bits;
                if (!(m_table[bit / 64] & (1ULL << (bit % 64))))
                    return false;
            }
            return true;
        }

        // Insert typed value (requires T to be trivially copyable)
        void insert(const T& v) {
            insert_raw(&v, sizeof(T));
        }

        bool contains(const T& v) const {
            return contains_raw(&v, sizeof(v));
        }

        void clear() {
            std::fill(m_table.begin(), m_table.end(), 0ULL);
            m_count = 0;
        }

        // Estimated false-positive probability given current fill
        double fpp() const noexcept {
            double fill_ratio = static_cast<double>(bits_set()) / m_bits;
            return std::pow(fill_ratio, static_cast<double>(m_k));
        }

        size_t item_count()  const noexcept { return m_count; }
        size_t bit_count()   const noexcept { return m_bits;  }
        size_t hash_funcs()  const noexcept { return m_k;     }

        // Bitwise OR merge (union) of two filters with identical parameters
        BloomFilter& operator|=(const BloomFilter& other) {
            if (m_bits != other.m_bits || m_k != other.m_k)
                throw std::invalid_argument("Bloom filter parameter mismatch");
            for (size_t i = 0; i < m_table.size(); ++i)
                m_table[i] |= other.m_table[i];
            m_count += other.m_count;
            return *this;
        }

    private:
        std::vector<uint64_t> m_table;
        size_t m_bits;
        size_t m_k;     // number of hash functions
        size_t m_count; // approximate item count

        std::pair<uint64_t,uint64_t> hash_pair(const void* data, size_t len) const {
            uint64_t h1, h2;
            murmur3::hash128(data, static_cast<int>(len), 0xDEADBEEF, h1, h2);
            // h2 must be odd to ensure double-hashing covers all bits
            h2 |= 1ULL;
            return {h1, h2};
        }

        size_t bits_set() const noexcept {
            size_t n = 0;
            for (auto w : m_table) n += static_cast<size_t>(__builtin_popcountll(w));
            return n;
        }
    };

    // Convenience specialization for flow key hashing
    struct FlowKeyHasher {
        template<typename FK>
        static void insert(BloomFilter<uint64_t>& bf, const FK& fk) {
            uint64_t h = fk.hash();
            bf.insert(h);
        }
        template<typename FK>
        static bool contains(const BloomFilter<uint64_t>& bf, const FK& fk) {
            uint64_t h = fk.hash();
            return bf.contains(h);
        }
    };

} // namespace smartwan
