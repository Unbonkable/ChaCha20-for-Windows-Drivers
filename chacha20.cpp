#include "chacha20.h"

// https://github.com/jedisct1/libsodium/tree/master/src/libsodium/crypto_stream/chacha20

// libsodium chacha20 port for WDK by @Unbonkable, horrible stuff...
// I DID NOT make all of this, i just made it so you can use it in Windows kernel
// only "crypto_stream_chacha20_xor_ic" and "crypto_stream_chacha20_xor" are ported, since these are the only ones i needed.
// dont even try to understand this shit, i promise you'll most likely just waste your time


static void chacha20_encrypt_bytes(chacha_ctx* ctx, const unsigned char* m, unsigned char* c, unsigned long long bytes) {
    UINT32* const x = &ctx->input[0];

    if (!bytes) {
        return; /* LCOV_EXCL_LINE */
    }
    
    //u8.h  ---------------------------------------------

#define VEC8_ROT(A, IMM) \
    _mm256_or_si256(_mm256_slli_epi32(A, IMM), _mm256_srli_epi32(A, (32 - IMM)))

    /* same, but replace 2 of the shift/shift/or "rotation" by byte shuffles (8 & * 16) (better) */
#define VEC8_QUARTERROUND_SHUFFLE(A, B, C, D)  \
    x_##A = _mm256_add_epi32(x_##A, x_##B);    \
    t_##A = _mm256_xor_si256(x_##D, x_##A);    \
    x_##D = _mm256_shuffle_epi8(t_##A, rot16); \
    x_##C = _mm256_add_epi32(x_##C, x_##D);    \
    t_##C = _mm256_xor_si256(x_##B, x_##C);    \
    x_##B = VEC8_ROT(t_##C, 12);               \
    x_##A = _mm256_add_epi32(x_##A, x_##B);    \
    t_##A = _mm256_xor_si256(x_##D, x_##A);    \
    x_##D = _mm256_shuffle_epi8(t_##A, rot8);  \
    x_##C = _mm256_add_epi32(x_##C, x_##D);    \
    t_##C = _mm256_xor_si256(x_##B, x_##C);    \
    x_##B = VEC8_ROT(t_##C, 7)

#define VEC8_QUARTERROUND(A, B, C, D) VEC8_QUARTERROUND_SHUFFLE(A, B, C, D)

#define VEC8_LINE1(A, B, C, D)              \
    x_##A = _mm256_add_epi32(x_##A, x_##B); \
    x_##D = _mm256_shuffle_epi8(_mm256_xor_si256(x_##D, x_##A), rot16)
#define VEC8_LINE2(A, B, C, D)              \
    x_##C = _mm256_add_epi32(x_##C, x_##D); \
    x_##B = VEC8_ROT(_mm256_xor_si256(x_##B, x_##C), 12)
#define VEC8_LINE3(A, B, C, D)              \
    x_##A = _mm256_add_epi32(x_##A, x_##B); \
    x_##D = _mm256_shuffle_epi8(_mm256_xor_si256(x_##D, x_##A), rot8)
#define VEC8_LINE4(A, B, C, D)              \
    x_##C = _mm256_add_epi32(x_##C, x_##D); \
    x_##B = VEC8_ROT(_mm256_xor_si256(x_##B, x_##C), 7)

#define VEC8_ROUND_SEQ(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, A4, B4, \
                       C4, D4)                                                 \
    VEC8_LINE1(A1, B1, C1, D1);                                                \
    VEC8_LINE1(A2, B2, C2, D2);                                                \
    VEC8_LINE1(A3, B3, C3, D3);                                                \
    VEC8_LINE1(A4, B4, C4, D4);                                                \
    VEC8_LINE2(A1, B1, C1, D1);                                                \
    VEC8_LINE2(A2, B2, C2, D2);                                                \
    VEC8_LINE2(A3, B3, C3, D3);                                                \
    VEC8_LINE2(A4, B4, C4, D4);                                                \
    VEC8_LINE3(A1, B1, C1, D1);                                                \
    VEC8_LINE3(A2, B2, C2, D2);                                                \
    VEC8_LINE3(A3, B3, C3, D3);                                                \
    VEC8_LINE3(A4, B4, C4, D4);                                                \
    VEC8_LINE4(A1, B1, C1, D1);                                                \
    VEC8_LINE4(A2, B2, C2, D2);                                                \
    VEC8_LINE4(A3, B3, C3, D3);                                                \
    VEC8_LINE4(A4, B4, C4, D4)

#define VEC8_ROUND_HALF(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, A4, \
                        B4, C4, D4)                                         \
    VEC8_LINE1(A1, B1, C1, D1);                                             \
    VEC8_LINE1(A2, B2, C2, D2);                                             \
    VEC8_LINE2(A1, B1, C1, D1);                                             \
    VEC8_LINE2(A2, B2, C2, D2);                                             \
    VEC8_LINE3(A1, B1, C1, D1);                                             \
    VEC8_LINE3(A2, B2, C2, D2);                                             \
    VEC8_LINE4(A1, B1, C1, D1);                                             \
    VEC8_LINE4(A2, B2, C2, D2);                                             \
    VEC8_LINE1(A3, B3, C3, D3);                                             \
    VEC8_LINE1(A4, B4, C4, D4);                                             \
    VEC8_LINE2(A3, B3, C3, D3);                                             \
    VEC8_LINE2(A4, B4, C4, D4);                                             \
    VEC8_LINE3(A3, B3, C3, D3);                                             \
    VEC8_LINE3(A4, B4, C4, D4);                                             \
    VEC8_LINE4(A3, B3, C3, D3);                                             \
    VEC8_LINE4(A4, B4, C4, D4)

#define VEC8_ROUND_HALFANDHALF(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, \
                               A4, B4, C4, D4)                                 \
    VEC8_LINE1(A1, B1, C1, D1);                                                \
    VEC8_LINE1(A2, B2, C2, D2);                                                \
    VEC8_LINE2(A1, B1, C1, D1);                                                \
    VEC8_LINE2(A2, B2, C2, D2);                                                \
    VEC8_LINE1(A3, B3, C3, D3);                                                \
    VEC8_LINE1(A4, B4, C4, D4);                                                \
    VEC8_LINE2(A3, B3, C3, D3);                                                \
    VEC8_LINE2(A4, B4, C4, D4);                                                \
    VEC8_LINE3(A1, B1, C1, D1);                                                \
    VEC8_LINE3(A2, B2, C2, D2);                                                \
    VEC8_LINE4(A1, B1, C1, D1);                                                \
    VEC8_LINE4(A2, B2, C2, D2);                                                \
    VEC8_LINE3(A3, B3, C3, D3);                                                \
    VEC8_LINE3(A4, B4, C4, D4);                                                \
    VEC8_LINE4(A3, B3, C3, D3);                                                \
    VEC8_LINE4(A4, B4, C4, D4)

#define VEC8_ROUND(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, A4, B4, C4, \
                   D4)                                                         \
    VEC8_ROUND_SEQ(A1, B1, C1, D1, A2, B2, C2, D2, A3, B3, C3, D3, A4, B4, C4, \
                   D4)

    if (bytes >= 512) {
        /* constant for shuffling bytes (replacing multiple-of-8 rotates) */
        __m256i rot16 =
            _mm256_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
                13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
        __m256i rot8 =
            _mm256_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
                14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
        UINT32 in12, in13;

        /* the naive way seems as fast (if not a bit faster) than the vector way */
        __m256i x_0 = _mm256_set1_epi32(x[0]);
        __m256i x_1 = _mm256_set1_epi32(x[1]);
        __m256i x_2 = _mm256_set1_epi32(x[2]);
        __m256i x_3 = _mm256_set1_epi32(x[3]);
        __m256i x_4 = _mm256_set1_epi32(x[4]);
        __m256i x_5 = _mm256_set1_epi32(x[5]);
        __m256i x_6 = _mm256_set1_epi32(x[6]);
        __m256i x_7 = _mm256_set1_epi32(x[7]);
        __m256i x_8 = _mm256_set1_epi32(x[8]);
        __m256i x_9 = _mm256_set1_epi32(x[9]);
        __m256i x_10 = _mm256_set1_epi32(x[10]);
        __m256i x_11 = _mm256_set1_epi32(x[11]);
        __m256i x_12;
        __m256i x_13;
        __m256i x_14 = _mm256_set1_epi32(x[14]);
        __m256i x_15 = _mm256_set1_epi32(x[15]);

        __m256i orig0 = x_0;
        __m256i orig1 = x_1;
        __m256i orig2 = x_2;
        __m256i orig3 = x_3;
        __m256i orig4 = x_4;
        __m256i orig5 = x_5;
        __m256i orig6 = x_6;
        __m256i orig7 = x_7;
        __m256i orig8 = x_8;
        __m256i orig9 = x_9;
        __m256i orig10 = x_10;
        __m256i orig11 = x_11;
        __m256i orig12;
        __m256i orig13;
        __m256i orig14 = x_14;
        __m256i orig15 = x_15;
        __m256i t_0, t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11, t_12,
            t_13, t_14, t_15;

        while (bytes >= 512) {
            const __m256i addv12 = _mm256_set_epi64x(3, 2, 1, 0);
            const __m256i addv13 = _mm256_set_epi64x(7, 6, 5, 4);
            const __m256i permute = _mm256_set_epi32(7, 6, 3, 2, 5, 4, 1, 0);
            __m256i       t12, t13;

            UINT64 in1213;
            int      i;

            x_0 = orig0;
            x_1 = orig1;
            x_2 = orig2;
            x_3 = orig3;
            x_4 = orig4;
            x_5 = orig5;
            x_6 = orig6;
            x_7 = orig7;
            x_8 = orig8;
            x_9 = orig9;
            x_10 = orig10;
            x_11 = orig11;
            x_14 = orig14;
            x_15 = orig15;

            in12 = x[12];
            in13 = x[13];
            in1213 = ((UINT64)in12) | (((UINT64)in13) << 32);
            x_12 = x_13 = _mm256_broadcastq_epi64(_mm_cvtsi64_si128(in1213));

            t12 = _mm256_add_epi64(addv12, x_12);
            t13 = _mm256_add_epi64(addv13, x_13);

            x_12 = _mm256_unpacklo_epi32(t12, t13);
            x_13 = _mm256_unpackhi_epi32(t12, t13);

            t12 = _mm256_unpacklo_epi32(x_12, x_13);
            t13 = _mm256_unpackhi_epi32(x_12, x_13);

            /* required because unpack* are intra-lane */
            x_12 = _mm256_permutevar8x32_epi32(t12, permute);
            x_13 = _mm256_permutevar8x32_epi32(t13, permute);

            orig12 = x_12;
            orig13 = x_13;

            in1213 += 8;

            x[12] = in1213 & 0xFFFFFFFF;
            x[13] = (in1213 >> 32) & 0xFFFFFFFF;

            for (i = 0; i < ROUNDS; i += 2) {
                VEC8_ROUND(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15);
                VEC8_ROUND(0, 5, 10, 15, 1, 6, 11, 12, 2, 7, 8, 13, 3, 4, 9, 14);
            }

#define ONEQUAD_TRANSPOSE(A, B, C, D)                                     \
    {                                                                     \
        __m128i t0, t1, t2, t3;                                           \
        x_##A = _mm256_add_epi32(x_##A, orig##A);                         \
        x_##B = _mm256_add_epi32(x_##B, orig##B);                         \
        x_##C = _mm256_add_epi32(x_##C, orig##C);                         \
        x_##D = _mm256_add_epi32(x_##D, orig##D);                         \
        t_##A = _mm256_unpacklo_epi32(x_##A, x_##B);                      \
        t_##B = _mm256_unpacklo_epi32(x_##C, x_##D);                      \
        t_##C = _mm256_unpackhi_epi32(x_##A, x_##B);                      \
        t_##D = _mm256_unpackhi_epi32(x_##C, x_##D);                      \
        x_##A = _mm256_unpacklo_epi64(t_##A, t_##B);                      \
        x_##B = _mm256_unpackhi_epi64(t_##A, t_##B);                      \
        x_##C = _mm256_unpacklo_epi64(t_##C, t_##D);                      \
        x_##D = _mm256_unpackhi_epi64(t_##C, t_##D);                      \
        t0    = _mm_xor_si128(_mm256_extracti128_si256(x_##A, 0),         \
                           _mm_loadu_si128((const __m128i*) (m + 0))); \
        _mm_storeu_si128((__m128i*) (c + 0), t0);                         \
        t1 = _mm_xor_si128(_mm256_extracti128_si256(x_##B, 0),            \
                           _mm_loadu_si128((const __m128i*) (m + 64)));   \
        _mm_storeu_si128((__m128i*) (c + 64), t1);                        \
        t2 = _mm_xor_si128(_mm256_extracti128_si256(x_##C, 0),            \
                           _mm_loadu_si128((const __m128i*) (m + 128)));  \
        _mm_storeu_si128((__m128i*) (c + 128), t2);                       \
        t3 = _mm_xor_si128(_mm256_extracti128_si256(x_##D, 0),            \
                           _mm_loadu_si128((const __m128i*) (m + 192)));  \
        _mm_storeu_si128((__m128i*) (c + 192), t3);                       \
        t0 = _mm_xor_si128(_mm256_extracti128_si256(x_##A, 1),            \
                           _mm_loadu_si128((const __m128i*) (m + 256)));  \
        _mm_storeu_si128((__m128i*) (c + 256), t0);                       \
        t1 = _mm_xor_si128(_mm256_extracti128_si256(x_##B, 1),            \
                           _mm_loadu_si128((const __m128i*) (m + 320)));  \
        _mm_storeu_si128((__m128i*) (c + 320), t1);                       \
        t2 = _mm_xor_si128(_mm256_extracti128_si256(x_##C, 1),            \
                           _mm_loadu_si128((const __m128i*) (m + 384)));  \
        _mm_storeu_si128((__m128i*) (c + 384), t2);                       \
        t3 = _mm_xor_si128(_mm256_extracti128_si256(x_##D, 1),            \
                           _mm_loadu_si128((const __m128i*) (m + 448)));  \
        _mm_storeu_si128((__m128i*) (c + 448), t3);                       \
    }

#define ONEQUAD(A, B, C, D) ONEQUAD_TRANSPOSE(A, B, C, D)

#define ONEQUAD_UNPCK(A, B, C, D)                    \
    {                                                \
        x_##A = _mm256_add_epi32(x_##A, orig##A);    \
        x_##B = _mm256_add_epi32(x_##B, orig##B);    \
        x_##C = _mm256_add_epi32(x_##C, orig##C);    \
        x_##D = _mm256_add_epi32(x_##D, orig##D);    \
        t_##A = _mm256_unpacklo_epi32(x_##A, x_##B); \
        t_##B = _mm256_unpacklo_epi32(x_##C, x_##D); \
        t_##C = _mm256_unpackhi_epi32(x_##A, x_##B); \
        t_##D = _mm256_unpackhi_epi32(x_##C, x_##D); \
        x_##A = _mm256_unpacklo_epi64(t_##A, t_##B); \
        x_##B = _mm256_unpackhi_epi64(t_##A, t_##B); \
        x_##C = _mm256_unpacklo_epi64(t_##C, t_##D); \
        x_##D = _mm256_unpackhi_epi64(t_##C, t_##D); \
    }

#define ONEOCTO(A, B, C, D, A2, B2, C2, D2)                          \
    {                                                                \
        ONEQUAD_UNPCK(A, B, C, D);                                   \
        ONEQUAD_UNPCK(A2, B2, C2, D2);                               \
        t_##A  = _mm256_permute2x128_si256(x_##A, x_##A2, 0x20);     \
        t_##A2 = _mm256_permute2x128_si256(x_##A, x_##A2, 0x31);     \
        t_##B  = _mm256_permute2x128_si256(x_##B, x_##B2, 0x20);     \
        t_##B2 = _mm256_permute2x128_si256(x_##B, x_##B2, 0x31);     \
        t_##C  = _mm256_permute2x128_si256(x_##C, x_##C2, 0x20);     \
        t_##C2 = _mm256_permute2x128_si256(x_##C, x_##C2, 0x31);     \
        t_##D  = _mm256_permute2x128_si256(x_##D, x_##D2, 0x20);     \
        t_##D2 = _mm256_permute2x128_si256(x_##D, x_##D2, 0x31);     \
        t_##A  = _mm256_xor_si256(                                   \
            t_##A, _mm256_loadu_si256((const __m256i*) (m + 0)));   \
        t_##B = _mm256_xor_si256(                                    \
            t_##B, _mm256_loadu_si256((const __m256i*) (m + 64)));   \
        t_##C = _mm256_xor_si256(                                    \
            t_##C, _mm256_loadu_si256((const __m256i*) (m + 128)));  \
        t_##D = _mm256_xor_si256(                                    \
            t_##D, _mm256_loadu_si256((const __m256i*) (m + 192)));  \
        t_##A2 = _mm256_xor_si256(                                   \
            t_##A2, _mm256_loadu_si256((const __m256i*) (m + 256))); \
        t_##B2 = _mm256_xor_si256(                                   \
            t_##B2, _mm256_loadu_si256((const __m256i*) (m + 320))); \
        t_##C2 = _mm256_xor_si256(                                   \
            t_##C2, _mm256_loadu_si256((const __m256i*) (m + 384))); \
        t_##D2 = _mm256_xor_si256(                                   \
            t_##D2, _mm256_loadu_si256((const __m256i*) (m + 448))); \
        _mm256_storeu_si256((__m256i*) (c + 0), t_##A);              \
        _mm256_storeu_si256((__m256i*) (c + 64), t_##B);             \
        _mm256_storeu_si256((__m256i*) (c + 128), t_##C);            \
        _mm256_storeu_si256((__m256i*) (c + 192), t_##D);            \
        _mm256_storeu_si256((__m256i*) (c + 256), t_##A2);           \
        _mm256_storeu_si256((__m256i*) (c + 320), t_##B2);           \
        _mm256_storeu_si256((__m256i*) (c + 384), t_##C2);           \
        _mm256_storeu_si256((__m256i*) (c + 448), t_##D2);           \
    }

            ONEOCTO(0, 1, 2, 3, 4, 5, 6, 7);
            m += 32;
            c += 32;
            ONEOCTO(8, 9, 10, 11, 12, 13, 14, 15);
            m -= 32;
            c -= 32;

#undef ONEQUAD
#undef ONEQUAD_TRANSPOSE
#undef ONEQUAD_UNPCK
#undef ONEOCTO

            bytes -= 512;
            c += 512;
            m += 512;
        }
    }
#undef VEC8_ROT
#undef VEC8_QUARTERROUND
#undef VEC8_QUARTERROUND_NAIVE
#undef VEC8_QUARTERROUND_SHUFFLE
#undef VEC8_QUARTERROUND_SHUFFLE2
#undef VEC8_LINE1
#undef VEC8_LINE2
#undef VEC8_LINE3
#undef VEC8_LINE4
#undef VEC8_ROUND
#undef VEC8_ROUND_SEQ
#undef VEC8_ROUND_HALF
#undef VEC8_ROUND_HALFANDHALF

    //u4.h  ---------------------------------------------

#define VEC4_ROT(A, IMM) \
    _mm_or_si128(_mm_slli_epi32(A, IMM), _mm_srli_epi32(A, (32 - IMM)))

/* same, but replace 2 of the shift/shift/or "rotation" by byte shuffles (8 & 16) (better) */
#define VEC4_QUARTERROUND_SHUFFLE(A, B, C, D) \
    x_##A = _mm_add_epi32(x_##A, x_##B);      \
    t_##A = _mm_xor_si128(x_##D, x_##A);      \
    x_##D = _mm_shuffle_epi8(t_##A, rot16);   \
    x_##C = _mm_add_epi32(x_##C, x_##D);      \
    t_##C = _mm_xor_si128(x_##B, x_##C);      \
    x_##B = VEC4_ROT(t_##C, 12);              \
    x_##A = _mm_add_epi32(x_##A, x_##B);      \
    t_##A = _mm_xor_si128(x_##D, x_##A);      \
    x_##D = _mm_shuffle_epi8(t_##A, rot8);    \
    x_##C = _mm_add_epi32(x_##C, x_##D);      \
    t_##C = _mm_xor_si128(x_##B, x_##C);      \
    x_##B = VEC4_ROT(t_##C, 7)

#define VEC4_QUARTERROUND(A, B, C, D) VEC4_QUARTERROUND_SHUFFLE(A, B, C, D)

    if (bytes >= 256) {
        /* constant for shuffling bytes (replacing multiple-of-8 rotates) */
        __m128i rot16 =
            _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
        __m128i rot8 =
            _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

        __m128i x_0 = _mm_set1_epi32(x[0]);
        __m128i x_1 = _mm_set1_epi32(x[1]);
        __m128i x_2 = _mm_set1_epi32(x[2]);
        __m128i x_3 = _mm_set1_epi32(x[3]);
        __m128i x_4 = _mm_set1_epi32(x[4]);
        __m128i x_5 = _mm_set1_epi32(x[5]);
        __m128i x_6 = _mm_set1_epi32(x[6]);
        __m128i x_7 = _mm_set1_epi32(x[7]);
        __m128i x_8 = _mm_set1_epi32(x[8]);
        __m128i x_9 = _mm_set1_epi32(x[9]);
        __m128i x_10 = _mm_set1_epi32(x[10]);
        __m128i x_11 = _mm_set1_epi32(x[11]);
        __m128i x_12;
        __m128i x_13;
        __m128i x_14 = _mm_set1_epi32(x[14]);
        __m128i x_15 = _mm_set1_epi32(x[15]);
        __m128i orig0 = x_0;
        __m128i orig1 = x_1;
        __m128i orig2 = x_2;
        __m128i orig3 = x_3;
        __m128i orig4 = x_4;
        __m128i orig5 = x_5;
        __m128i orig6 = x_6;
        __m128i orig7 = x_7;
        __m128i orig8 = x_8;
        __m128i orig9 = x_9;
        __m128i orig10 = x_10;
        __m128i orig11 = x_11;
        __m128i orig12;
        __m128i orig13;
        __m128i orig14 = x_14;
        __m128i orig15 = x_15;
        __m128i t_0, t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11, t_12,
            t_13, t_14, t_15;

        UINT32 in12, in13;
        int      i;
        while (bytes >= 256) {
            const __m128i addv12 = _mm_set_epi64x(1, 0);
            const __m128i addv13 = _mm_set_epi64x(3, 2);
            __m128i       t12, t13;
            UINT64      in1213;

            x_0 = orig0;
            x_1 = orig1;
            x_2 = orig2;
            x_3 = orig3;
            x_4 = orig4;
            x_5 = orig5;
            x_6 = orig6;
            x_7 = orig7;
            x_8 = orig8;
            x_9 = orig9;
            x_10 = orig10;
            x_11 = orig11;
            x_14 = orig14;
            x_15 = orig15;

            in12 = x[12];
            in13 = x[13];
            in1213 = ((UINT64)in12) | (((UINT64)in13) << 32);
            t12 = _mm_set1_epi64x(in1213);
            t13 = _mm_set1_epi64x(in1213);

            x_12 = _mm_add_epi64(addv12, t12);
            x_13 = _mm_add_epi64(addv13, t13);

            t12 = _mm_unpacklo_epi32(x_12, x_13);
            t13 = _mm_unpackhi_epi32(x_12, x_13);

            x_12 = _mm_unpacklo_epi32(t12, t13);
            x_13 = _mm_unpackhi_epi32(t12, t13);

            orig12 = x_12;
            orig13 = x_13;

            in1213 += 4;

            x[12] = in1213 & 0xFFFFFFFF;
            x[13] = (in1213 >> 32) & 0xFFFFFFFF;

            for (i = 0; i < ROUNDS; i += 2) {
                VEC4_QUARTERROUND(0, 4, 8, 12);
                VEC4_QUARTERROUND(1, 5, 9, 13);
                VEC4_QUARTERROUND(2, 6, 10, 14);
                VEC4_QUARTERROUND(3, 7, 11, 15);
                VEC4_QUARTERROUND(0, 5, 10, 15);
                VEC4_QUARTERROUND(1, 6, 11, 12);
                VEC4_QUARTERROUND(2, 7, 8, 13);
                VEC4_QUARTERROUND(3, 4, 9, 14);
            }

#define ONEQUAD_TRANSPOSE(A, B, C, D)                                          \
    {                                                                          \
        __m128i t0, t1, t2, t3;                                                \
                                                                               \
        x_##A = _mm_add_epi32(x_##A, orig##A);                                 \
        x_##B = _mm_add_epi32(x_##B, orig##B);                                 \
        x_##C = _mm_add_epi32(x_##C, orig##C);                                 \
        x_##D = _mm_add_epi32(x_##D, orig##D);                                 \
        t_##A = _mm_unpacklo_epi32(x_##A, x_##B);                              \
        t_##B = _mm_unpacklo_epi32(x_##C, x_##D);                              \
        t_##C = _mm_unpackhi_epi32(x_##A, x_##B);                              \
        t_##D = _mm_unpackhi_epi32(x_##C, x_##D);                              \
        x_##A = _mm_unpacklo_epi64(t_##A, t_##B);                              \
        x_##B = _mm_unpackhi_epi64(t_##A, t_##B);                              \
        x_##C = _mm_unpacklo_epi64(t_##C, t_##D);                              \
        x_##D = _mm_unpackhi_epi64(t_##C, t_##D);                              \
                                                                               \
        t0 = _mm_xor_si128(x_##A, _mm_loadu_si128((const __m128i*) (m + 0)));  \
        _mm_storeu_si128((__m128i*) (c + 0), t0);                              \
        t1 = _mm_xor_si128(x_##B, _mm_loadu_si128((const __m128i*) (m + 64))); \
        _mm_storeu_si128((__m128i*) (c + 64), t1);                             \
        t2 =                                                                   \
            _mm_xor_si128(x_##C, _mm_loadu_si128((const __m128i*) (m + 128))); \
        _mm_storeu_si128((__m128i*) (c + 128), t2);                            \
        t3 =                                                                   \
            _mm_xor_si128(x_##D, _mm_loadu_si128((const __m128i*) (m + 192))); \
        _mm_storeu_si128((__m128i*) (c + 192), t3);                            \
    }

#define ONEQUAD(A, B, C, D) ONEQUAD_TRANSPOSE(A, B, C, D)

            ONEQUAD(0, 1, 2, 3);
            m += 16;
            c += 16;
            ONEQUAD(4, 5, 6, 7);
            m += 16;
            c += 16;
            ONEQUAD(8, 9, 10, 11);
            m += 16;
            c += 16;
            ONEQUAD(12, 13, 14, 15);
            m -= 48;
            c -= 48;

#undef ONEQUAD
#undef ONEQUAD_TRANSPOSE

            bytes -= 256;
            c += 256;
            m += 256;
        }
    }
#undef VEC4_ROT
#undef VEC4_QUARTERROUND
#undef VEC4_QUARTERROUND_SHUFFLE

    // u1.h ---------------------------------------------

    while (bytes >= 64) {
        __m128i       x_0, x_1, x_2, x_3;
        __m128i       t_1;
        const __m128i rot16 =
            _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
        const __m128i rot8 =
            _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

        UINT32 in12;
        UINT32 in13;
        int      i;

        x_0 = _mm_loadu_si128((const __m128i*) (x + 0));
        x_1 = _mm_loadu_si128((const __m128i*) (x + 4));
        x_2 = _mm_loadu_si128((const __m128i*) (x + 8));
        x_3 = _mm_loadu_si128((const __m128i*) (x + 12));

        for (i = 0; i < ROUNDS; i += 2) {
            x_0 = _mm_add_epi32(x_0, x_1);
            x_3 = _mm_xor_si128(x_3, x_0);
            x_3 = _mm_shuffle_epi8(x_3, rot16);

            x_2 = _mm_add_epi32(x_2, x_3);
            x_1 = _mm_xor_si128(x_1, x_2);

            t_1 = x_1;
            x_1 = _mm_slli_epi32(x_1, 12);
            t_1 = _mm_srli_epi32(t_1, 20);
            x_1 = _mm_xor_si128(x_1, t_1);

            x_0 = _mm_add_epi32(x_0, x_1);
            x_3 = _mm_xor_si128(x_3, x_0);
            x_0 = _mm_shuffle_epi32(x_0, 0x93);
            x_3 = _mm_shuffle_epi8(x_3, rot8);

            x_2 = _mm_add_epi32(x_2, x_3);
            x_3 = _mm_shuffle_epi32(x_3, 0x4e);
            x_1 = _mm_xor_si128(x_1, x_2);
            x_2 = _mm_shuffle_epi32(x_2, 0x39);

            t_1 = x_1;
            x_1 = _mm_slli_epi32(x_1, 7);
            t_1 = _mm_srli_epi32(t_1, 25);
            x_1 = _mm_xor_si128(x_1, t_1);

            x_0 = _mm_add_epi32(x_0, x_1);
            x_3 = _mm_xor_si128(x_3, x_0);
            x_3 = _mm_shuffle_epi8(x_3, rot16);

            x_2 = _mm_add_epi32(x_2, x_3);
            x_1 = _mm_xor_si128(x_1, x_2);

            t_1 = x_1;
            x_1 = _mm_slli_epi32(x_1, 12);
            t_1 = _mm_srli_epi32(t_1, 20);
            x_1 = _mm_xor_si128(x_1, t_1);

            x_0 = _mm_add_epi32(x_0, x_1);
            x_3 = _mm_xor_si128(x_3, x_0);
            x_0 = _mm_shuffle_epi32(x_0, 0x39);
            x_3 = _mm_shuffle_epi8(x_3, rot8);

            x_2 = _mm_add_epi32(x_2, x_3);
            x_3 = _mm_shuffle_epi32(x_3, 0x4e);
            x_1 = _mm_xor_si128(x_1, x_2);
            x_2 = _mm_shuffle_epi32(x_2, 0x93);

            t_1 = x_1;
            x_1 = _mm_slli_epi32(x_1, 7);
            t_1 = _mm_srli_epi32(t_1, 25);
            x_1 = _mm_xor_si128(x_1, t_1);
        }
        x_0 = _mm_add_epi32(x_0, _mm_loadu_si128((const __m128i*) (x + 0)));
        x_1 = _mm_add_epi32(x_1, _mm_loadu_si128((const __m128i*) (x + 4)));
        x_2 = _mm_add_epi32(x_2, _mm_loadu_si128((const __m128i*) (x + 8)));
        x_3 = _mm_add_epi32(x_3, _mm_loadu_si128((const __m128i*) (x + 12)));
        x_0 = _mm_xor_si128(x_0, _mm_loadu_si128((const __m128i*) (m + 0)));
        x_1 = _mm_xor_si128(x_1, _mm_loadu_si128((const __m128i*) (m + 16)));
        x_2 = _mm_xor_si128(x_2, _mm_loadu_si128((const __m128i*) (m + 32)));
        x_3 = _mm_xor_si128(x_3, _mm_loadu_si128((const __m128i*) (m + 48)));
        _mm_storeu_si128((__m128i*) (c + 0), x_0);
        _mm_storeu_si128((__m128i*) (c + 16), x_1);
        _mm_storeu_si128((__m128i*) (c + 32), x_2);
        _mm_storeu_si128((__m128i*) (c + 48), x_3);

        in12 = x[12];
        in13 = x[13];
        in12++;
        if (in12 == 0) {
            in13++;
        }
        x[12] = in12;
        x[13] = in13;

        bytes -= 64;
        c += 64;
        m += 64;
    }

    if (bytes > 0) {
        __m128i       x_0, x_1, x_2, x_3;
        __m128i       t_1;
        const __m128i rot16 =
            _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
        const __m128i rot8 =
            _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
        unsigned char partialblock[64];

        unsigned int i;

        x_0 = _mm_loadu_si128((const __m128i*) (x + 0));
        x_1 = _mm_loadu_si128((const __m128i*) (x + 4));
        x_2 = _mm_loadu_si128((const __m128i*) (x + 8));
        x_3 = _mm_loadu_si128((const __m128i*) (x + 12));

        for (i = 0; i < ROUNDS; i += 2) {
            x_0 = _mm_add_epi32(x_0, x_1);
            x_3 = _mm_xor_si128(x_3, x_0);
            x_3 = _mm_shuffle_epi8(x_3, rot16);

            x_2 = _mm_add_epi32(x_2, x_3);
            x_1 = _mm_xor_si128(x_1, x_2);

            t_1 = x_1;
            x_1 = _mm_slli_epi32(x_1, 12);
            t_1 = _mm_srli_epi32(t_1, 20);
            x_1 = _mm_xor_si128(x_1, t_1);

            x_0 = _mm_add_epi32(x_0, x_1);
            x_3 = _mm_xor_si128(x_3, x_0);
            x_0 = _mm_shuffle_epi32(x_0, 0x93);
            x_3 = _mm_shuffle_epi8(x_3, rot8);

            x_2 = _mm_add_epi32(x_2, x_3);
            x_3 = _mm_shuffle_epi32(x_3, 0x4e);
            x_1 = _mm_xor_si128(x_1, x_2);
            x_2 = _mm_shuffle_epi32(x_2, 0x39);

            t_1 = x_1;
            x_1 = _mm_slli_epi32(x_1, 7);
            t_1 = _mm_srli_epi32(t_1, 25);
            x_1 = _mm_xor_si128(x_1, t_1);

            x_0 = _mm_add_epi32(x_0, x_1);
            x_3 = _mm_xor_si128(x_3, x_0);
            x_3 = _mm_shuffle_epi8(x_3, rot16);

            x_2 = _mm_add_epi32(x_2, x_3);
            x_1 = _mm_xor_si128(x_1, x_2);

            t_1 = x_1;
            x_1 = _mm_slli_epi32(x_1, 12);
            t_1 = _mm_srli_epi32(t_1, 20);
            x_1 = _mm_xor_si128(x_1, t_1);

            x_0 = _mm_add_epi32(x_0, x_1);
            x_3 = _mm_xor_si128(x_3, x_0);
            x_0 = _mm_shuffle_epi32(x_0, 0x39);
            x_3 = _mm_shuffle_epi8(x_3, rot8);

            x_2 = _mm_add_epi32(x_2, x_3);
            x_3 = _mm_shuffle_epi32(x_3, 0x4e);
            x_1 = _mm_xor_si128(x_1, x_2);
            x_2 = _mm_shuffle_epi32(x_2, 0x93);

            t_1 = x_1;
            x_1 = _mm_slli_epi32(x_1, 7);
            t_1 = _mm_srli_epi32(t_1, 25);
            x_1 = _mm_xor_si128(x_1, t_1);
        }
        x_0 = _mm_add_epi32(x_0, _mm_loadu_si128((const __m128i*) (x + 0)));
        x_1 = _mm_add_epi32(x_1, _mm_loadu_si128((const __m128i*) (x + 4)));
        x_2 = _mm_add_epi32(x_2, _mm_loadu_si128((const __m128i*) (x + 8)));
        x_3 = _mm_add_epi32(x_3, _mm_loadu_si128((const __m128i*) (x + 12)));
        _mm_storeu_si128((__m128i*) (partialblock + 0), x_0);
        _mm_storeu_si128((__m128i*) (partialblock + 16), x_1);
        _mm_storeu_si128((__m128i*) (partialblock + 32), x_2);
        _mm_storeu_si128((__m128i*) (partialblock + 48), x_3);

        for (i = 0; i < bytes; i++) {
            c[i] = m[i] ^ partialblock[i];
        }

        RtlSecureZeroMemory(partialblock, sizeof partialblock);
    }
}

static void chacha_keysetup(chacha_ctx* ctx, const unsigned char* k)
{
    ctx->input[0] = 0x61707865;
    ctx->input[1] = 0x3320646e;
    ctx->input[2] = 0x79622d32;
    ctx->input[3] = 0x6b206574;
    ctx->input[4] = LOAD32_LE(k + 0);
    ctx->input[5] = LOAD32_LE(k + 4);
    ctx->input[6] = LOAD32_LE(k + 8);
    ctx->input[7] = LOAD32_LE(k + 12);
    ctx->input[8] = LOAD32_LE(k + 16);
    ctx->input[9] = LOAD32_LE(k + 20);
    ctx->input[10] = LOAD32_LE(k + 24);
    ctx->input[11] = LOAD32_LE(k + 28);
}

static void chacha_ivsetup(chacha_ctx* ctx, const unsigned char* iv, const unsigned char* counter)
{
    ctx->input[12] = counter == NULL ? 0 : LOAD32_LE(counter + 0);
    ctx->input[13] = counter == NULL ? 0 : LOAD32_LE(counter + 4);
    ctx->input[14] = LOAD32_LE(iv + 0);
    ctx->input[15] = LOAD32_LE(iv + 4);
}

int crypto_stream_chacha20_xor_ic(unsigned char* c, const unsigned char* m,
    unsigned long long mlen, const unsigned char* n, UINT64 ic,
    const unsigned char* k)
{
    struct chacha_ctx ctx;
    unsigned char     ic_bytes[8];
    UINT32          ic_high;
    UINT32          ic_low;

    if (!mlen) {
        return 0;
    }
    ic_high = (UINT32)(ic >> 32);
    ic_low = (UINT32)ic;
    STORE32_LE(&ic_bytes[0], ic_low);
    STORE32_LE(&ic_bytes[4], ic_high);
    chacha_keysetup(&ctx, k);
    chacha_ivsetup(&ctx, n, ic_bytes);
    chacha20_encrypt_bytes(&ctx, m, c, mlen);
    RtlSecureZeroMemory(&ctx, sizeof ctx);

    return 0;
}

int crypto_stream_chacha20_xor(unsigned char* c, const unsigned char* m, unsigned long long mlen, const unsigned char* n, const unsigned char* k) {
    crypto_stream_chacha20_xor_ic(c, m, mlen, n, 0u, k);
    return 0;
}

// allows to decrypt (and encrypt, because it's XOR) a specific byte from byte array.
// usage: chacha20_xor_byte(stream[i], i, key, nonce);
unsigned char chacha20_xor_byte(unsigned char encrypted_byte, size_t index, const unsigned char key[crypto_stream_chacha20_KEYBYTES], const unsigned char nonce[crypto_stream_chacha20_NONCEBYTES]) {
    unsigned char keystream_block[BLOCK_SIZE] = { 0 };
    UINT64 block_index = index / BLOCK_SIZE;
    size_t offset = index % BLOCK_SIZE;

    crypto_stream_chacha20_xor_ic(keystream_block, keystream_block, BLOCK_SIZE, nonce, block_index, key);

    return encrypted_byte ^ keystream_block[offset];
}