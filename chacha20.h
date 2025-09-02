#pragma once
#include <ntifs.h>
#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>

// https://github.com/jedisct1/libsodium/tree/master/src/libsodium/crypto_stream/chacha20

// libsodium chacha20 port for WDK by @Unbonkable, horrible stuff...
// I DID NOT make all of this, i just made it so you can use it in Windows kernel
// only "crypto_stream_chacha20_xor_ic" and "crypto_stream_chacha20_xor" are ported, since these are the only ones i needed.
// dont even try to understand this shit, i promise you'll most likely just waste your time

#define ROUNDS 20
#define BLOCK_SIZE 64

#define crypto_stream_chacha20_KEYBYTES 32
#define crypto_stream_chacha20_NONCEBYTES 8

typedef struct chacha_ctx {
    UINT32 input[16];
} chacha_ctx;

#define LOAD32_LE(SRC) load32_le(SRC)
static inline UINT32 load32_le(const unsigned char src[4]) {
    UINT32 w;
    memcpy(&w, src, sizeof w);
    return w;
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void store32_le(unsigned char dst[4], UINT32 w) {
    memcpy(dst, &w, sizeof w);
}

#ifdef _MSC_VER // if Visual C/C++
__inline __m64 _mm_set_pi64x(const __int64 i) {
    union {
        __int64 i;
        __m64 v;
    } u;

    u.i = i;
    return u.v;
}
#endif

// all of that is just a really wonky way of doing this, i feel like this is really bad, but oh well, it works the same

// _mm_set1_epi64 (__m64 a)
inline __m128i mm_set1_epi64(__m64 a) {
    __m128i tmp = _mm_setzero_si128();
    tmp = _mm_unpacklo_epi64(_mm_cvtsi64_si128(*reinterpret_cast<long long*>(&a)),
        _mm_cvtsi64_si128(*reinterpret_cast<long long*>(&a)));
    return tmp;
}

// _mm_set_epi64 (__m64 e1, __m64 e0)
inline __m128i mm_set_epi64(__m64 e1, __m64 e0) {
    return _mm_unpacklo_epi64(_mm_cvtsi64_si128(*reinterpret_cast<long long*>(&e0)),
        _mm_cvtsi64_si128(*reinterpret_cast<long long*>(&e1)));
}

#define _mm_set1_epi64x(a) mm_set1_epi64(_mm_set_pi64x(a))
#define _mm_set_epi64x(m0, m1) mm_set_epi64(_mm_set_pi64x(m0), _mm_set_pi64x(m1))


int crypto_stream_chacha20_xor_ic(unsigned char* c, const unsigned char* m, unsigned long long mlen, const unsigned char* n, UINT64 ic, const unsigned char* k);
int crypto_stream_chacha20_xor(unsigned char* c, const unsigned char* m, unsigned long long mlen, const unsigned char* n, const unsigned char* k);

unsigned char chacha20_xor_byte(unsigned char encrypted_byte, size_t index, const unsigned char key[crypto_stream_chacha20_KEYBYTES], const unsigned char nonce[crypto_stream_chacha20_NONCEBYTES]);