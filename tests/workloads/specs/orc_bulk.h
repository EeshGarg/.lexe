/* orc_bulk.h -- shared machinery for the output-VOLUME specimens.
 *
 * Why this exists separately from oracle.h: oracle.h is included by every
 * specimen in the corpus, and its sha256 is recorded once in the index as
 * `source.oracle_header_sha256`. Adding 150 lines of SHA-256 to it would churn
 * that digest for 112 specimens that will never call it. Only the bulk
 * specimens include this.
 *
 * Two things live here:
 *
 *   1. A deterministic byte source (xorshift64, fixed seed). The same offset in
 *      the stream always holds the same byte, on every host and at every
 *      optimisation level, because every operation is on an explicitly-sized
 *      unsigned type. That is what makes "4 MiB" and "256 MiB" the same
 *      specimen at two sizes rather than two unrelated blobs.
 *
 *   2. SHA-256, so a specimen can ATTEST to a stream it does not keep. FNV-1a
 *      (in oracle.h) is enough for 8 MiB but the consumer has to recompute it
 *      one byte at a time in Python; at 256 MiB that is minutes of pointless
 *      CPU. A SHA-256 claim is verified by hashlib at C speed on the other
 *      side, and the corpus index already records a SHA-256 of every captured
 *      stream, so the specimen's claim and the runner's observation are
 *      directly comparable.
 *
 * Nothing here writes anything. A specimen decides what goes to which fd.
 */
#ifndef LEXE_ORC_BULK_H
#define LEXE_ORC_BULK_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define ORB_UNUSED __attribute__((unused))

/* ---- deterministic byte source ---------------------------------------- */

/* xorshift64. Seeded with the golden-ratio constant so the seed is visibly not
 * chosen to make any particular result come out. */
#define ORB_SEED 0x9E3779B97F4A7C15ULL

typedef struct { uint64_t x; } orb_rng;

ORB_UNUSED static void orb_rng_init(orb_rng *r) { r->x = ORB_SEED; }

ORB_UNUSED static uint8_t orb_rng_byte(orb_rng *r) {
    uint64_t x = r->x;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    r->x = x;
    return (uint8_t)(x & 0xffu);
}

ORB_UNUSED static void orb_fill(orb_rng *r, uint8_t *buf, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) buf[i] = orb_rng_byte(r);
}

/* ---- SHA-256 ----------------------------------------------------------- */

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   used;
} orb_sha256;

static const uint32_t ORB_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ORB_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

ORB_UNUSED static void orb_sha256_block(orb_sha256 *s, const uint8_t *p) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16)
             | ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ORB_ROR(w[i - 15], 7) ^ ORB_ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ORB_ROR(w[i - 2], 17) ^ ORB_ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ORB_ROR(e, 6) ^ ORB_ROR(e, 11) ^ ORB_ROR(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t S0 = ORB_ROR(a, 2) ^ ORB_ROR(a, 13) ^ ORB_ROR(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        t1 = h + S1 + ch + ORB_K[i] + w[i];
        t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

ORB_UNUSED static void orb_sha256_init(orb_sha256 *s) {
    s->h[0] = 0x6a09e667u; s->h[1] = 0xbb67ae85u;
    s->h[2] = 0x3c6ef372u; s->h[3] = 0xa54ff53au;
    s->h[4] = 0x510e527fu; s->h[5] = 0x9b05688cu;
    s->h[6] = 0x1f83d9abu; s->h[7] = 0x5be0cd19u;
    s->bits = 0;
    s->used = 0;
}

ORB_UNUSED static void orb_sha256_update(orb_sha256 *s, const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    s->bits += (uint64_t)n * 8u;
    if (s->used) {
        size_t want = 64 - s->used;
        if (want > n) want = n;
        memcpy(s->buf + s->used, p, want);
        s->used += want; p += want; n -= want;
        if (s->used == 64) { orb_sha256_block(s, s->buf); s->used = 0; }
    }
    while (n >= 64) { orb_sha256_block(s, p); p += 64; n -= 64; }
    if (n) { memcpy(s->buf, p, n); s->used = n; }
}

/* Writes 64 hex characters plus a NUL into `hex`. */
ORB_UNUSED static void orb_sha256_final(orb_sha256 *s, char *hex) {
    static const char digits[] = "0123456789abcdef";
    uint8_t pad[72];
    size_t padlen;
    uint64_t bits = s->bits;
    int i;
    memset(pad, 0, sizeof pad);
    pad[0] = 0x80;
    padlen = (s->used < 56) ? (56 - s->used) : (120 - s->used);
    if (padlen == 0) padlen = 64;
    orb_sha256_update(s, pad, padlen);
    s->bits = bits; /* update() above must not count the padding */
    for (i = 7; i >= 0; i--) pad[7 - i] = (uint8_t)((bits >> (i * 8)) & 0xffu);
    orb_sha256_update(s, pad, 8);
    for (i = 0; i < 8; i++) {
        uint32_t v = s->h[i];
        hex[i * 8 + 0] = digits[(v >> 28) & 0xf];
        hex[i * 8 + 1] = digits[(v >> 24) & 0xf];
        hex[i * 8 + 2] = digits[(v >> 20) & 0xf];
        hex[i * 8 + 3] = digits[(v >> 16) & 0xf];
        hex[i * 8 + 4] = digits[(v >> 12) & 0xf];
        hex[i * 8 + 5] = digits[(v >> 8) & 0xf];
        hex[i * 8 + 6] = digits[(v >> 4) & 0xf];
        hex[i * 8 + 7] = digits[v & 0xf];
    }
    hex[64] = '\0';
}

/* ---- writing without stdio ------------------------------------------- */

/* A full write to a raw fd, retrying short writes. Bulk specimens bypass stdio
 * deliberately: the property under test is what reaches the other end of the
 * pipe and in what order, and a 4 KiB stdio buffer is free to reorder the
 * interleaving of two streams that a deadlock test depends on. Returns 0 on
 * success, -1 on a write error. */
ORB_UNUSED static int orb_write_all(int fd, const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}

#endif /* LEXE_ORC_BULK_H */
