/**
 * @file    hsm_hash.c
 * @brief   SHA-256 / HMAC-SHA256 / HKDF-SHA256 — software (FIPS 180-4 / RFC).
 *
 * Deliberately software, not the STM32 HASH peripheral: the HW block's
 * partial-final-word handling proved unreliable for byte lengths that are not
 * a multiple of 4 (it corrupted HMAC results and left the peripheral in a bad
 * state, which in turn made the KEK non-reproducible across boots). A compact
 * software SHA-256 is correct for any length and fast enough for the occasional
 * HKDF/HMAC an HSM performs. AES-GCM and the TRNG remain on hardware.
 */
#include "hsm_hash.h"

#include <string.h>

/* ---- SHA-256 core (FIPS 180-4) ------------------------------------------- */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_init(sha256_ctx *c)
{
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
    c->bitlen = 0;
    c->buflen = 0;
}

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i-15],7) ^ ROTR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR(w[i-2],17) ^ ROTR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len)
{
    c->bitlen += (uint64_t)len * 8u;
    while (len > 0) {
        size_t n = 64 - c->buflen;
        if (n > len) n = len;
        memcpy(c->buf + c->buflen, data, n);
        c->buflen += n; data += n; len -= n;
        if (c->buflen == 64) { sha256_block(c, c->buf); c->buflen = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->bitlen;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56) sha256_update(c, &zero, 1);
    uint8_t lenbe[8];
    for (int i = 0; i < 8; i++) lenbe[i] = (uint8_t)(bits >> (56 - 8*i));
    /* feed length without re-counting it into bitlen */
    memcpy(c->buf + c->buflen, lenbe, 8);
    sha256_block(c, c->buf);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->state[i] >> 24);
        out[i*4+1] = (uint8_t)(c->state[i] >> 16);
        out[i*4+2] = (uint8_t)(c->state[i] >> 8);
        out[i*4+3] = (uint8_t)(c->state[i]);
    }
}

/* ---- Public API ---------------------------------------------------------- */

int HSM_Sha256(const uint8_t *data, size_t len, uint8_t out[HSM_SHA256_LEN])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
    return 0;
}

int HSM_HmacSha256(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[HSM_SHA256_LEN])
{
    uint8_t k0[64];
    uint8_t ipad[64], opad[64];
    uint8_t inner[HSM_SHA256_LEN];
    sha256_ctx c;

    memset(k0, 0, sizeof(k0));
    if (key_len > 64) {
        HSM_Sha256(key, key_len, k0);   /* K0 = H(key) padded with zeros */
    } else {
        memcpy(k0, key, key_len);
    }
    for (int i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }

    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, data, data_len);
    sha256_final(&c, inner);

    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, sizeof(inner));
    sha256_final(&c, out);

    memset(k0, 0, sizeof(k0));
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    return 0;
}

int HSM_HkdfExtract(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    uint8_t prk[HSM_SHA256_LEN])
{
    static const uint8_t zero_salt[HSM_SHA256_LEN] = {0};
    if (salt == NULL || salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    return HSM_HmacSha256(salt, salt_len, ikm, ikm_len, prk);
}

int HSM_HkdfSha256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *out, size_t out_len)
{
    uint8_t prk[HSM_SHA256_LEN];
    if (HSM_HkdfExtract(salt, salt_len, ikm, ikm_len, prk) != 0) {
        return -1;
    }

    uint8_t t[HSM_SHA256_LEN];
    uint8_t block[HSM_SHA256_LEN + 256 + 1];
    size_t  t_len = 0;
    size_t  done = 0;
    uint8_t counter = 1;

    if (info_len > 256) {
        return -1;
    }

    while (done < out_len) {
        size_t off = 0;
        memcpy(block + off, t, t_len); off += t_len;
        if (info_len) { memcpy(block + off, info, info_len); off += info_len; }
        block[off++] = counter;

        if (HSM_HmacSha256(prk, sizeof(prk), block, off, t) != 0) {
            return -1;
        }
        t_len = HSM_SHA256_LEN;

        size_t chunk = (out_len - done) < HSM_SHA256_LEN ? (out_len - done)
                                                         : HSM_SHA256_LEN;
        memcpy(out + done, t, chunk);
        done += chunk;
        counter++;
    }
    return 0;
}
