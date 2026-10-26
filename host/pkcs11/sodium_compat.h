/**
 * @file    sodium_compat.h
 * @brief   HKDF-SHA256 for libsodium < 1.0.19.
 *
 * crypto_kdf_hkdf_sha256_* first shipped in libsodium 1.0.19, but Debian
 * (bookworm, trixie), Ubuntu 24.04 and EPEL still package 1.0.18. On those this
 * header supplies the same two calls as RFC 5869 over HMAC-SHA256; on a newer
 * libsodium it is a no-op. Include it after <sodium.h>.
 */
#ifndef OPENHSM_SODIUM_COMPAT_H
#define OPENHSM_SODIUM_COMPAT_H

#include <sodium.h>
#include <string.h>

#ifndef crypto_kdf_hkdf_sha256_KEYBYTES
#define crypto_kdf_hkdf_sha256_KEYBYTES crypto_auth_hmacsha256_BYTES

static inline int crypto_kdf_hkdf_sha256_extract(
    unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES],
    const unsigned char *salt, size_t salt_len,
    const unsigned char *ikm, size_t ikm_len)
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt, salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    return crypto_auth_hmacsha256_final(&st, prk);
}

static inline int crypto_kdf_hkdf_sha256_expand(
    unsigned char *out, size_t out_len, const char *ctx, size_t ctx_len,
    const unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES])
{
    unsigned char t[crypto_auth_hmacsha256_BYTES];
    if (out_len > 255 * sizeof(t)) return -1;
    for (size_t done = 0, n; done < out_len; done += n) {
        unsigned char i = (unsigned char)(done / sizeof(t) + 1);
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk, crypto_kdf_hkdf_sha256_KEYBYTES);
        if (i > 1) crypto_auth_hmacsha256_update(&st, t, sizeof(t));
        crypto_auth_hmacsha256_update(&st, (const unsigned char *)ctx, ctx_len);
        crypto_auth_hmacsha256_update(&st, &i, 1);
        crypto_auth_hmacsha256_final(&st, t);
        n = out_len - done < sizeof(t) ? out_len - done : sizeof(t);
        memcpy(out + done, t, n);
    }
    sodium_memzero(t, sizeof(t));
    return 0;
}
#endif

#endif /* OPENHSM_SODIUM_COMPAT_H */
