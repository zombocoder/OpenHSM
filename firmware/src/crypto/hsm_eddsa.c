/**
 * @file    hsm_eddsa.c
 * @brief   Ed25519 signing via Monocypher's RFC 8032 (SHA-512) variant.
 */
#include "hsm_eddsa.h"
#include "monocypher-ed25519.h"

#include <string.h>

void HSM_Ed25519_Public(const uint8_t seed[HSM_ED25519_SEED_LEN],
                        uint8_t pub[HSM_ED25519_PUB_LEN])
{
    uint8_t sk[64];
    uint8_t seed_copy[HSM_ED25519_SEED_LEN];
    memcpy(seed_copy, seed, HSM_ED25519_SEED_LEN); /* key_pair may wipe seed */
    crypto_ed25519_key_pair(sk, pub, seed_copy);
    crypto_wipe(sk, sizeof(sk));
    crypto_wipe(seed_copy, sizeof(seed_copy));
}

void HSM_Ed25519_Sign(const uint8_t seed[HSM_ED25519_SEED_LEN],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t sig[HSM_ED25519_SIG_LEN])
{
    uint8_t sk[64], pub[32];
    uint8_t seed_copy[HSM_ED25519_SEED_LEN];
    memcpy(seed_copy, seed, HSM_ED25519_SEED_LEN);
    crypto_ed25519_key_pair(sk, pub, seed_copy);
    crypto_ed25519_sign(sig, sk, msg, msg_len);
    crypto_wipe(sk, sizeof(sk));
    crypto_wipe(seed_copy, sizeof(seed_copy));
}
