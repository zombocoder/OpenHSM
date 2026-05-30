/**
 * @file    hsm_x25519.c
 * @brief   X25519 ECDH via Monocypher.
 */
#include "hsm_x25519.h"
#include "monocypher.h"

#include <string.h>

void HSM_X25519_PublicKey(uint8_t public_key[HSM_X25519_LEN],
                          const uint8_t secret_key[HSM_X25519_LEN])
{
    crypto_x25519_public_key(public_key, secret_key);
}

int HSM_X25519_Shared(uint8_t shared[HSM_X25519_LEN],
                      const uint8_t secret_key[HSM_X25519_LEN],
                      const uint8_t their_public[HSM_X25519_LEN])
{
    crypto_x25519(shared, secret_key, their_public);

    /* Reject the all-zero shared secret (contributory behaviour / low-order
     * point check), constant-time. */
    uint8_t acc = 0;
    for (unsigned i = 0; i < HSM_X25519_LEN; i++) {
        acc |= shared[i];
    }
    return (acc == 0) ? -1 : 0;
}
