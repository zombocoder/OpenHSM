/**
 * @file    hsm_crypto.h
 * @brief   Crypto subsystem init + power-on self-test (KAT) for OpenHSM.
 */
#ifndef OPENHSM_HSM_CRYPTO_H
#define OPENHSM_HSM_CRYPTO_H

#include <stdint.h>
#include "hsm_proto.h"  /* hsm_selftest_t (wire struct) */

/** @brief Enable AES + HASH peripheral clocks. Call once at boot. */
void HSM_Crypto_Init(void);

/**
 * @brief Run known-answer tests for all crypto primitives.
 * @return 0 if all pass; fills @p out with per-primitive results.
 */
int HSM_Crypto_SelfTest(hsm_selftest_t *out);

#endif /* OPENHSM_HSM_CRYPTO_H */
