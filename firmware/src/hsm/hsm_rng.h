/**
 * @file    hsm_rng.h
 * @brief   Hardware TRNG access for OpenHSM (STM32U585 RNG peripheral).
 */
#ifndef OPENHSM_HSM_RNG_H
#define OPENHSM_HSM_RNG_H

#include <stdint.h>
#include <stddef.h>

/** @brief Initialize the RNG peripheral and its 48 MHz clock source. */
void HSM_Rng_Init(void);

/**
 * @brief Fill a buffer with hardware-generated random bytes.
 * @return 0 on success, non-zero on RNG error (seed/clock fault).
 */
int HSM_Rng_Fill(uint8_t *buf, size_t len);

#endif /* OPENHSM_HSM_RNG_H */
