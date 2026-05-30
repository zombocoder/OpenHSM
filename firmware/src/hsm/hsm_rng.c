/**
 * @file    hsm_rng.c
 * @brief   Hardware TRNG access for OpenHSM.
 *
 * Uses the STM32U585 RNG peripheral, clocked from HSI48. Generates 32-bit
 * words and copies them out byte-wise so callers get arbitrary lengths.
 */
#include "hsm_rng.h"
#include "main.h"

static RNG_HandleTypeDef hrng;

void HSM_Rng_Init(void)
{
    RCC_PeriphCLKInitTypeDef periph = {0};

    /* RNG requires a 48 MHz clock; source it from HSI48 (already enabled). */
    periph.PeriphClockSelection = RCC_PERIPHCLK_RNG;
    periph.RngClockSelection    = RCC_RNGCLKSOURCE_HSI48;
    if (HAL_RCCEx_PeriphCLKConfig(&periph) != HAL_OK) {
        Error_Handler();
    }

    __HAL_RCC_RNG_CLK_ENABLE();

    hrng.Instance = RNG;
    if (HAL_RNG_Init(&hrng) != HAL_OK) {
        Error_Handler();
    }
}

int HSM_Rng_Fill(uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        uint32_t word;
        if (HAL_RNG_GenerateRandomNumber(&hrng, &word) != HAL_OK) {
            return -1;
        }
        size_t chunk = (len - off) < 4 ? (len - off) : 4;
        for (size_t i = 0; i < chunk; i++) {
            buf[off + i] = (uint8_t)(word >> (8 * i));
        }
        off += chunk;
    }
    return 0;
}
