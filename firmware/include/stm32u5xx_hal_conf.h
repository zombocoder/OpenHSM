/**
 * @file    stm32u5xx_hal_conf.h
 * @brief   HAL configuration for OpenHSM firmware (STM32U585CIU6).
 *
 * Trimmed configuration: only the HAL modules actually used by the firmware
 * are enabled. Add modules here as the HSM feature set grows (RNG, PKA, CRYP,
 * AES, FLASH for secure storage, etc.).
 */
#ifndef STM32U5xx_HAL_CONF_H
#define STM32U5xx_HAL_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

/* ########################## Module Selection ############################## */
#define HAL_MODULE_ENABLED
#define HAL_CORTEX_MODULE_ENABLED
#define HAL_CRYP_MODULE_ENABLED
#define HAL_DMA_MODULE_ENABLED
#define HAL_EXTI_MODULE_ENABLED
#define HAL_FLASH_MODULE_ENABLED
#define HAL_GPIO_MODULE_ENABLED
#define HAL_HASH_MODULE_ENABLED
#define HAL_PCD_MODULE_ENABLED
#define HAL_PWR_MODULE_ENABLED
#define HAL_RCC_MODULE_ENABLED
#define HAL_RNG_MODULE_ENABLED

/* ########################## Oscillator Values ############################ */
#if !defined(HSE_VALUE)
#define HSE_VALUE            16000000UL
#endif
#if !defined(HSE_STARTUP_TIMEOUT)
#define HSE_STARTUP_TIMEOUT  100UL
#endif
#if !defined(MSI_VALUE)
#define MSI_VALUE            4000000UL
#endif
#if !defined(HSI_VALUE)
#define HSI_VALUE            16000000UL
#endif
#if !defined(HSI48_VALUE)
#define HSI48_VALUE          48000000UL
#endif
#if !defined(LSI_VALUE)
#define LSI_VALUE            32000UL
#endif
#if !defined(LSE_VALUE)
#define LSE_VALUE            32768UL
#endif
#if !defined(LSE_STARTUP_TIMEOUT)
#define LSE_STARTUP_TIMEOUT  5000UL
#endif
#if !defined(EXTERNAL_SAI1_CLOCK_VALUE)
#define EXTERNAL_SAI1_CLOCK_VALUE  48000UL
#endif
#if !defined(EXTERNAL_SAI2_CLOCK_VALUE)
#define EXTERNAL_SAI2_CLOCK_VALUE  48000UL
#endif

/* ########################### System Configuration ######################## */
#define VDD_VALUE                    3300UL
#define TICK_INT_PRIORITY            0U
#define USE_RTOS                     0U
#define PREFETCH_ENABLE              0U

#define USE_HAL_PCD_REGISTER_CALLBACKS 0U

/* ########################## Assert Selection ############################# */
/* #define USE_FULL_ASSERT    1U */

/* ################## Register callback feature toggles ################### */
#define USE_HAL_ADC_REGISTER_CALLBACKS        0U
#define USE_HAL_CRYP_REGISTER_CALLBACKS       0U
#define USE_HAL_RNG_REGISTER_CALLBACKS        0U

/* ########################## Includes ##################################### */
#ifdef HAL_RCC_MODULE_ENABLED
#include "stm32u5xx_hal_rcc.h"
#endif
#ifdef HAL_GPIO_MODULE_ENABLED
#include "stm32u5xx_hal_gpio.h"
#endif
#ifdef HAL_DMA_MODULE_ENABLED
#include "stm32u5xx_hal_dma.h"
#endif
#ifdef HAL_CORTEX_MODULE_ENABLED
#include "stm32u5xx_hal_cortex.h"
#endif
#ifdef HAL_EXTI_MODULE_ENABLED
#include "stm32u5xx_hal_exti.h"
#endif
#ifdef HAL_FLASH_MODULE_ENABLED
#include "stm32u5xx_hal_flash.h"
#endif
#ifdef HAL_PWR_MODULE_ENABLED
#include "stm32u5xx_hal_pwr.h"
#endif
#ifdef HAL_PCD_MODULE_ENABLED
#include "stm32u5xx_hal_pcd.h"
#endif
#ifdef HAL_RNG_MODULE_ENABLED
#include "stm32u5xx_hal_rng.h"
#endif
#ifdef HAL_CRYP_MODULE_ENABLED
#include "stm32u5xx_hal_cryp.h"
#endif
#ifdef HAL_HASH_MODULE_ENABLED
#include "stm32u5xx_hal_hash.h"
#endif

/* ########################## Assert Macro ################################ */
#ifdef USE_FULL_ASSERT
#define assert_param(expr) ((expr) ? (void)0U : assert_failed((uint8_t *)__FILE__, __LINE__))
void assert_failed(uint8_t *file, uint32_t line);
#else
#define assert_param(expr) ((void)0U)
#endif

#ifdef __cplusplus
}
#endif

#endif /* STM32U5xx_HAL_CONF_H */
