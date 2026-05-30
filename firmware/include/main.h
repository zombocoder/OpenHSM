/**
 * @file    main.h
 * @brief   Common declarations for OpenHSM firmware.
 */
#ifndef MAIN_H
#define MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stm32u5xx_hal.h"

/* Heartbeat LED — ADJUST TO YOUR BOARD.
 * The STM32U585 Mini Core Board user-LED pin varies by vendor; override with
 * -DOPENHSM_LED_PORT / -DOPENHSM_LED_PIN at configure time if it differs.
 * A wrong pin only toggles an unused GPIO and is otherwise harmless. */
#ifndef OPENHSM_LED_PORT
#define OPENHSM_LED_PORT GPIOA
#endif
#ifndef OPENHSM_LED_PIN
#define OPENHSM_LED_PIN  GPIO_PIN_1
#endif
#define OPENHSM_LED_RCC_ENABLE() __HAL_RCC_GPIOA_CLK_ENABLE()

void SystemClock_Config(void);
void Error_Handler(void);

#ifdef __cplusplus
}
#endif

#endif /* MAIN_H */
