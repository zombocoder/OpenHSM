/**
 * @file    stm32u5xx_it.c
 * @brief   Interrupt service routines for OpenHSM firmware.
 *
 * Cortex-M fault handlers are left as the startup file's default (infinite
 * loop) for now; only the handlers the firmware actively needs are defined.
 */
#include "main.h"

extern PCD_HandleTypeDef hpcd_USB_OTG_FS;

/* 1 ms tick for the HAL time base. */
void SysTick_Handler(void)
{
    HAL_IncTick();
}

/* USB OTG FS global interrupt. */
void OTG_FS_IRQHandler(void)
{
    HAL_PCD_IRQHandler(&hpcd_USB_OTG_FS);
}

/* Programmable Voltage Detector / Peripheral Voltage Monitor (brownout tamper).
 * HAL clears the EXTI flag and invokes HAL_PWR_PVDCallback() (see main.c). */
void PVD_PVM_IRQHandler(void)
{
    HAL_PWR_PVD_IRQHandler();
}
