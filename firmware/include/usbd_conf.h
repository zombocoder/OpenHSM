/**
 * @file    usbd_conf.h
 * @brief   STM32 USB Device Library configuration for OpenHSM.
 *
 * Full-speed vendor-specific device on USB_OTG_FS. A single configuration with
 * one vendor interface exposing EP1 IN/OUT bulk endpoints.
 */
#ifndef USBD_CONF_H
#define USBD_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stm32u5xx.h"
#include "stm32u5xx_hal.h"

/* Common config -------------------------------------------------------------*/
#define USBD_MAX_NUM_INTERFACES        1U
#define USBD_MAX_NUM_CONFIGURATION     1U
#define USBD_MAX_STR_DESC_SIZ          512U
#define USBD_DEBUG_LEVEL               0U
#define USBD_SELF_POWERED              1U
#define USBD_MAX_POWER                 0x32U /* 100 mA */

/* The vendor class keeps its own handle; provide static allocation. */
#define USBD_malloc                    (void *)USBD_static_malloc
#define USBD_free                      USBD_static_free
#define USBD_memset                    memset
#define USBD_memcpy                    memcpy
#define USBD_Delay                     HAL_Delay

/* DEBUG macros --------------------------------------------------------------*/
#if (USBD_DEBUG_LEVEL > 0U)
#define USBD_UsrLog(...)  do { printf(__VA_ARGS__); printf("\n"); } while (0)
#else
#define USBD_UsrLog(...) do {} while (0)
#endif
#if (USBD_DEBUG_LEVEL > 1U)
#define USBD_DbgLog(...)  do { printf("DEBUG : "); printf(__VA_ARGS__); printf("\n"); } while (0)
#else
#define USBD_DbgLog(...) do {} while (0)
#endif
#if (USBD_DEBUG_LEVEL > 2U)
#define USBD_ErrLog(...)  do { printf("ERROR : "); printf(__VA_ARGS__); printf("\n"); } while (0)
#else
#define USBD_ErrLog(...) do {} while (0)
#endif

void *USBD_static_malloc(uint32_t size);
void  USBD_static_free(void *p);

#ifdef __cplusplus
}
#endif

#endif /* USBD_CONF_H */
