/**
 * @file    bootloader/main.c
 * @brief   OpenHSM stage-1 secure bootloader.
 *
 * Runs from 0x08000000 on the 4 MHz MSI reset clock (no HAL/clock/USB init).
 * Verifies the Ed25519 signature over the application image against the baked-in
 * vendor public key, then jumps to the app at 0x08012000. On any failure it
 * blinks the LED and halts — recovery is via BOOT0 + DFU (the ST ROM bootloader
 * rewrites bank 1; we touch no option bytes, so the board can't be bricked here).
 *
 * Ed25519 verify is one-shot, so the signed message — u32le(version) ||
 * u32le(img_len) || app_bytes — is assembled in a RAM buffer (the app is small;
 * RAM is 768 KB).
 */
#include "stm32u5xx_hal.h"          /* device regs + CMSIS core + HAL_FLASH (anti-rollback) */
#include "image_header.h"
#include "vendor_pubkey.h"
#include "monocypher-ed25519.h"

#include <stdint.h>
#include <string.h>

typedef struct { uint32_t magic; uint32_t min_version; } rollback_t;

/* Highest version accepted so far (0 if the counter page is blank). */
static uint32_t rollback_min(void)
{
    const rollback_t *rb = (const rollback_t *)ROLLBACK_ADDR;
    return (rb->magic == ROLLBACK_MAGIC) ? rb->min_version : 0u;
}

/* Persist a new minimum version (one erase + one quad-word program). */
static void rollback_bump(uint32_t version)
{
    static __attribute__((aligned(16))) uint8_t qw[16];
    memset(qw, 0xFF, sizeof(qw));
    ((uint32_t *)qw)[0] = ROLLBACK_MAGIC;
    ((uint32_t *)qw)[1] = version;

    if (HAL_FLASH_Unlock() != HAL_OK) return;
    FLASH_EraseInitTypeDef e = {0};
    e.TypeErase = FLASH_TYPEERASE_PAGES;
    e.Banks     = FLASH_BANK_2;
    e.Page      = ROLLBACK_PAGE;
    e.NbPages   = 1;
    uint32_t pe = 0;
    if (HAL_FLASHEx_Erase(&e, &pe) == HAL_OK) {
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, ROLLBACK_ADDR, (uint32_t)(uintptr_t)qw);
    }
    HAL_FLASH_Lock();
}

/* Largest app the bootloader will verify (RAM-bounded; firmware is far smaller). */
#define VERIFY_MAX  0x60000u       /* 384 KB */

static uint8_t g_msg[8 + VERIFY_MAX];

static void delay(volatile uint32_t n) { while (n--) { __asm volatile("nop"); } }

/* Blink PA1 forever (direct registers; the LED on this board is PA1). */
static void fail_halt(void)
{
    RCC->AHB2ENR1 |= RCC_AHB2ENR1_GPIOAEN;
    (void)RCC->AHB2ENR1;                       /* sync */
    GPIOA->MODER = (GPIOA->MODER & ~(3u << (1u * 2))) | (1u << (1u * 2)); /* PA1 = output */
    for (;;) {
        GPIOA->ODR ^= (1u << 1);
        delay(300000);                         /* ~fast blink at 4 MHz */
    }
}

static void jump_to_app(uint32_t app_base)
{
    const uint32_t *vec = (const uint32_t *)app_base;
    uint32_t app_msp = vec[0];
    uint32_t app_pc  = vec[1];

    __disable_irq();
    SysTick->CTRL = 0;                          /* stop any tick (none started) */
    SysTick->LOAD = 0;
    SysTick->VAL  = 0;
    SCB->VTOR = app_base;                        /* app's SystemInit also sets it */
    __DSB();
    __set_MSP(app_msp);
    __set_CONTROL(0);                            /* MSP, privileged — reset state */
    __ISB();
    __enable_irq();                              /* app inherits enabled IRQs from reset */
    ((void (*)(void))app_pc)();
    for (;;) { }                                 /* unreachable */
}

int main(void)
{
    const img_header_t *h   = (const img_header_t *)BOOT_HEADER_ADDR;
    const uint8_t      *app = (const uint8_t *)BOOT_APP_ADDR;

    if (h->magic != IMG_MAGIC) fail_halt();
    if (h->img_len == 0 || h->img_len > VERIFY_MAX) fail_halt();
    if (h->version < rollback_min()) fail_halt();   /* anti-rollback */

    /* message = u32le(version) || u32le(img_len) || app[] */
    uint32_t v = h->version, n = h->img_len;
    g_msg[0] = (uint8_t)v;  g_msg[1] = (uint8_t)(v >> 8);
    g_msg[2] = (uint8_t)(v >> 16); g_msg[3] = (uint8_t)(v >> 24);
    g_msg[4] = (uint8_t)n;  g_msg[5] = (uint8_t)(n >> 8);
    g_msg[6] = (uint8_t)(n >> 16); g_msg[7] = (uint8_t)(n >> 24);
    memcpy(g_msg + 8, app, n);

    if (crypto_ed25519_check(h->sig, openhsm_vendor_pubkey, g_msg, 8u + n) != 0)
        fail_halt();                             /* bad / wrong-key signature */

    if (h->version > rollback_min())             /* monotonic high-water bump */
        rollback_bump(h->version);

    jump_to_app(BOOT_APP_ADDR);
    return 0;                                    /* unreachable */
}
