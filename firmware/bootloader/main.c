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
#include "hsm_flash.h"              /* OPENHSM_STAGE_* / OPENHSM_FWCTL_* layout */
#include "flash_ram.h"             /* RAM-resident bank-1 apply */

#include <stdint.h>
#include <string.h>

typedef struct { uint32_t magic; uint32_t min_version; } rollback_t;
typedef struct { uint32_t magic; uint32_t total_len;   } fwctl_t;

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

/* Blue "boot activity" LED — factory part C131 on the board (PC13). Change here
 * if your board wires the user LED elsewhere. */
#define BLUE_GPIO       GPIOC
#define BLUE_PIN        13u
#define BLUE_CLK_EN()   do { RCC->AHB2ENR1 |= RCC_AHB2ENR1_GPIOCEN; (void)RCC->AHB2ENR1; } while (0)

static void delay(volatile uint32_t n) { while (n--) { __asm volatile("nop"); } }

/* Run sysclk from HSI16 (16 MHz) instead of the 4 MHz MSI reset clock so the
 * signature check finishes ~4x faster. Flash latency is over-provisioned first
 * (safe at any voltage range); the app reconfigures clocks fully on entry. */
static void clock_hsi16(void)
{
    FLASH->ACR = (FLASH->ACR & ~0xFu) | 0x3u;   /* 3 wait states (safe for 16 MHz) */
    (void)FLASH->ACR;
    RCC->CR |= RCC_CR_HSION;
    while (!(RCC->CR & RCC_CR_HSIRDY)) { }
    RCC->CFGR1 = (RCC->CFGR1 & ~RCC_CFGR1_SW) | RCC_CFGR1_SW_0;  /* SW=01: HSI16 */
    while ((RCC->CFGR1 & RCC_CFGR1_SWS) != RCC_CFGR1_SWS_0) { }
    __DSB(); __ISB();
}

static void blue_init(void)
{
    BLUE_CLK_EN();
    BLUE_GPIO->MODER = (BLUE_GPIO->MODER & ~(3u << (BLUE_PIN * 2))) | (1u << (BLUE_PIN * 2)); /* output */
}
static void blue_toggle(void) { BLUE_GPIO->ODR ^= (1u << BLUE_PIN); }
static void blue_release(void)   /* back to analog/high-Z so the LED is off in the app */
{
    BLUE_GPIO->MODER |= (3u << (BLUE_PIN * 2));
}

/* Blink the blue LED forever — verification failed; recovery is BOOT0 + DFU. */
static void fail_halt(void)
{
    blue_init();
    for (;;) {
        blue_toggle();
        delay(300000);                         /* fast continuous blink */
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

/* ---- Secure firmware update: apply a staged image on boot ---------------- */

/* Pending iff the control word has the magic AND a sane staged length. */
static int update_pending(uint32_t *total_len)
{
    const fwctl_t *c = (const fwctl_t *)OPENHSM_FWCTL_ADDR;
    if (c->magic == OPENHSM_FWCTL_MAGIC &&
        c->total_len >= BOOT_HEADER_SIZE &&
        c->total_len <= OPENHSM_STAGE_SIZE &&
        c->total_len <= BOOT_HEADER_SIZE + VERIFY_MAX) {
        *total_len = c->total_len;
        return 1;
    }
    return 0;
}

/* Erase the control page so the update isn't re-applied next boot. */
static void clear_pending(void)
{
    if (HAL_FLASH_Unlock() != HAL_OK) return;
    FLASH_EraseInitTypeDef e = {0};
    e.TypeErase = FLASH_TYPEERASE_PAGES;
    e.Banks     = FLASH_BANK_2;
    e.Page      = OPENHSM_FWCTL_PAGE;
    e.NbPages   = 1;
    uint32_t pe = 0;
    HAL_FLASHEx_Erase(&e, &pe);
    HAL_FLASH_Lock();
}

/* Verify the staged image (bank-2): magic, Ed25519 over version||img_len||app,
 * anti-rollback, and that the staged bytes cover the image. @return 0 if valid. */
static int verify_staged(uint32_t staged_total)
{
    const img_header_t *h   = (const img_header_t *)OPENHSM_STAGE_ADDR;
    const uint8_t      *app = (const uint8_t *)(OPENHSM_STAGE_ADDR + BOOT_HEADER_SIZE);
    if (h->magic != IMG_MAGIC) return -1;
    if (h->img_len == 0 || h->img_len > VERIFY_MAX) return -1;
    if ((uint32_t)BOOT_HEADER_SIZE + h->img_len > staged_total) return -1;
    if (h->version < rollback_min()) return -1;          /* anti-rollback */

    uint32_t v = h->version, n = h->img_len;
    g_msg[0] = (uint8_t)v;  g_msg[1] = (uint8_t)(v >> 8);
    g_msg[2] = (uint8_t)(v >> 16); g_msg[3] = (uint8_t)(v >> 24);
    g_msg[4] = (uint8_t)n;  g_msg[5] = (uint8_t)(n >> 8);
    g_msg[6] = (uint8_t)(n >> 16); g_msg[7] = (uint8_t)(n >> 24);
    memcpy(g_msg + 8, app, n);
    return crypto_ed25519_check(h->sig, openhsm_vendor_pubkey, g_msg, 8u + n) == 0 ? 0 : -1;
}

/* If an update is pending and verifies, program it into the bank-1 app region.
 * The control word is cleared only AFTER programming, so a power loss mid-apply
 * simply retries from the intact bank-2 staging on the next boot. */
static void apply_pending_update(void)
{
    uint32_t total = 0;
    if (!update_pending(&total)) return;
    if (verify_staged(total) != 0) { clear_pending(); return; }   /* bad image → drop */

    const img_header_t *sh = (const img_header_t *)OPENHSM_STAGE_ADDR;
    uint32_t img = (uint32_t)BOOT_HEADER_SIZE + sh->img_len;
    if (flash_apply(BOOT_HEADER_ADDR, OPENHSM_STAGE_ADDR, img) != 0) {
        /* leave pending set → retry next boot */
        return;
    }
    ICACHE->CR |= ICACHE_CR_CACHEINV;            /* no-op if ICACHE off; future-proof */
    while (ICACHE->SR & ICACHE_SR_BUSYF) { }
    __DSB(); __ISB();
    clear_pending();
}

int main(void)
{
    const img_header_t *h   = (const img_header_t *)BOOT_HEADER_ADDR;
    const uint8_t      *app = (const uint8_t *)BOOT_APP_ADDR;

    clock_hsi16();                               /* 4 MHz -> 16 MHz for a fast verify */

    /* "Booting / verifying" — blink the blue LED briefly, then hold it on
     * through the (blocking) signature check. */
    blue_init();
    for (int i = 0; i < 8; i++) { blue_toggle(); delay(300000); }  /* ~0.9 s @16 MHz */
    BLUE_GPIO->ODR |= (1u << BLUE_PIN);          /* solid during verify */

    apply_pending_update();                      /* install a staged USB update, if any */

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

    blue_release();                              /* LED off; app drives its own heartbeat */
    jump_to_app(BOOT_APP_ADDR);
    return 0;                                    /* unreachable */
}
