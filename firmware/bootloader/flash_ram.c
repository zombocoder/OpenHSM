/**
 * @file    flash_ram.c
 * @brief   RAM-resident bank-1 flash erase+program for the firmware-update apply.
 *
 * The bootloader executes from bank 1, so reprogramming the bank-1 app region
 * must run from RAM (read-while-write is cross-bank only). This routine is placed
 * in .ramfunc and MUST be fully self-contained: no HAL, no libc/memcpy, no
 * .rodata, no calls into bank 1. Reading the source (bank 2 staging) while
 * writing bank 1 is the supported cross-bank case. Compile this TU with
 * -fno-builtin -fno-tree-loop-distribute-patterns -mlong-calls; verify with
 * objdump that flash_apply has no 0x0800xxxx branch / __aeabi_* / memcpy refs.
 */
#include "flash_ram.h"
#include "stm32u585xx.h"   /* register addresses + __disable_irq/__DSB/__ISB (inline) */

#define FLASH_NS_BASE_ADDR  0x40022000u
#define NSKEYR_OFF          0x08u
#define NSSR_OFF            0x20u
#define NSCR_OFF            0x28u

#define KEY1                0x45670123u
#define KEY2                0xCDEF89ABu

#define NSCR_PG             (1u << 0)
#define NSCR_PER            (1u << 1)
#define NSCR_PNB_POS        3u
#define NSCR_BKER           (1u << 11)
#define NSCR_STRT           (1u << 16)
#define NSCR_LOCK           (1u << 31)

#define NSSR_BSY            (1u << 16)
#define NSSR_WDW            (1u << 17)
#define NSSR_ERR_MASK       ((1u<<1)|(1u<<3)|(1u<<4)|(1u<<5)|(1u<<6)|(1u<<7))
#define NSSR_CLEAR_ALL      (NSSR_ERR_MASK | (1u<<0))   /* + EOP, write-1-to-clear */

#define FLASH_MEM_BASE      0x08000000u
#define PAGE_SHIFT          13u                          /* 8 KB pages */
#define APP_REGION_BASE     0x08010000u                  /* header page (page 8) */
#define BANK2_BASE          0x08100000u

__attribute__((section(".ramfunc"), noinline, long_call))
uint32_t flash_apply(uint32_t dst, uint32_t src, uint32_t total)
{
    volatile uint32_t *NSKEYR = (volatile uint32_t *)(FLASH_NS_BASE_ADDR + NSKEYR_OFF);
    volatile uint32_t *NSSR   = (volatile uint32_t *)(FLASH_NS_BASE_ADDR + NSSR_OFF);
    volatile uint32_t *NSCR   = (volatile uint32_t *)(FLASH_NS_BASE_ADDR + NSCR_OFF);

    uint32_t bytes  = (total + 15u) & ~15u;              /* whole quad-words */
    uint32_t nwords = bytes >> 2;
    uint32_t end    = dst + bytes;

    /* Guard: only ever the app region (pages 8..), never the bootloader (0..7). */
    if (dst != APP_REGION_BASE || end > BANK2_BASE || bytes == 0u) return 0xFFFFFFFFu;

    uint32_t first_page = (dst - FLASH_MEM_BASE) >> PAGE_SHIFT;
    uint32_t last_page  = (end - 1u - FLASH_MEM_BASE) >> PAGE_SHIFT;

    __disable_irq();
    __DSB(); __ISB();

    while (*NSSR & (NSSR_BSY | NSSR_WDW)) { }
    if (*NSCR & NSCR_LOCK) { *NSKEYR = KEY1; *NSKEYR = KEY2; }

    /* Erase bank-1 pages [first_page .. last_page] (BKER = 0). */
    for (uint32_t p = first_page; p <= last_page; p++) {
        *NSSR = NSSR_CLEAR_ALL;
        uint32_t cr = *NSCR & ~((0x7Fu << NSCR_PNB_POS) | NSCR_BKER);
        cr |= NSCR_PER | (p << NSCR_PNB_POS);
        *NSCR = cr;
        *NSCR = cr | NSCR_STRT;
        while (*NSSR & (NSSR_BSY | NSSR_WDW)) { }
        uint32_t e = *NSSR & NSSR_ERR_MASK;
        if (e) { *NSCR &= ~NSCR_PER; *NSSR = NSSR_CLEAR_ALL; *NSCR |= NSCR_LOCK; __enable_irq(); return e; }
        *NSCR &= ~NSCR_PER;
    }

    /* Program quad-words: PG once, 4 ascending word writes (4th auto-triggers). */
    volatile uint32_t *d = (volatile uint32_t *)dst;
    const volatile uint32_t *s = (const volatile uint32_t *)src;   /* bank2: cross-bank read */
    *NSSR = NSSR_CLEAR_ALL;
    *NSCR |= NSCR_PG;
    for (uint32_t i = 0; i < nwords; i += 4u) {
        d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = s[3];
        __DSB();
        while (*NSSR & (NSSR_BSY | NSSR_WDW)) { }
        uint32_t e = *NSSR & NSSR_ERR_MASK;
        if (e) { *NSCR &= ~NSCR_PG; *NSSR = NSSR_CLEAR_ALL; *NSCR |= NSCR_LOCK; __enable_irq(); return e; }
        d += 4; s += 4;
    }
    *NSCR &= ~NSCR_PG;

    *NSCR |= NSCR_LOCK;
    __DSB(); __ISB();
    __enable_irq();
    return 0;
}
