/**
 * @file    flash_ram.h
 * @brief   RAM-resident bank-1 flash apply (see flash_ram.c).
 */
#ifndef OPENHSM_FLASH_RAM_H
#define OPENHSM_FLASH_RAM_H

#include <stdint.h>

/** @brief Erase+program @p total bytes from @p src (bank-2 staging) into @p dst
 *  (bank-1 app region; must be 0x08010000). Runs from RAM. @return 0 on success,
 *  else the FLASH NSSR error bits (non-zero). */
uint32_t flash_apply(uint32_t dst, uint32_t src, uint32_t total);

#endif /* OPENHSM_FLASH_RAM_H */
