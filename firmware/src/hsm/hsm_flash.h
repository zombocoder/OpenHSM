/**
 * @file    hsm_flash.h
 * @brief   Low-level persistent-storage flash access for the key store.
 *
 * Uses the last 8 KB page of bank 2 (the firmware runs from bank 1, so erasing
 * bank 2 never stalls execution). One page is the whole store; callers keep a
 * RAM shadow and rewrite the page atomically via HSM_Flash_WriteRegion.
 */
#ifndef OPENHSM_HSM_FLASH_H
#define OPENHSM_HSM_FLASH_H

#include <stdint.h>
#include <stddef.h>

#define OPENHSM_STORE_ADDR  0x081FE000u  /* bank 2, page 127 */
#define OPENHSM_STORE_PAGE  127u
#define OPENHSM_STORE_SIZE  0x2000u       /* 8 KB */

/** @brief Copy @p len bytes from store offset @p off into @p dst (mapped read). */
void HSM_Flash_Read(uint32_t off, void *dst, size_t len);

/**
 * @brief Erase the store page and program @p len bytes from @p src.
 * @param src  Source buffer; len is rounded up to a 16-byte (quad-word) unit,
 *             trailing bytes programmed as 0xFF padding. Must be <= store size.
 * @return 0 on success (including a read-back verify), non-zero on failure.
 */
int HSM_Flash_WriteRegion(const void *src, size_t len);

#endif /* OPENHSM_HSM_FLASH_H */
