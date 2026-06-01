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

/* Durable audit log: a ring of bank-2 pages, written one 16-byte entry (one
 * quad-word) at a time, no per-entry erase. Entries fill a page, then the next;
 * when we wrap back to a page we erase just THAT page first (dropping its
 * generation), so the most recent ~(PAGES-1)*512 .. PAGES*512 entries always
 * survive — a rolling window, not an erase-everything sawtooth. */
#define OPENHSM_AUDIT_ADDR   0x081FA000u  /* bank 2, page 125 (lowest page) */
#define OPENHSM_AUDIT_PAGE   125u         /* first page number; +ord for the rest */
#define OPENHSM_AUDIT_PAGES  2u           /* page 125 + 126 */
#define OPENHSM_AUDIT_PAGE_SLOTS 512u     /* 16-byte entries per 8 KB page */
#define OPENHSM_AUDIT_SLOTS  (OPENHSM_AUDIT_PAGES * OPENHSM_AUDIT_PAGE_SLOTS)  /* 1024 */

/* Secure firmware update (shared with the bootloader). The running app stages a
 * new signed image (header+app) here in bank 2, sets the control word, and
 * resets; the bootloader verifies + applies it to the bank-1 app region. */
#define OPENHSM_STAGE_ADDR   0x08100000u  /* bank 2, page 0 */
#define OPENHSM_STAGE_PAGES  32u           /* 256 KB staging window */
#define OPENHSM_STAGE_SIZE   (OPENHSM_STAGE_PAGES * 0x2000u)
#define OPENHSM_FWCTL_ADDR   0x081F6000u  /* bank 2, page 123: pending-update control */
#define OPENHSM_FWCTL_PAGE   123u
#define OPENHSM_FWCTL_MAGIC  0x4F485550u  /* "OHUP" */

/** @brief Copy @p len bytes from store offset @p off into @p dst (mapped read). */
void HSM_Flash_Read(uint32_t off, void *dst, size_t len);

/**
 * @brief Erase the store page and program @p len bytes from @p src.
 * @param src  Source buffer; len is rounded up to a 16-byte (quad-word) unit,
 *             trailing bytes programmed as 0xFF padding. Must be <= store size.
 * @return 0 on success (including a read-back verify), non-zero on failure.
 */
int HSM_Flash_WriteRegion(const void *src, size_t len);

/** @brief Read the 16-byte audit slot @p index (0..OPENHSM_AUDIT_SLOTS-1). */
void HSM_Flash_AuditRead(uint32_t index, void *dst);

/** @brief Program one 16-byte audit entry into global slot @p index (no erase).
 *  @return 0 on success (incl. read-back verify), non-zero on failure. */
int HSM_Flash_AuditWrite(uint32_t index, const void *src16);

/** @brief Erase audit page ordinal @p page_ord (0..OPENHSM_AUDIT_PAGES-1). */
int HSM_Flash_AuditErasePage(uint32_t page_ord);

/* ---- Firmware-update staging (bank 2; app-side, cross-bank writes) ---- */

/** @brief Erase the staging pages needed to hold @p total_len bytes. @return 0 ok. */
int HSM_Flash_StageErase(uint32_t total_len);

/** @brief Program @p len bytes (16-aligned) into staging at @p offset. @return 0 ok. */
int HSM_Flash_StageWrite(uint32_t offset, const uint8_t *src, uint32_t len);

/** @brief Write the pending-update control word {magic,total_len}. @return 0 ok. */
int HSM_Flash_SetPending(uint32_t total_len);

#endif /* OPENHSM_HSM_FLASH_H */
