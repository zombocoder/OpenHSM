/**
 * @file    hsm_flash.c
 * @brief   Persistent-storage flash access (STM32U585, bank 2 last page).
 */
#include "hsm_flash.h"
#include "stm32u5xx_hal.h"

#include <string.h>

void HSM_Flash_Read(uint32_t off, void *dst, size_t len)
{
    if (off + len > OPENHSM_STORE_SIZE) {
        return;
    }
    memcpy(dst, (const void *)(uintptr_t)(OPENHSM_STORE_ADDR + off), len);
}

int HSM_Flash_WriteRegion(const void *src, size_t len)
{
    if (len > OPENHSM_STORE_SIZE) {
        return -1;
    }

    /* Stage into a 16-byte-rounded, word-aligned RAM buffer so the final
     * quad-word is fully defined (0xFF padding past the data). */
    static __attribute__((aligned(16))) uint8_t stage[OPENHSM_STORE_SIZE];
    size_t rounded = (len + 15u) & ~(size_t)15u;
    memset(stage, 0xFF, rounded);
    memcpy(stage, src, len);

    if (HAL_FLASH_Unlock() != HAL_OK) {
        return -2;
    }

    FLASH_EraseInitTypeDef erase = {0};
    erase.TypeErase = FLASH_TYPEERASE_PAGES;
    erase.Banks     = FLASH_BANK_2;
    erase.Page      = OPENHSM_STORE_PAGE;
    erase.NbPages   = 1;
    uint32_t page_error = 0;
    if (HAL_FLASHEx_Erase(&erase, &page_error) != HAL_OK) {
        HAL_FLASH_Lock();
        return -3;
    }

    /* Program one 128-bit quad-word at a time. */
    for (size_t i = 0; i < rounded; i += 16u) {
        uint32_t dst = OPENHSM_STORE_ADDR + (uint32_t)i;
        uint32_t srcaddr = (uint32_t)(uintptr_t)(stage + i);
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, dst, srcaddr) != HAL_OK) {
            HAL_FLASH_Lock();
            return -4;
        }
    }

    HAL_FLASH_Lock();

    /* Read-back verify the data region. */
    if (memcmp((const void *)(uintptr_t)OPENHSM_STORE_ADDR, stage, len) != 0) {
        return -5;
    }
    return 0;
}

/* ---- Durable audit log ring (append-only, quad-word at a time) ---------- */

/* Flash address of global audit slot `gi` (spans OPENHSM_AUDIT_PAGES pages). */
static uint32_t audit_slot_addr(uint32_t gi)
{
    uint32_t page = gi / OPENHSM_AUDIT_PAGE_SLOTS;
    uint32_t slot = gi % OPENHSM_AUDIT_PAGE_SLOTS;
    return OPENHSM_AUDIT_ADDR + page * OPENHSM_STORE_SIZE + slot * 16u;
}

void HSM_Flash_AuditRead(uint32_t index, void *dst)
{
    if (index >= OPENHSM_AUDIT_SLOTS) return;
    memcpy(dst, (const void *)(uintptr_t)audit_slot_addr(index), 16);
}

int HSM_Flash_AuditWrite(uint32_t index, const void *src16)
{
    if (index >= OPENHSM_AUDIT_SLOTS) return -1;
    static __attribute__((aligned(16))) uint8_t qw[16];
    memcpy(qw, src16, 16);

    if (HAL_FLASH_Unlock() != HAL_OK) return -2;
    uint32_t dst = audit_slot_addr(index);
    int rc = (HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, dst,
                                (uint32_t)(uintptr_t)qw) == HAL_OK) ? 0 : -4;
    HAL_FLASH_Lock();
    if (rc == 0 && memcmp((const void *)(uintptr_t)dst, qw, 16) != 0) rc = -5;
    return rc;
}

int HSM_Flash_AuditErasePage(uint32_t page_ord)
{
    if (page_ord >= OPENHSM_AUDIT_PAGES) return -1;
    if (HAL_FLASH_Unlock() != HAL_OK) return -2;
    FLASH_EraseInitTypeDef erase = {0};
    erase.TypeErase = FLASH_TYPEERASE_PAGES;
    erase.Banks     = FLASH_BANK_2;
    erase.Page      = OPENHSM_AUDIT_PAGE + page_ord;
    erase.NbPages   = 1;
    uint32_t page_error = 0;
    int rc = (HAL_FLASHEx_Erase(&erase, &page_error) == HAL_OK) ? 0 : -3;
    HAL_FLASH_Lock();
    return rc;
}

/* ---- Firmware-update staging (bank 2; written by the running app) -------- */

int HSM_Flash_StageErase(uint32_t total_len)
{
    if (total_len > OPENHSM_STAGE_SIZE) return -1;
    uint32_t npages = (total_len + 0x1FFFu) / 0x2000u;
    if (npages == 0) npages = 1;
    if (npages > OPENHSM_STAGE_PAGES) npages = OPENHSM_STAGE_PAGES;
    if (HAL_FLASH_Unlock() != HAL_OK) return -2;
    FLASH_EraseInitTypeDef erase = {0};
    erase.TypeErase = FLASH_TYPEERASE_PAGES;
    erase.Banks     = FLASH_BANK_2;
    erase.Page      = 0;             /* staging starts at bank-2 page 0 */
    erase.NbPages   = npages;
    uint32_t pe = 0;
    int rc = (HAL_FLASHEx_Erase(&erase, &pe) == HAL_OK) ? 0 : -3;
    HAL_FLASH_Lock();
    return rc;
}

int HSM_Flash_StageWrite(uint32_t offset, const uint8_t *src, uint32_t len)
{
    if ((offset & 0xF) || (len & 0xF) || (uint64_t)offset + len > OPENHSM_STAGE_SIZE)
        return -1;
    if (HAL_FLASH_Unlock() != HAL_OK) return -2;
    int rc = 0;
    for (uint32_t i = 0; i < len; i += 16u) {
        static __attribute__((aligned(16))) uint8_t qw[16];
        memcpy(qw, src + i, 16);    /* align the (possibly unaligned) packet source */
        uint32_t dst = OPENHSM_STAGE_ADDR + offset + i;
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, dst, (uint32_t)(uintptr_t)qw) != HAL_OK ||
            memcmp((const void *)(uintptr_t)dst, qw, 16) != 0) { rc = -4; break; }
    }
    HAL_FLASH_Lock();
    return rc;
}

int HSM_Flash_SetPending(uint32_t total_len)
{
    if (HAL_FLASH_Unlock() != HAL_OK) return -2;
    FLASH_EraseInitTypeDef erase = {0};
    erase.TypeErase = FLASH_TYPEERASE_PAGES;
    erase.Banks     = FLASH_BANK_2;
    erase.Page      = OPENHSM_FWCTL_PAGE;
    erase.NbPages   = 1;
    uint32_t pe = 0;
    int rc = -3;
    if (HAL_FLASHEx_Erase(&erase, &pe) == HAL_OK) {
        static __attribute__((aligned(16))) uint8_t qw[16];
        memset(qw, 0xFF, sizeof(qw));
        ((uint32_t *)qw)[0] = OPENHSM_FWCTL_MAGIC;
        ((uint32_t *)qw)[1] = total_len;
        rc = (HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, OPENHSM_FWCTL_ADDR,
                                (uint32_t)(uintptr_t)qw) == HAL_OK) ? 0 : -4;
    }
    HAL_FLASH_Lock();
    return rc;
}
