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
