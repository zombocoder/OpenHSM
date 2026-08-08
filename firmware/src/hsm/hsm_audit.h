/**
 * @file    hsm_audit.h
 * @brief   Append-only, tamper-evident audit log with a monotonic counter.
 */
#ifndef OPENHSM_HSM_AUDIT_H
#define OPENHSM_HSM_AUDIT_H

#include <stdint.h>
#include <stddef.h>
#include "hsm_proto.h"

/** @brief Initialize the log (reserve a seq block) and record a BOOT event. */
void HSM_Audit_Init(void);

/**
 * @brief Factory reset for the log: erase the durable audit pages and start a
 *        fresh chain whose first entry is FACTORY_RESET. Call after
 *        HSM_KeyStore_FactoryReset so the seq counter starts clean.
 */
void HSM_Audit_Reset(void);

/** @brief Append an event: monotonic seq + chained HMAC over the prior entry. */
void HSM_Audit_Log(uint16_t event, uint16_t arg);

/**
 * @brief Read a page of the durable (flash) log in oldest-first seq order.
 * @param offset   skip this many entries
 * @param max      max entries to copy into @p out
 * @param total    if non-NULL, set to the total durable entry count
 * @param next_seq if non-NULL, set to the seq the next event will use
 * @return number copied into @p out
 */
uint16_t HSM_Audit_GetFlash(uint16_t offset, uint16_t max, hsm_audit_entry_t *out,
                            uint16_t *total, uint32_t *next_seq);

#endif /* OPENHSM_HSM_AUDIT_H */
