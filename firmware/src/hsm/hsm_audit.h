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

/** @brief Append an event: monotonic seq + chained HMAC over the prior entry. */
void HSM_Audit_Log(uint16_t event, uint16_t arg);

/**
 * @brief Copy up to @p max of the most recent entries (oldest-first order)
 *        into @p out. @return number copied; *next_seq = next seq to be used.
 */
uint16_t HSM_Audit_Get(uint16_t max, hsm_audit_entry_t *out, uint32_t *next_seq);

#endif /* OPENHSM_HSM_AUDIT_H */
