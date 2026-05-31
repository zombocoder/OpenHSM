/**
 * @file    hsm_audit.c
 * @brief   Append-only, tamper-evident audit log.
 *
 * - Monotonic sequence number, durable across reboots via block reservation in
 *   the key store (one flash write per AUDIT_BLOCK events, not per event).
 * - Tamper-evidence: each entry carries a truncated HMAC chained over the
 *   previous entry's MAC, keyed by an audit key derived from the KEK. Altering,
 *   reordering or dropping an entry breaks the chain (verifiable on-device or by
 *   an auditor holding the key).
 * - Entries live in a RAM ring buffer (most recent AUDIT_RING). Durable storage
 *   of the full entry stream (flash log region / external sink) is future work;
 *   the monotonic counter already makes truncation across reboots detectable.
 */
#include "hsm_audit.h"
#include "hsm_keystore.h"
#include "hsm_hash.h"

#include <string.h>

#define AUDIT_RING   64u
#define AUDIT_BLOCK  256u   /* seqs reserved per flash write */

static hsm_audit_entry_t ring[AUDIT_RING];
static uint16_t          ring_count;   /* total appended (caps at AUDIT_RING for readout) */
static uint16_t          ring_head;    /* next write index */
static uint32_t          next_seq;
static uint32_t          block_end;
static uint8_t           audit_key[32];
static uint8_t           prev_mac[8];

void HSM_Audit_Init(void)
{
    HSM_KeyStore_AuditKey(audit_key);
    next_seq = HSM_KeyStore_ReserveAudit(AUDIT_BLOCK);
    block_end = next_seq + AUDIT_BLOCK;
    ring_count = 0;
    ring_head = 0;
    memset(prev_mac, 0, sizeof(prev_mac));
    HSM_Audit_Log(HSM_EV_BOOT, 0);
}

void HSM_Audit_Log(uint16_t event, uint16_t arg)
{
    if (next_seq >= block_end) {
        next_seq = HSM_KeyStore_ReserveAudit(AUDIT_BLOCK);
        block_end = next_seq + AUDIT_BLOCK;
    }

    hsm_audit_entry_t e;
    e.seq = next_seq++;
    e.event = event;
    e.arg = arg;

    /* mac = HMAC(audit_key, prev_mac || seq || event || arg)[0:8] */
    uint8_t buf[8 + 4 + 2 + 2];
    memcpy(buf, prev_mac, 8);
    memcpy(buf + 8, &e.seq, 4);
    memcpy(buf + 12, &e.event, 2);
    memcpy(buf + 14, &e.arg, 2);
    uint8_t full[32];
    HSM_HmacSha256(audit_key, sizeof(audit_key), buf, sizeof(buf), full);
    memcpy(e.mac, full, 8);
    memcpy(prev_mac, full, 8);

    ring[ring_head] = e;
    ring_head = (uint16_t)((ring_head + 1) % AUDIT_RING);
    if (ring_count < AUDIT_RING) ring_count++;
}

uint16_t HSM_Audit_Get(uint16_t max, hsm_audit_entry_t *out, uint32_t *next)
{
    if (next) *next = next_seq;
    uint16_t n = ring_count < max ? ring_count : max;
    /* Emit oldest-first. The oldest of the n returned is (ring_head - n). */
    uint16_t start = (uint16_t)((ring_head + AUDIT_RING - n) % AUDIT_RING);
    for (uint16_t i = 0; i < n; i++) {
        out[i] = ring[(start + i) % AUDIT_RING];
    }
    return n;
}
