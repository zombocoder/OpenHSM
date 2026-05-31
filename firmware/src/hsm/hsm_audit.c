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
 * - Entries are persisted to a ring of dedicated flash pages (OPENHSM_AUDIT_*):
 *   one 16-byte entry per quad-word, appended without a per-entry erase. Entries
 *   fill one page then the next; on returning to a page we erase only THAT page
 *   (its old generation), so the most recent ~512..1024 entries always survive —
 *   a rolling window, not an erase-everything wipe. The HMAC chain survives the
 *   wrap because prev_mac is kept in RAM. A RAM ring mirrors the most recent
 *   AUDIT_RING entries for fast readout and is rebuilt from flash at boot, so
 *   GET_AUDIT_LOG shows persisted history after a reboot.
 */
#include "hsm_audit.h"
#include "hsm_keystore.h"
#include "hsm_hash.h"
#include "hsm_flash.h"

#include <string.h>

#define AUDIT_RING   64u
#define AUDIT_BLOCK  256u          /* seqs reserved per flash write */
#define AUDIT_EMPTY  0xFFFFFFFFu   /* erased slot marker (seq field) */

static hsm_audit_entry_t ring[AUDIT_RING];
static uint16_t          ring_count;   /* total appended (caps at AUDIT_RING for readout) */
static uint16_t          ring_head;    /* next write index */
static uint32_t          next_seq;
static uint32_t          block_end;
static uint32_t          flash_idx;    /* next audit-page slot to write */
static uint8_t           audit_key[32];
static uint8_t           prev_mac[8];

/* Scan the flash audit page: find the newest entry (max seq), recover the chain
 * tail (prev_mac) and the next write slot, and rebuild the RAM ring. */
static void audit_recover(void)
{
    hsm_audit_entry_t e;
    int newest = -1;
    uint32_t maxseq = 0;
    for (uint32_t i = 0; i < OPENHSM_AUDIT_SLOTS; i++) {
        HSM_Flash_AuditRead(i, &e);
        if (e.seq != AUDIT_EMPTY && (newest < 0 || e.seq > maxseq)) {
            maxseq = e.seq; newest = (int)i;
        }
    }
    if (newest < 0) { flash_idx = 0; return; }   /* empty page */

    HSM_Flash_AuditRead((uint32_t)newest, &e);
    memcpy(prev_mac, e.mac, 8);
    flash_idx = ((uint32_t)newest + 1u) % OPENHSM_AUDIT_SLOTS;
    if (maxseq + 1u > next_seq) {                 /* keep seq monotonic vs log */
        next_seq = maxseq + 1u;
        block_end = next_seq;                     /* force a fresh reservation */
    }

    /* Rebuild the ring: the newest AUDIT_RING entries, ending at `newest`. */
    hsm_audit_entry_t tmp[AUDIT_RING];
    uint16_t n = 0;
    int idx = newest;
    while (n < AUDIT_RING) {
        HSM_Flash_AuditRead((uint32_t)idx, &e);
        if (e.seq == AUDIT_EMPTY) break;
        tmp[n++] = e;
        int prev = (idx - 1 + (int)OPENHSM_AUDIT_SLOTS) % (int)OPENHSM_AUDIT_SLOTS;
        if (prev == newest) break;                /* full lap */
        idx = prev;
    }
    for (uint16_t j = 0; j < n; j++) ring[j] = tmp[n - 1 - j];   /* oldest-first */
    ring_count = n;
    ring_head = (uint16_t)(n % AUDIT_RING);
}

void HSM_Audit_Init(void)
{
    HSM_KeyStore_AuditKey(audit_key);
    next_seq = HSM_KeyStore_ReserveAudit(AUDIT_BLOCK);
    block_end = next_seq + AUDIT_BLOCK;
    ring_count = 0;
    ring_head = 0;
    flash_idx = 0;
    memset(prev_mac, 0, sizeof(prev_mac));
    audit_recover();
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

    /* Durable append into the page ring. Whenever we step onto a page's first
     * slot we erase just that page first — it holds the oldest generation, so
     * the other page's newest entries survive (rolling window, not a full wipe).
     * The HMAC chain is unbroken because prev_mac lives in RAM. */
    if (flash_idx % OPENHSM_AUDIT_PAGE_SLOTS == 0) {
        HSM_Flash_AuditErasePage(flash_idx / OPENHSM_AUDIT_PAGE_SLOTS);
    }
    HSM_Flash_AuditWrite(flash_idx, &e);
    flash_idx = (flash_idx + 1u) % OPENHSM_AUDIT_SLOTS;
}

uint16_t HSM_Audit_GetFlash(uint16_t offset, uint16_t max, hsm_audit_entry_t *out,
                            uint16_t *total, uint32_t *next)
{
    /* Collect every durable entry, then order by seq (the ring's write order is
     * not seq order across the page-reuse boundary). seqs cached in RAM so the
     * sort never touches flash. */
    static uint32_t seqs[OPENHSM_AUDIT_SLOTS];
    static uint16_t order[OPENHSM_AUDIT_SLOTS];
    hsm_audit_entry_t e;
    uint16_t n = 0;
    for (uint32_t i = 0; i < OPENHSM_AUDIT_SLOTS; i++) {
        HSM_Flash_AuditRead(i, &e);
        if (e.seq != AUDIT_EMPTY) { seqs[n] = e.seq; order[n] = (uint16_t)i; n++; }
    }
    /* insertion sort `order` by `seqs` ascending */
    for (uint16_t a = 1; a < n; a++) {
        uint32_t ks = seqs[a]; uint16_t ko = order[a];
        int b = (int)a - 1;
        while (b >= 0 && seqs[b] > ks) { seqs[b + 1] = seqs[b]; order[b + 1] = order[b]; b--; }
        seqs[b + 1] = ks; order[b + 1] = ko;
    }

    if (total) *total = n;
    if (next)  *next  = next_seq;

    uint16_t outn = 0;
    for (uint16_t k = offset; k < n && outn < max; k++) {
        HSM_Flash_AuditRead(order[k], &out[outn++]);
    }
    return outn;
}
