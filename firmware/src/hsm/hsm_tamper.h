/**
 * @file    hsm_tamper.h
 * @brief   Tamper response: wipe RAM secrets, drop sessions, audit-log the event.
 *
 * The response is a *runtime* lockdown — it zeroizes the in-RAM master key (KEK)
 * and all secure-session keys, so every key operation fails until the next boot
 * re-derives the KEK from the hardware HUK+UID. A power cycle therefore restores
 * a healthy device (the KEK is deterministic). A *permanent* wipe would require
 * an irreversible root-of-trust step (RDP-2 / tamper-cleared backup registers,
 * ROADMAP D) and is intentionally out of scope for this DFU-safe layer.
 */
#ifndef OPENHSM_HSM_TAMPER_H
#define OPENHSM_HSM_TAMPER_H

#include <stdint.h>

/* Reason codes (recorded as the audit arg of the HSM_EV_TAMPER entry). */
#define HSM_TAMPER_NONE  0u
#define HSM_TAMPER_TEST  1u   /* fired by the HSM_CMD_TAMPER_TEST diagnostic */
#define HSM_TAMPER_PVD   2u   /* fired by the programmable voltage detector (brownout) */

/**
 * @brief Non-zero ⇒ a tamper trip is queued. Set by the command dispatcher or the
 *        PVD ISR (never trips in-line); serviced (and cleared) from a safe context
 *        — after the current encrypted response is built, or in the main loop.
 *        Holds the reason code so the service point knows what to log.
 */
extern volatile uint8_t g_tamper_pending;

/**
 * @brief Execute the tamper response. MUST run in thread (non-ISR) context: it
 *        writes the audit log (flash) before wiping the KEK, then drops sessions.
 */
void HSM_Tamper_Trip(uint8_t reason);

/** @brief Service a queued trip (if any) from a safe context. */
static inline void HSM_Tamper_Service(void)
{
    uint8_t r = g_tamper_pending;
    if (r) {
        g_tamper_pending = HSM_TAMPER_NONE;
        HSM_Tamper_Trip(r);
    }
}

#endif /* OPENHSM_HSM_TAMPER_H */
