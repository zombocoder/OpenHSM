/**
 * @file    hsm_tamper.c
 * @brief   Tamper response implementation. See hsm_tamper.h for the model.
 */
#include "hsm_tamper.h"
#include "hsm_audit.h"
#include "hsm_keystore.h"
#include "hsm_session.h"
#include "hsm_proto.h"

volatile uint8_t g_tamper_pending = HSM_TAMPER_NONE;

void HSM_Tamper_Trip(uint8_t reason)
{
    /* 1. Record the event FIRST — while the audit key (derived from the KEK) is
     *    still valid. Entries logged after the wipe key off a zeroized KEK, so
     *    the broken chain link after this point is itself tamper evidence. */
    HSM_Audit_Log(HSM_EV_TAMPER, reason);

    /* 2. Zeroize the in-RAM master key: every stored key is sealed under it, so
     *    all key operations now fail until the next boot re-derives it. This is
     *    the secret a cold-boot / probe attack would be after. */
    HSM_KeyStore_TamperWipe();

    /* 3. Drop every secure session (zeroizes per-session transport keys + login
     *    state). Any in-flight session is dead; the host must re-handshake. */
    HSM_Session_Init();
}
