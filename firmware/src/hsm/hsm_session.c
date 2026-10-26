/**
 * @file    hsm_session.c
 * @brief   Secure session layer for OpenHSM.
 *
 * Handshake (ECDH, signed by the device identity key; see hsm_proto.h):
 *   host -> OPEN_SESSION { eph_pub_h, nonce_h }
 *   dev  -> { eph_pub_d, nonce_d, sig }, header.session_id = assigned id
 *   both: shared = X25519(eph_priv, peer_pub)
 *         okm    = HKDF(salt = nonce_h||nonce_d, ikm = shared, info)
 *         k_c2d  = okm[0..31]   (host->device)
 *         k_d2c  = okm[32..63]  (device->host)
 *
 * Encrypted transport: AES-256-GCM, AAD = outer 16-byte header, per-message
 * nonce = [dir | 0 0 0 | session_id LE | counter LE], strictly increasing
 * counter per direction (anti-replay).
 */
#include "hsm_session.h"
#include "hsm_command.h"
#include "hsm_proto.h"
#include "hsm_rng.h"
#include "hsm_x25519.h"
#include "hsm_hash.h"
#include "hsm_aead.h"
#include "hsm_tamper.h"
#include "hsm_keystore.h"
#include "hsm_eddsa.h"

#include <string.h>

static const char HKDF_INFO[] = "OpenHSM/v1 session keys";

typedef struct {
    uint8_t  valid;
    int      authenticated;  /* per-session login state (set by AUTH in-session) */
    uint32_t session_id;
    uint8_t  k_c2d[32];
    uint8_t  k_d2c[32];
    uint32_t rx_counter;  /* last accepted host->device counter */
    uint32_t tx_counter;  /* next device->host counter to use   */
    uint32_t last_used;   /* use_tick at open / last accepted envelope */
} session_t;

static session_t sessions[HSM_MAX_SESSIONS];
static uint32_t   next_session_id = 1;
static uint32_t   use_tick;

/* Scratch (word-aligned for the AES HAL). */
static __attribute__((aligned(4))) uint8_t inner_plain[HSM_MAX_MSG];
static __attribute__((aligned(4))) uint8_t inner_resp[HSM_MAX_MSG];

static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) { *v++ = 0; }
}

void HSM_Session_Init(void)
{
    secure_zero(sessions, sizeof(sessions));
    next_session_id = 1;
}

static session_t *find_session(uint32_t id)
{
    for (unsigned i = 0; i < HSM_MAX_SESSIONS; i++) {
        if (sessions[i].valid && sessions[i].session_id == id) {
            return &sessions[i];
        }
    }
    return NULL;
}

/* A free slot, or else the least recently used one, logged-out sessions first.
 * Clients that die without CLOSE_SESSION (a killed process, a restarted pod)
 * would otherwise fill the table until power-cycle; preferring logged-out
 * victims keeps a flood of bare handshakes from evicting a working login. */
static session_t *alloc_session(void)
{
    session_t *victim = &sessions[0];
    for (unsigned i = 0; i < HSM_MAX_SESSIONS; i++) {
        session_t *s = &sessions[i];
        if (!s->valid) {
            return s;
        }
        if (s->authenticated < victim->authenticated ||
            (s->authenticated == victim->authenticated && s->last_used < victim->last_used)) {
            victim = s;
        }
    }
    secure_zero(victim, sizeof(*victim));
    return victim;
}

static void make_nonce(uint8_t nonce[HSM_GCM_NONCE_LEN], uint8_t dir,
                       uint32_t session_id, uint32_t counter)
{
    nonce[0] = dir;
    nonce[1] = 0; nonce[2] = 0; nonce[3] = 0;
    nonce[4] = (uint8_t)(session_id);
    nonce[5] = (uint8_t)(session_id >> 8);
    nonce[6] = (uint8_t)(session_id >> 16);
    nonce[7] = (uint8_t)(session_id >> 24);
    nonce[8]  = (uint8_t)(counter);
    nonce[9]  = (uint8_t)(counter >> 8);
    nonce[10] = (uint8_t)(counter >> 16);
    nonce[11] = (uint8_t)(counter >> 24);
}

size_t HSM_Session_Open(const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t resp_cap)
{
    hsm_header_t hdr;
    memcpy(&hdr, req, sizeof(hdr));
    (void)req_len;

    if (resp_cap < HSM_HEADER_SIZE + sizeof(hsm_open_session_t) + HSM_ED25519_SIG_LEN ||
        hdr.payload_length < sizeof(hsm_open_session_t)) {
        return HSM_BuildResponse(resp, req, HSM_ERR_BAD_LENGTH, 0);
    }

    const hsm_open_session_t *ho = (const hsm_open_session_t *)(req + HSM_HEADER_SIZE);

    uint8_t eph_priv[32], eph_pub[32], dev_nonce[32], shared[32];
    uint8_t salt[64], okm[64];

    if (HSM_Rng_Fill(eph_priv, sizeof(eph_priv)) != 0 ||
        HSM_Rng_Fill(dev_nonce, sizeof(dev_nonce)) != 0) {
        return HSM_BuildResponse(resp, req, HSM_ERR_INTERNAL, 0);
    }
    HSM_X25519_PublicKey(eph_pub, eph_priv);

    if (HSM_X25519_Shared(shared, eph_priv, ho->eph_pub) != 0) {
        secure_zero(eph_priv, sizeof(eph_priv));
        return HSM_BuildResponse(resp, req, HSM_ERR_INVALID_PARAM, 0);
    }

    memcpy(salt, ho->nonce, 32);       /* nonce_h */
    memcpy(salt + 32, dev_nonce, 32);  /* nonce_d */
    if (HSM_HkdfSha256(salt, sizeof(salt), shared, sizeof(shared),
                       (const uint8_t *)HKDF_INFO, sizeof(HKDF_INFO) - 1,
                       okm, sizeof(okm)) != 0) {
        secure_zero(eph_priv, sizeof(eph_priv));
        secure_zero(shared, sizeof(shared));
        return HSM_BuildResponse(resp, req, HSM_ERR_INTERNAL, 0);
    }

    session_t *s = alloc_session();   /* never NULL: a full table reuses a slot */

    s->session_id = next_session_id++;
    if (next_session_id == 0) next_session_id = 1;
    memcpy(s->k_c2d, okm, 32);
    memcpy(s->k_d2c, okm + 32, 32);
    s->rx_counter = 0;
    s->tx_counter = 1;
    s->valid = 1;
    s->authenticated = 0;   /* fresh session starts logged-out */
    s->last_used = ++use_tick;

    /* Wipe transient secrets. */
    secure_zero(eph_priv, sizeof(eph_priv));
    secure_zero(shared, sizeof(shared));
    secure_zero(okm, sizeof(okm));

    /* Sign the transcript with the device identity (skipped while tamper-latched).
     * Built before resp is written, in case resp and req share a buffer. */
    uint8_t sig[HSM_ED25519_SIG_LEN], seed[HSM_ED25519_SEED_LEN];
    int signed_ok = (HSM_KeyStore_IdentitySeed(seed) == HSM_OK);
    if (signed_ok) {
        uint8_t t[HSM_ID_TRANSCRIPT_LEN], *p = t;
        memcpy(p, HSM_ID_CONTEXT, HSM_ID_CONTEXT_LEN); p += HSM_ID_CONTEXT_LEN;
        memcpy(p, ho->eph_pub, 32); p += 32;
        memcpy(p, ho->nonce, 32);   p += 32;
        memcpy(p, eph_pub, 32);     p += 32;
        memcpy(p, dev_nonce, 32);   p += 32;
        p[0] = (uint8_t)(s->session_id);       p[1] = (uint8_t)(s->session_id >> 8);
        p[2] = (uint8_t)(s->session_id >> 16); p[3] = (uint8_t)(s->session_id >> 24);
        HSM_Ed25519_Sign(seed, t, sizeof(t), sig);
        secure_zero(seed, sizeof(seed));
    }

    /* Response payload = eph_pub_d || dev_nonce [|| sig]; session_id in header. */
    hsm_open_session_t *out = (hsm_open_session_t *)(resp + HSM_HEADER_SIZE);
    memcpy(out->eph_pub, eph_pub, 32);
    memcpy(out->nonce, dev_nonce, 32);
    uint16_t plen = (uint16_t)sizeof(hsm_open_session_t);
    if (signed_ok) {
        memcpy(resp + HSM_HEADER_SIZE + plen, sig, sizeof(sig));
        plen += HSM_ED25519_SIG_LEN;
    }

    size_t n = HSM_BuildResponse(resp, req, HSM_OK, plen);
    /* Patch the assigned session_id into the response header (bytes 4..7). */
    resp[4] = (uint8_t)(s->session_id);
    resp[5] = (uint8_t)(s->session_id >> 8);
    resp[6] = (uint8_t)(s->session_id >> 16);
    resp[7] = (uint8_t)(s->session_id >> 24);
    return n;
}

size_t HSM_Session_Close(const uint8_t *req, size_t req_len,
                         uint8_t *resp, size_t resp_cap)
{
    (void)req_len; (void)resp_cap;
    hsm_header_t hdr;
    memcpy(&hdr, req, sizeof(hdr));

    session_t *s = find_session(hdr.session_id);
    if (s == NULL) {
        return HSM_BuildResponse(resp, req, HSM_ERR_NO_SESSION, 0);
    }
    secure_zero(s, sizeof(*s));
    return HSM_BuildResponse(resp, req, HSM_OK, 0);
}

size_t HSM_Session_Unwrap(const uint8_t *req, size_t req_len,
                          uint8_t *resp, size_t resp_cap)
{
    hsm_header_t hdr;
    memcpy(&hdr, req, sizeof(hdr));

    if (req_len < HSM_HEADER_SIZE + HSM_GCM_TAG_LEN) {
        return HSM_BuildResponse(resp, req, HSM_ERR_BAD_LENGTH, 0);
    }
    session_t *s = find_session(hdr.session_id);
    if (s == NULL) {
        return HSM_BuildResponse(resp, req, HSM_ERR_NO_SESSION, 0);
    }
    /* Strictly-increasing counter (anti-replay). */
    if (hdr.counter <= s->rx_counter) {
        return HSM_BuildResponse(resp, req, HSM_ERR_NOT_AUTHORIZED, 0);
    }

    size_t pl = hdr.payload_length;
    if (pl < HSM_GCM_TAG_LEN || pl > (req_len - HSM_HEADER_SIZE) ||
        (pl - HSM_GCM_TAG_LEN) > sizeof(inner_plain)) {
        return HSM_BuildResponse(resp, req, HSM_ERR_BAD_LENGTH, 0);
    }
    size_t ct_len = pl - HSM_GCM_TAG_LEN;
    const uint8_t *ct  = req + HSM_HEADER_SIZE;
    const uint8_t *tag = ct + ct_len;

    uint8_t nonce[HSM_GCM_NONCE_LEN];
    make_nonce(nonce, HSM_NONCE_DIR_C2D, hdr.session_id, hdr.counter);

    if (HSM_AesGcmDecrypt(s->k_c2d, nonce, req, HSM_HEADER_SIZE,
                          ct, ct_len, tag, inner_plain) != 0) {
        return HSM_BuildResponse(resp, req, HSM_ERR_NOT_AUTHORIZED, 0);
    }
    s->rx_counter = hdr.counter;
    s->last_used = ++use_tick;

    /* Run the inner (decrypted) command. Bound its response so the encrypted
     * envelope (header + ct + tag) fits in resp_cap. */
    size_t inner_cap = sizeof(inner_resp);
    if (inner_cap > resp_cap - HSM_HEADER_SIZE - HSM_GCM_TAG_LEN) {
        inner_cap = resp_cap - HSM_HEADER_SIZE - HSM_GCM_TAG_LEN;
    }
    size_t inner_len = HSM_ProcessPlaintext(inner_plain, ct_len, inner_resp, inner_cap,
                                            &s->authenticated);
    if (inner_len == 0) {
        return HSM_BuildResponse(resp, req, HSM_ERR_INTERNAL, 0);
    }

    /* Build the encrypted response: same outer command/session, RESPONSE flag,
     * fresh device->host counter, AAD = the new outer header. */
    uint32_t tx_ctr = s->tx_counter++;
    HSM_BuildResponse(resp, req, HSM_OK, (uint16_t)(inner_len + HSM_GCM_TAG_LEN));
    resp[8]  = (uint8_t)(tx_ctr);
    resp[9]  = (uint8_t)(tx_ctr >> 8);
    resp[10] = (uint8_t)(tx_ctr >> 16);
    resp[11] = (uint8_t)(tx_ctr >> 24);

    make_nonce(nonce, HSM_NONCE_DIR_D2C, hdr.session_id, tx_ctr);
    uint8_t *out_ct  = resp + HSM_HEADER_SIZE;
    uint8_t *out_tag = out_ct + inner_len;
    if (HSM_AesGcmEncrypt(s->k_d2c, nonce, resp, HSM_HEADER_SIZE,
                          inner_resp, inner_len, out_ct, out_tag) != 0) {
        return HSM_BuildResponse(resp, req, HSM_ERR_INTERNAL, 0);
    }
    /* The response envelope is fully built above. If an inner command (e.g.
     * TAMPER_TEST) queued a tamper trip, service it now — *after* encrypting
     * with the still-valid key, *before* returning the bytes to be sent. The
     * trip zeroizes this session (and the KEK); `s` must not be used after. */
    HSM_Tamper_Service();
    return HSM_HEADER_SIZE + inner_len + HSM_GCM_TAG_LEN;
}
