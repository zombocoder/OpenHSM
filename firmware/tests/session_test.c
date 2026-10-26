/* Host-side test of hsm_session.c slot reuse (make test); crypto is stubbed to identity. */
#include "hsm_session.h"
#include "hsm_command.h"
#include "hsm_proto.h"
#include "hsm_aead.h"
#include "hsm_tamper.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

volatile uint8_t g_tamper_pending;
void HSM_Tamper_Trip(uint8_t r) { (void)r; }
int  HSM_Rng_Fill(uint8_t *b, size_t n) { memset(b, 7, n); return 0; }
void HSM_X25519_PublicKey(uint8_t p[32], const uint8_t s[32]) { memcpy(p, s, 32); }
int  HSM_X25519_Shared(uint8_t o[32], const uint8_t a[32], const uint8_t b[32]) { (void)a; memcpy(o, b, 32); return 0; }
int  HSM_HkdfSha256(const uint8_t *s, size_t sl, const uint8_t *k, size_t kl, const uint8_t *i, size_t il, uint8_t *o, size_t ol)
{ (void)s; (void)sl; (void)k; (void)kl; (void)i; (void)il; memset(o, 1, ol); return 0; }
int HSM_AesGcmEncrypt(const uint8_t k[32], const uint8_t n[12], const uint8_t *a, size_t al,
                      const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[16])
{ (void)k; (void)n; (void)a; (void)al; memmove(ct, pt, len); memset(tag, 0, 16); return 0; }
int HSM_AesGcmDecrypt(const uint8_t k[32], const uint8_t n[12], const uint8_t *a, size_t al,
                      const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt)
{ (void)k; (void)n; (void)a; (void)al; (void)tag; memmove(pt, ct, len); return 0; }
size_t HSM_BuildResponse(uint8_t *resp, const uint8_t *req, uint16_t st, uint16_t pl)
{ hsm_header_t h; memcpy(&h, req, sizeof h); h.flags |= HSM_FLAG_RESPONSE; h.payload_length = pl; h.status = st;
  memcpy(resp, &h, sizeof h); return sizeof h + pl; }
/* Inner command AUTH logs the session in; anything else is a no-op. */
size_t HSM_ProcessPlaintext(const uint8_t *req, size_t len, uint8_t *resp, size_t cap, int *auth)
{ (void)len; (void)cap; hsm_header_t h; memcpy(&h, req, sizeof h); if (h.command == HSM_CMD_AUTH) *auth = 1;
  return HSM_BuildResponse(resp, req, HSM_OK, 0); }

static uint8_t resp[HSM_MAX_MSG];
static uint32_t counter[64];

static uint32_t open_session(void)
{
    uint8_t req[HSM_HEADER_SIZE + 64] = {0};
    hsm_header_t h = { .command = HSM_CMD_OPEN_SESSION, .payload_length = 64 };
    memcpy(req, &h, sizeof h);
    HSM_Session_Open(req, sizeof req, resp, sizeof resp);
    hsm_header_t r; memcpy(&r, resp, sizeof r);
    assert(r.status == HSM_OK);
    return r.session_id;
}

/* Send one envelope; returns the outer status (NO_SESSION if evicted). */
static uint16_t envelope(uint32_t sid, uint16_t inner_cmd)
{
    uint8_t req[HSM_HEADER_SIZE * 2 + 16] = {0};
    hsm_header_t in = { .command = inner_cmd };
    hsm_header_t out = { .command = HSM_CMD_SESSION_DATA, .flags = HSM_FLAG_ENCRYPTED,
                         .session_id = sid, .counter = ++counter[sid], .payload_length = HSM_HEADER_SIZE + 16 };
    memcpy(req, &out, sizeof out);
    memcpy(req + HSM_HEADER_SIZE, &in, sizeof in);
    HSM_Session_Unwrap(req, sizeof req, resp, sizeof resp);
    hsm_header_t r; memcpy(&r, resp, sizeof r);
    return r.status;
}

int main(void)
{
    HSM_Session_Init();
    uint32_t s1 = open_session(), s2 = open_session(), s3 = open_session(), s4 = open_session();
    assert(envelope(s2, HSM_CMD_AUTH) == HSM_OK);   /* s2 logged in */
    assert(envelope(s1, HSM_CMD_PING) == HSM_OK);   /* s1 used recently */

    /* Full table: the LRU logged-out session (s3) goes, the login survives. */
    uint32_t s5 = open_session();
    assert(envelope(s3, HSM_CMD_PING) == HSM_ERR_NO_SESSION);
    assert(envelope(s2, HSM_CMD_PING) == HSM_OK);
    /* A flood of bare handshakes only churns logged-out slots. */
    for (int i = 0; i < 10; i++) open_session();
    assert(envelope(s2, HSM_CMD_PING) == HSM_OK);
    assert(envelope(s1, HSM_CMD_PING) == HSM_ERR_NO_SESSION);
    assert(envelope(s4, HSM_CMD_PING) == HSM_ERR_NO_SESSION);
    assert(envelope(s5, HSM_CMD_PING) == HSM_ERR_NO_SESSION);

    /* All four logged in (leaked logins): the least recently used login goes. */
    HSM_Session_Init();
    uint32_t a = open_session(), b = open_session(), c = open_session(), d = open_session();
    assert(envelope(b, HSM_CMD_AUTH) == HSM_OK);
    assert(envelope(c, HSM_CMD_AUTH) == HSM_OK);
    assert(envelope(d, HSM_CMD_AUTH) == HSM_OK);
    assert(envelope(a, HSM_CMD_AUTH) == HSM_OK);    /* a is now the most recent */
    open_session();
    assert(envelope(b, HSM_CMD_PING) == HSM_ERR_NO_SESSION);
    assert(envelope(a, HSM_CMD_PING) == HSM_OK);
    assert(envelope(c, HSM_CMD_PING) == HSM_OK);
    puts("session slot reuse: LRU, logged-out first — all checks pass");
    return 0;
}
