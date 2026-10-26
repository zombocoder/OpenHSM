/* Host-side tests of hsm_session.c (make test): slot reuse, and the signed
 * handshake end to end against the host transport through a fake daemon.
 * Ed25519 is the firmware's (Monocypher); X25519, HKDF and AES are stubbed. */
#include "hsm_session.h"
#include "hsm_command.h"
#include "hsm_keystore.h"
#include "hsm_proto.h"
#include "hsm_aead.h"
#include "hsm_tamper.h"
#include "openhsm_transport.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

volatile uint8_t g_tamper_pending;
static int g_tampered;
uint16_t HSM_KeyStore_IdentitySeed(uint8_t out[32])
{ if (g_tampered) return HSM_ERR_NOT_AUTHORIZED; memset(out, 0x42, 32); return HSM_OK; }
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

/* Fake openhsm-daemon in front of the session layer. With g_mitm set it flips
 * a bit of the device's ephemeral key in the OPEN_SESSION reply. */
static int g_mitm;
static void *fake_daemon(void *arg)
{
    int srv = *(int *)arg;
    for (int fd; (fd = accept(srv, NULL, NULL)) >= 0; close(fd)) {
        uint8_t len[4], req[HSM_MAX_MSG], rsp[HSM_MAX_MSG];
        while (recv(fd, len, 4, MSG_WAITALL) == 4) {
            uint32_t n = (uint32_t)len[0] << 24 | (uint32_t)len[1] << 16 | (uint32_t)len[2] << 8 | len[3];
            if (n < HSM_HEADER_SIZE || n > sizeof(req) || recv(fd, req, n, MSG_WAITALL) != (ssize_t)n) break;
            hsm_header_t h; memcpy(&h, req, sizeof h);
            size_t rl = h.command == HSM_CMD_OPEN_SESSION  ? HSM_Session_Open(req, n, rsp, sizeof rsp)
                      : h.command == HSM_CMD_CLOSE_SESSION ? HSM_Session_Close(req, n, rsp, sizeof rsp)
                      :                                      HSM_Session_Unwrap(req, n, rsp, sizeof rsp);
            if (h.command == HSM_CMD_OPEN_SESSION && g_mitm) rsp[HSM_HEADER_SIZE] ^= 1;
            uint8_t out[4] = { (uint8_t)(rl >> 24), (uint8_t)(rl >> 16), (uint8_t)(rl >> 8), (uint8_t)rl };
            if (write(fd, out, 4) != 4 || write(fd, rsp, rl) != (ssize_t)rl) break;
        }
    }
    return NULL;
}

/* 1 if the host transport accepts the session under the given pin (NULL = none). */
static int host_opens(const char *pin)
{
    if (pin) setenv("OPENHSM_DEVICE_KEY", pin, 1); else unsetenv("OPENHSM_DEVICE_KEY");
    ohsm_ctx *c = ohsm_open();
    if (c) ohsm_close(c);
    return c != NULL;
}

static void test_identity(void)
{
    HSM_Session_Init();
    static int srv;
    srv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t sl = sizeof sa;
    assert(bind(srv, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(srv, 4) == 0);
    assert(getsockname(srv, (struct sockaddr *)&sa, &sl) == 0);
    char addr[32];
    snprintf(addr, sizeof addr, "127.0.0.1:%u", ntohs(sa.sin_port));
    setenv("OPENHSM_ADDR", addr, 1);
    pthread_t t;
    assert(pthread_create(&t, NULL, fake_daemon, &srv) == 0);

    /* The pin is libsodium's own derivation of the identity seed. */
    uint8_t seed[32], pk[32], sk[64];
    char good[65], wrong[65];
    memset(seed, 0x42, sizeof seed);
    crypto_sign_seed_keypair(pk, sk, seed);
    sodium_bin2hex(good, sizeof good, pk, sizeof pk);
    memcpy(wrong, good, sizeof wrong);
    wrong[0] = wrong[0] == '0' ? '1' : '0';

    assert(host_opens(good));       /* pinned, genuine device          */
    assert(!host_opens(wrong));     /* pinned to another device        */
    assert(!host_opens("zz"));      /* malformed pin                   */
    g_mitm = 1;
    assert(!host_opens(good));      /* reply altered on the path...    */
    assert(host_opens(NULL));       /* ...invisible without a pin      */
    g_mitm = 0;
    g_tampered = 1;
    assert(!host_opens(good));      /* tamper latch: unsigned, refused */
    assert(host_opens(NULL));
    g_tampered = 0;
    puts("identity: device signature verifies on the host; wrong key, MITM, tamper latch refused");
}

int main(void)
{
    assert(sodium_init() >= 0);
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

    test_identity();
    return 0;
}
