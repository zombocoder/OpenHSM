/**
 * @file    main.c
 * @brief   openhsm-cli — maintenance & debugging CLI for OpenHSM devices.
 *
 * Reuses the shared transport (host/pkcs11/openhsm_transport.c): direct USB, or
 * remote via openhsm-daemon when --addr / OPENHSM_ADDR is set. The encrypted
 * session is established automatically; gated commands auto-login with the PIN.
 *
 *   openhsm-cli [--addr host:port] [--pin PIN] <command> [args...]
 *
 * Commands:
 *   ping                         liveness check
 *   info                         device info (proto/fw/serial)
 *   selftest                     crypto known-answer self-test
 *   random <n>                   <n> random bytes (hex)
 *   list                         list key objects
 *   get <id>                     one object's metadata
 *   pubkey <id>                  public key of an Ed25519/X25519 object (hex)
 *   gen <type> <label> [caps]    type: aes|hmac|ed25519|x25519 ; caps e.g. enc,dec,sign,wrap,unwrap,exp
 *   del <id>                     delete an object
 *   sign <id> <message>          Ed25519 signature (hex)
 *   hmac <id> <message>          HMAC-SHA256 (hex)
 *   encrypt <id> <hexdata>       AES-256-GCM ; prints nonce|ct|tag (hex)
 *   decrypt <id> <noncehex> <ct+taghex>   AES-256-GCM decrypt (hex plaintext)
 *   wrap <wrapid> <targetid>     wrapped export (blob hex)
 *   unwrap <wrapid> <label> <blobhex>     import a wrap blob
 *   audit [n]                    recent audit-log entries
 *   setpin <old> <new>           change the login PIN
 */
#include "openhsm_transport.h"
#include "hsm_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

/* Monotonic seconds, for benchmark timing. */
static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static const char *g_pin = "123456";

/* ---- helpers ------------------------------------------------------------- */
static int hex2bin(const char *hex, uint8_t *out, int max)
{
    int n = 0;
    for (const char *p = hex; p[0] && p[1]; p += 2) {
        if (n >= max) return -1;
        unsigned v;
        if (sscanf(p, "%2x", &v) != 1) return -1;
        out[n++] = (uint8_t)v;
    }
    return n;
}
static void printhex(const uint8_t *b, int n)
{
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}
static const char *status_str(uint16_t s)
{
    switch (s) {
    case HSM_OK: return "OK";
    case HSM_ERR_UNKNOWN_CMD: return "unknown command";
    case HSM_ERR_BAD_LENGTH: return "bad length";
    case HSM_ERR_NOT_AUTHORIZED: return "not authorized";
    case HSM_ERR_NO_SESSION: return "no session";
    case HSM_ERR_INVALID_PARAM: return "invalid parameter";
    case HSM_ERR_NOT_IMPLEMENTED: return "not implemented";
    case HSM_ERR_KEY_VERIFY: return "key self-verify failed";
    case HSM_ERR_LOCKED: return "locked (PIN tries exhausted)";
    case HSM_ERR_STORE_FULL: return "store full (no free slot)";
    default: return "internal error";
    }
}

/* Exchange a command; returns device status, sets the payload ptr and length. */
static uint16_t cmd(ohsm_ctx *c, uint16_t command, const uint8_t *p, uint16_t plen,
                    uint8_t *resp, int cap, const uint8_t **out, int *olen)
{
    int rl = 0;
    if (ohsm_cmd(c, command, p, plen, resp, cap, &rl) != 0) return HSM_ERR_INTERNAL;
    hsm_header_t *rh = (hsm_header_t *)resp;
    if (out) *out = resp + HSM_HEADER_SIZE;
    if (olen) *olen = (int)rh->payload_length;
    return rh->status;
}

static int login(ohsm_ctx *c)
{
    uint8_t resp[HSM_MAX_MSG]; int ol;
    uint16_t st = cmd(c, HSM_CMD_AUTH, (const uint8_t *)g_pin, (uint16_t)strlen(g_pin),
                      resp, sizeof(resp), NULL, &ol);
    if (st != HSM_OK) { fprintf(stderr, "login failed: %s\n", status_str(st)); return -1; }
    return 0;
}

static int key_alg(const char *t)
{
    if (!strcmp(t, "aes")) return HSM_KEY_AES256;
    if (!strcmp(t, "hmac")) return HSM_KEY_HMAC256;
    if (!strcmp(t, "ed25519")) return HSM_KEY_ED25519;
    if (!strcmp(t, "x25519")) return HSM_KEY_X25519;
    return -1;
}
static const char *alg_name(uint16_t a)
{
    switch (a) {
    case HSM_KEY_AES256: return "aes256"; case HSM_KEY_HMAC256: return "hmac256";
    case HSM_KEY_ED25519: return "ed25519"; case HSM_KEY_X25519: return "x25519";
    default: return "?";
    }
}
static const char *ev_name(uint16_t e)
{
    static const char *n[] = {"?","BOOT","AUTH_OK","AUTH_FAIL","KEYGEN","KEYDEL",
        "SIGN","HMAC","WRAP","UNWRAP","ENCRYPT","DECRYPT","SET_PIN"};
    return (e <= 12) ? n[e] : "?";
}

/* ---- subcommands --------------------------------------------------------- */
static int c_ping(ohsm_ctx *c, int ac, char **av)
{
    (void)ac; (void)av;
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_PING, NULL, 0, resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "ping: %s\n", status_str(st)); return 1; }
    uint32_t magic; memcpy(&magic, o, 4);
    printf("pong magic=0x%08x %s\n", magic, magic == HSM_PING_MAGIC ? "OK" : "BAD");
    return 0;
}
static int c_info(ohsm_ctx *c, int ac, char **av)
{
    (void)ac; (void)av;
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_GET_INFO, NULL, 0, resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "info: %s\n", status_str(st)); return 1; }
    hsm_info_t in; memcpy(&in, o, sizeof(in));
    printf("proto=0x%04x fw=%u.%u serial=", in.proto_version,
           (in.fw_version >> 8) & 0xFF, in.fw_version & 0xFF);
    for (int i = 0; i < 12; i++) printf("%02x", in.serial[i]);
    printf("\n");
    return 0;
}
static int c_storage(ohsm_ctx *c, int ac, char **av)
{
    (void)ac; (void)av;
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_GET_STORAGE, NULL, 0, resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "storage: %s\n", status_str(st)); return 1; }
    hsm_storage_info_t s; memcpy(&s, o, sizeof(s));
    unsigned free_slots = (s.max_objects > s.used_objects)
                          ? (unsigned)(s.max_objects - s.used_objects) : 0u;
    double pct = s.max_objects ? (100.0 * s.used_objects / s.max_objects) : 0.0;
    printf("objects:  %u / %u used  (%u free, %.0f%% full)\n",
           s.used_objects, s.max_objects, free_slots, pct);
    printf("slot:     %u B/object  (key material <= %u B, label <= %u B)\n",
           s.slot_size, s.key_blob_max, s.label_max);
    printf("region:   %u B flash, store uses %u B (%u B free)\n",
           s.region_size, s.store_bytes,
           s.region_size > s.store_bytes ? s.region_size - s.store_bytes : 0u);
    printf("capacity: region physically holds %u slots; firmware limit is %u "
           "(raise HSM_MAX_OBJECTS for more)\n", s.region_capacity, s.max_objects);
    return 0;
}
static int c_selftest(ohsm_ctx *c, int ac, char **av)
{
    (void)ac; (void)av;
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_SELFTEST, NULL, 0, resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "selftest: %s\n", status_str(st)); return 1; }
    hsm_selftest_t t; memcpy(&t, o, sizeof(t));
    printf("sha256=%s hmac=%s hkdf=%s gcm-enc=%s gcm-dec=%s x25519=%s x25519-pub=%s  [%s]\n",
           t.sha256?"FAIL":"ok", t.hmac?"FAIL":"ok", t.hkdf?"FAIL":"ok",
           t.aesgcm_enc?"FAIL":"ok", t.aesgcm_dec?"FAIL":"ok", t.x25519?"FAIL":"ok",
           t.x25519_pub?"FAIL":"ok", t.overall?"FAILED":"ALL PASS");
    return t.overall ? 1 : 0;
}
static int c_random(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 1) { fprintf(stderr, "usage: random <n>\n"); return 2; }
    uint16_t n = (uint16_t)atoi(av[0]);
    uint8_t req[2] = { (uint8_t)n, (uint8_t)(n >> 8) };
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_RANDOM, req, 2, resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "random: %s\n", status_str(st)); return 1; }
    printhex(o, ol);
    return 0;
}
static int c_list(ohsm_ctx *c, int ac, char **av)
{
    (void)ac; (void)av;
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t offset = 0, total = 0, shown = 0;
    int header_done = 0;
    do {
        hsm_find_req_t rq; memset(&rq, 0, sizeof(rq));
        rq.offset = offset;            /* {offset, max=0}: no label filter */
        uint16_t st = cmd(c, HSM_CMD_FIND_OBJECT, (uint8_t *)&rq, 4,
                          resp, sizeof(resp), &o, &ol);
        if (st != HSM_OK) { fprintf(stderr, "list: %s\n", status_str(st)); return 1; }
        hsm_find_resp_t fr; memcpy(&fr, o, sizeof(fr));
        total = fr.total;
        if (!header_done) { printf("%u object(s):\n", total); header_done = 1; }
        const uint8_t *p = o + sizeof(fr);
        for (int i = 0; i < fr.count; i++) {
            hsm_obj_info_t k; memcpy(&k, p + i * sizeof(k), sizeof(k));
            char lbl[HSM_LABEL_LEN + 1] = {0}; memcpy(lbl, k.label, HSM_LABEL_LEN);
            printf("  id=%-3u %-8s caps=0x%04x bits=%u exp=%u usage=%u label=\"%s\"\n",
                   k.id, alg_name(k.algorithm), k.capabilities, k.key_bits,
                   k.exportable, k.usage_counter, lbl);
        }
        shown += fr.count;
        if (fr.count == 0) break;      /* guard against a stuck cursor */
        offset = fr.next_offset;
    } while (shown < total);
    return 0;
}
static int c_get(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 1) { fprintf(stderr, "usage: get <id>\n"); return 2; }
    hsm_objid_req_t rq = { .id = (uint32_t)strtoul(av[0], NULL, 0) };
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_GET_OBJECT, (uint8_t *)&rq, sizeof(rq), resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "get: %s\n", status_str(st)); return 1; }
    hsm_obj_info_t k; memcpy(&k, o, sizeof(k));
    char lbl[HSM_LABEL_LEN + 1] = {0}; memcpy(lbl, k.label, HSM_LABEL_LEN);
    printf("id=%u alg=%s caps=0x%04x bits=%u exp=%u usage=%u seq=%u label=\"%s\"\n",
           k.id, alg_name(k.algorithm), k.capabilities, k.key_bits, k.exportable,
           k.usage_counter, k.created_seq, lbl);
    return 0;
}
static int c_pubkey(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 1) { fprintf(stderr, "usage: pubkey <id>\n"); return 2; }
    if (login(c)) return 1;
    hsm_objid_req_t rq = { .id = (uint32_t)strtoul(av[0], NULL, 0) };
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_GET_PUBLIC, (uint8_t *)&rq, sizeof(rq), resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "pubkey: %s\n", status_str(st)); return 1; }
    printhex(o, ol);
    return 0;
}
static int c_gen(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 2) { fprintf(stderr, "usage: gen <aes|hmac|ed25519|x25519> <label> [caps]\n"); return 2; }
    int alg = key_alg(av[0]);
    if (alg < 0) { fprintf(stderr, "unknown type %s\n", av[0]); return 2; }
    if (login(c)) return 1;
    hsm_genkey_req_t rq; memset(&rq, 0, sizeof(rq));
    rq.algorithm = (uint16_t)alg; rq.key_bits = 256;
    /* default caps per type, or parse the comma list */
    if (ac >= 3) {
        char *caps = av[2], *t;
        for (t = strtok(caps, ","); t; t = strtok(NULL, ",")) {
            if (!strcmp(t, "enc")) rq.capabilities |= HSM_CAP_ENCRYPT;
            else if (!strcmp(t, "dec")) rq.capabilities |= HSM_CAP_DECRYPT;
            else if (!strcmp(t, "sign")) rq.capabilities |= HSM_CAP_SIGN;
            else if (!strcmp(t, "verify")) rq.capabilities |= HSM_CAP_VERIFY;
            else if (!strcmp(t, "wrap")) rq.capabilities |= HSM_CAP_WRAP;
            else if (!strcmp(t, "unwrap")) rq.capabilities |= HSM_CAP_UNWRAP;
            else if (!strcmp(t, "derive")) rq.capabilities |= HSM_CAP_DERIVE;
            else if (!strcmp(t, "exp")) rq.exportable = 1;
        }
    } else {
        if (alg == HSM_KEY_AES256) rq.capabilities = HSM_CAP_ENCRYPT | HSM_CAP_DECRYPT;
        else rq.capabilities = HSM_CAP_SIGN;
    }
    size_t ll = strlen(av[1]); if (ll > HSM_LABEL_LEN) ll = HSM_LABEL_LEN;
    memcpy(rq.label, av[1], ll);
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_GENERATE_KEY, (uint8_t *)&rq, sizeof(rq), resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "gen: %s\n", status_str(st)); return 1; }
    hsm_obj_info_t k; memcpy(&k, o, sizeof(k));
    printf("generated id=%u %s caps=0x%04x label=\"%s\"\n", k.id, alg_name(k.algorithm),
           k.capabilities, av[1]);
    return 0;
}
static int c_del(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 1) { fprintf(stderr, "usage: del <id>\n"); return 2; }
    if (login(c)) return 1;
    hsm_objid_req_t rq = { .id = (uint32_t)strtoul(av[0], NULL, 0) };
    uint8_t resp[HSM_MAX_MSG]; int ol;
    uint16_t st = cmd(c, HSM_CMD_DELETE_OBJECT, (uint8_t *)&rq, sizeof(rq), resp, sizeof(resp), NULL, &ol);
    printf("delete id=%lu: %s\n", strtoul(av[0], NULL, 0), status_str(st));
    return st == HSM_OK ? 0 : 1;
}
static int c_keyop(ohsm_ctx *c, uint16_t command, int ac, char **av, const char *name)
{
    if (ac < 2) { fprintf(stderr, "usage: %s <id> <message>\n", name); return 2; }
    if (login(c)) return 1;
    uint8_t req[HSM_MAX_MSG]; size_t mlen = strlen(av[1]);
    hsm_keyop_req_t op = { .id = (uint32_t)strtoul(av[0], NULL, 0), .msg_len = (uint16_t)mlen };
    memcpy(req, &op, sizeof(op));
    memcpy(req + sizeof(op), av[1], mlen);
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, command, req, (uint16_t)(sizeof(op) + mlen), resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "%s: %s\n", name, status_str(st)); return 1; }
    printhex(o, ol);
    return 0;
}
static int c_encrypt(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 2) { fprintf(stderr, "usage: encrypt <id> <hexdata>\n"); return 2; }
    if (login(c)) return 1;
    uint8_t pt[256]; int ptlen = hex2bin(av[1], pt, sizeof(pt));
    if (ptlen < 0) { fprintf(stderr, "bad hex\n"); return 2; }
    uint8_t req[HSM_MAX_MSG];
    hsm_aead_req_t r = { .key_id = (uint32_t)strtoul(av[0], NULL, 0), .aad_len = 0, .data_len = (uint16_t)ptlen };
    randombytes_buf(r.nonce, 12);
    memcpy(req, &r, sizeof(r));
    memcpy(req + sizeof(r), pt, ptlen);
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_ENCRYPT, req, (uint16_t)(sizeof(r) + ptlen), resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "encrypt: %s\n", status_str(st)); return 1; }
    printf("nonce="); printhex(r.nonce, 12);
    printf("ct+tag="); printhex(o, ol);
    return 0;
}
static int c_decrypt(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 3) { fprintf(stderr, "usage: decrypt <id> <noncehex> <ct+taghex>\n"); return 2; }
    if (login(c)) return 1;
    uint8_t nonce[12], ct[272];
    if (hex2bin(av[1], nonce, 12) != 12) { fprintf(stderr, "nonce must be 12 bytes\n"); return 2; }
    int ctlen = hex2bin(av[2], ct, sizeof(ct));
    if (ctlen < 16) { fprintf(stderr, "ct+tag too short\n"); return 2; }
    uint8_t req[HSM_MAX_MSG];
    hsm_aead_req_t r = { .key_id = (uint32_t)strtoul(av[0], NULL, 0), .aad_len = 0,
                         .data_len = (uint16_t)(ctlen - 16) };
    memcpy(r.nonce, nonce, 12);
    memcpy(req, &r, sizeof(r));
    memcpy(req + sizeof(r), ct, ctlen);
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_DECRYPT, req, (uint16_t)(sizeof(r) + ctlen), resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "decrypt: %s\n", status_str(st)); return 1; }
    printhex(o, ol);
    return 0;
}
static int c_wrap(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 2) { fprintf(stderr, "usage: wrap <wrapid> <targetid>\n"); return 2; }
    if (login(c)) return 1;
    hsm_wrap_req_t r = { .wrap_id = (uint32_t)strtoul(av[0], NULL, 0),
                         .target_id = (uint32_t)strtoul(av[1], NULL, 0) };
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_WRAP, (uint8_t *)&r, sizeof(r), resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "wrap: %s\n", status_str(st)); return 1; }
    printhex(o, ol);
    return 0;
}
static int c_unwrap(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 3) { fprintf(stderr, "usage: unwrap <wrapid> <label> <blobhex>\n"); return 2; }
    if (login(c)) return 1;
    uint8_t req[HSM_MAX_MSG];
    hsm_unwrap_req_t r; memset(&r, 0, sizeof(r));
    r.wrap_id = (uint32_t)strtoul(av[0], NULL, 0);
    r.capabilities = HSM_CAP_SIGN;
    size_t ll = strlen(av[1]); if (ll > HSM_LABEL_LEN) ll = HSM_LABEL_LEN;
    memcpy(r.label, av[1], ll);
    int blen = hex2bin(av[2], req + sizeof(r), (int)(sizeof(req) - sizeof(r)));
    if (blen < 0) { fprintf(stderr, "bad blob hex\n"); return 2; }
    memcpy(req, &r, sizeof(r));
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_UNWRAP, req, (uint16_t)(sizeof(r) + blen), resp, sizeof(resp), &o, &ol);
    if (st != HSM_OK) { fprintf(stderr, "unwrap: %s\n", status_str(st)); return 1; }
    hsm_obj_info_t k; memcpy(&k, o, sizeof(k));
    printf("unwrapped id=%u %s label=\"%s\"\n", k.id, alg_name(k.algorithm), av[1]);
    return 0;
}
/* Fetch one page of the audit log. Returns device status; sets resp fields. */
static uint16_t audit_page(ohsm_ctx *c, uint16_t offset, hsm_auditlog_resp_t *ar,
                           hsm_audit_entry_t *out, uint8_t *resp, int cap)
{
    hsm_auditlog_req_t rq = { .offset = offset, .max_entries = 0 };  /* 0 = page full */
    const uint8_t *o; int ol;
    uint16_t st = cmd(c, HSM_CMD_GET_AUDIT_LOG, (uint8_t *)&rq, sizeof(rq), resp, cap, &o, &ol);
    if (st != HSM_OK) return st;
    memcpy(ar, o, sizeof(*ar));
    memcpy(out, o + sizeof(*ar), ar->count * sizeof(hsm_audit_entry_t));
    return HSM_OK;
}

static int c_audit(ohsm_ctx *c, int ac, char **av)
{
    int want_all = (ac >= 1 && strcmp(av[0], "all") == 0);
    uint32_t n = want_all ? 0 : (uint32_t)(ac >= 1 ? strtoul(av[0], NULL, 0) : 20);

    uint8_t resp[HSM_MAX_MSG]; hsm_auditlog_resp_t ar; hsm_audit_entry_t ent[32];
    /* Probe for total / next_seq. */
    uint16_t st = audit_page(c, 0, &ar, ent, resp, sizeof(resp));
    if (st != HSM_OK) { fprintf(stderr, "audit: %s\n", status_str(st)); return 1; }
    uint16_t total = ar.total;
    uint16_t start = (want_all || total <= n) ? 0 : (uint16_t)(total - n);

    printf("%u of %u durable entries (next_seq=%u):\n",
           want_all ? total : (uint16_t)(total - start), total, ar.next_seq);

    uint16_t offset = start;
    while (offset < total) {
        st = audit_page(c, offset, &ar, ent, resp, sizeof(resp));
        if (st != HSM_OK) { fprintf(stderr, "audit: %s\n", status_str(st)); return 1; }
        if (ar.count == 0) break;
        for (int i = 0; i < ar.count; i++) {
            printf("  seq=%-6u %-9s arg=%-4u mac=", ent[i].seq, ev_name(ent[i].event), ent[i].arg);
            for (int j = 0; j < 4; j++) printf("%02x", ent[i].mac[j]);
            printf("\n");
        }
        offset = ar.next_offset;
    }
    return 0;
}
static int c_setpin(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 2) { fprintf(stderr, "usage: setpin <old> <new>\n"); return 2; }
    uint8_t req[2 + 64];
    req[0] = (uint8_t)strlen(av[0]); req[1] = (uint8_t)strlen(av[1]);
    memcpy(req + 2, av[0], strlen(av[0]));
    memcpy(req + 2 + strlen(av[0]), av[1], strlen(av[1]));
    uint8_t resp[HSM_MAX_MSG]; int ol;
    uint16_t st = cmd(c, HSM_CMD_SET_PIN, req, (uint16_t)(2 + strlen(av[0]) + strlen(av[1])),
                      resp, sizeof(resp), NULL, &ol);
    printf("setpin: %s\n", status_str(st));
    return st == HSM_OK ? 0 : 1;
}

/* Generate a throwaway key for benchmarking; returns its id (0 on failure). */
static uint32_t bench_gen(ohsm_ctx *c, uint16_t alg, uint16_t caps, const char *label)
{
    hsm_genkey_req_t rq; memset(&rq, 0, sizeof(rq));
    rq.algorithm = alg; rq.key_bits = 256; rq.capabilities = caps;
    size_t ll = strlen(label); if (ll > HSM_LABEL_LEN) ll = HSM_LABEL_LEN;
    memcpy(rq.label, label, ll);
    uint8_t resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    if (cmd(c, HSM_CMD_GENERATE_KEY, (uint8_t *)&rq, sizeof(rq), resp, sizeof(resp), &o, &ol) != HSM_OK)
        return 0;
    hsm_obj_info_t k; memcpy(&k, o, sizeof(k));
    return k.id;
}

/* Throughput benchmark vs spec §20 targets (AES-GCM >100/s, HMAC >500/s). */
static int c_bench(ohsm_ctx *c, int ac, char **av)
{
    double dur   = (ac >= 1) ? atof(av[0]) : 2.0;     /* seconds per test */
    uint16_t plen = (ac >= 2) ? (uint16_t)atoi(av[1]) : 32; /* payload bytes */
    if (dur <= 0) dur = 2.0;
    if (plen == 0 || plen > 256) plen = 32;
    if (login(c)) return 1;

    uint32_t aes = bench_gen(c, HSM_KEY_AES256, HSM_CAP_ENCRYPT | HSM_CAP_DECRYPT, "bench-aes");
    uint32_t mac = bench_gen(c, HSM_KEY_HMAC256, HSM_CAP_SIGN, "bench-hmac");
    if (!aes || !mac) { fprintf(stderr, "bench: key generation failed (store full?)\n"); return 1; }

    uint8_t req[HSM_MAX_MSG], resp[HSM_MAX_MSG]; const uint8_t *o; int ol;
    uint8_t data[256]; randombytes_buf(data, plen);
    int rc = 0;

    printf("benchmark: payload=%u B, %.1f s per test, over secure session\n", plen, dur);

    /* ---- AES-256-GCM encrypt ---- */
    unsigned long n = 0; double t0 = now_s(), el = 0;
    do {
        hsm_aead_req_t r = { .key_id = aes, .aad_len = 0, .data_len = plen };
        randombytes_buf(r.nonce, 12);
        memcpy(req, &r, sizeof(r)); memcpy(req + sizeof(r), data, plen);
        if (cmd(c, HSM_CMD_ENCRYPT, req, (uint16_t)(sizeof(r) + plen), resp, sizeof(resp), &o, &ol) != HSM_OK) {
            fprintf(stderr, "bench: ENCRYPT failed\n"); rc = 1; break;
        }
        n++; el = now_s() - t0;
    } while (el < dur);
    double aes_ops = n / el;
    printf("  AES-256-GCM: %8.1f ops/s  (%.2f ms/op, n=%lu)  target >100/s  [%s]\n",
           aes_ops, 1000.0 / aes_ops, n, aes_ops > 100.0 ? "PASS" : "FAIL");
    if (aes_ops <= 100.0) rc = 1;

    /* ---- HMAC-SHA256 ---- */
    n = 0; t0 = now_s(); el = 0;
    do {
        hsm_keyop_req_t r = { .id = mac, .msg_len = plen };
        memcpy(req, &r, sizeof(r)); memcpy(req + sizeof(r), data, plen);
        if (cmd(c, HSM_CMD_HMAC, req, (uint16_t)(sizeof(r) + plen), resp, sizeof(resp), &o, &ol) != HSM_OK) {
            fprintf(stderr, "bench: HMAC failed\n"); rc = 1; break;
        }
        n++; el = now_s() - t0;
    } while (el < dur);
    double mac_ops = n / el;
    printf("  HMAC-SHA256: %8.1f ops/s  (%.2f ms/op, n=%lu)  target >500/s  [%s]\n",
           mac_ops, 1000.0 / mac_ops, n, mac_ops > 500.0 ? "PASS" : "FAIL");
    if (mac_ops <= 500.0) rc = 1;

    /* ---- unseal proxy: one AES-GCM op is the HSM's whole per-unseal cost ---- */
    printf("  unseal note: OpenBao unwraps its master key with ONE AES-GCM op\n"
           "               (~%.2f ms here); the <3 s target is process-startup\n"
           "               bound — measure end-to-end with `make -C host/openbao`.\n",
           1000.0 / aes_ops);

    /* cleanup */
    hsm_objid_req_t d;
    d.id = aes; cmd(c, HSM_CMD_DELETE_OBJECT, (uint8_t *)&d, sizeof(d), resp, sizeof(resp), NULL, &ol);
    d.id = mac; cmd(c, HSM_CMD_DELETE_OBJECT, (uint8_t *)&d, sizeof(d), resp, sizeof(resp), NULL, &ol);
    return rc;
}

static int c_initpin(ohsm_ctx *c, int ac, char **av)
{
    if (ac < 1) { fprintf(stderr, "usage: initpin <pin>\n"); return 2; }
    uint8_t resp[HSM_MAX_MSG]; int ol;
    uint16_t st = cmd(c, HSM_CMD_INIT_PIN, (const uint8_t *)av[0], (uint16_t)strlen(av[0]),
                      resp, sizeof(resp), NULL, &ol);
    printf("initpin: %s\n", status_str(st));
    if (st == HSM_ERR_INVALID_PARAM)
        fprintf(stderr, "  (device already provisioned — use setpin to change)\n");
    return st == HSM_OK ? 0 : 1;
}

static int usage(void)
{
    fprintf(stderr,
      "openhsm-cli [--addr host:port] [--pin PIN] <command> [args]\n"
      "  ping | info | selftest | storage | random <n> | list | get <id> | pubkey <id>\n"
      "  gen <aes|hmac|ed25519|x25519> <label> [caps] | del <id>\n"
      "  sign <id> <msg> | hmac <id> <msg> | encrypt <id> <hex> | decrypt <id> <noncehex> <cthex>\n"
      "  wrap <wrapid> <targetid> | unwrap <wrapid> <label> <blobhex>\n"
      "  audit [n|all] | initpin <pin> | setpin <old> <new> | bench [seconds] [payload-bytes]\n"
      "Env: OPENHSM_ADDR (= --addr), OPENHSM_DEBUG=1\n");
    return 2;
}

int main(int argc, char **argv)
{
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--addr") && i + 1 < argc) { setenv("OPENHSM_ADDR", argv[++i], 1); }
        else if (!strcmp(argv[i], "--pin") && i + 1 < argc) { g_pin = argv[++i]; }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) return usage();
        else break;
    }
    if (i >= argc) return usage();
    const char *sub = argv[i++];
    int ac = argc - i; char **av = argv + i;

    ohsm_ctx *c = ohsm_open();
    if (c == NULL) { fprintf(stderr, "cannot open device (USB or daemon)\n"); return 1; }

    int rc;
    if      (!strcmp(sub, "ping"))     rc = c_ping(c, ac, av);
    else if (!strcmp(sub, "info"))     rc = c_info(c, ac, av);
    else if (!strcmp(sub, "selftest")) rc = c_selftest(c, ac, av);
    else if (!strcmp(sub, "storage"))  rc = c_storage(c, ac, av);
    else if (!strcmp(sub, "random"))   rc = c_random(c, ac, av);
    else if (!strcmp(sub, "list"))     rc = c_list(c, ac, av);
    else if (!strcmp(sub, "get"))      rc = c_get(c, ac, av);
    else if (!strcmp(sub, "pubkey"))   rc = c_pubkey(c, ac, av);
    else if (!strcmp(sub, "gen"))      rc = c_gen(c, ac, av);
    else if (!strcmp(sub, "del"))      rc = c_del(c, ac, av);
    else if (!strcmp(sub, "sign"))     rc = c_keyop(c, HSM_CMD_SIGN, ac, av, "sign");
    else if (!strcmp(sub, "hmac"))     rc = c_keyop(c, HSM_CMD_HMAC, ac, av, "hmac");
    else if (!strcmp(sub, "encrypt"))  rc = c_encrypt(c, ac, av);
    else if (!strcmp(sub, "decrypt"))  rc = c_decrypt(c, ac, av);
    else if (!strcmp(sub, "wrap"))     rc = c_wrap(c, ac, av);
    else if (!strcmp(sub, "unwrap"))   rc = c_unwrap(c, ac, av);
    else if (!strcmp(sub, "audit"))    rc = c_audit(c, ac, av);
    else if (!strcmp(sub, "initpin"))  rc = c_initpin(c, ac, av);
    else if (!strcmp(sub, "setpin"))   rc = c_setpin(c, ac, av);
    else if (!strcmp(sub, "bench"))    rc = c_bench(c, ac, av);
    else { ohsm_close(c); return usage(); }

    ohsm_close(c);
    return rc;
}
