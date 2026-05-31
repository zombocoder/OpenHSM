/**
 * @file    main.c
 * @brief   OpenHSM SSH agent — exposes a device-held Ed25519 key to OpenSSH.
 *
 * Speaks the ssh-agent protocol on a unix socket. The private key never leaves
 * the HSM: REQUEST_IDENTITIES returns the device's Ed25519 public key, and
 * SIGN_REQUEST is forwarded to the device (HSM_CMD_SIGN). The 64-byte RFC 8032
 * signature is wrapped as an "ssh-ed25519" signature blob.
 *
 * Usage:
 *   openhsm-ssh-agent [-a <socket>] [-k <key-id> | -l <label>] [-c <comment>]
 *   --pin <pin>   device PIN (or env OPENHSM_PIN; default 123456)
 *   --addr host:port  talk to openhsm-daemon (or env OPENHSM_ADDR)
 *
 * Then in another shell:
 *   export SSH_AUTH_SOCK=<socket>
 *   ssh-add -l        # lists the device key
 *   ssh user@host     # logs in; signing happens on the HSM
 */
#include "openhsm_transport.h"
#include "hsm_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ssh-agent protocol message numbers (PROTOCOL.agent). */
#define SSH_AGENT_FAILURE              5
#define SSH_AGENT_SUCCESS              6
#define SSH_AGENTC_REQUEST_IDENTITIES  11
#define SSH_AGENT_IDENTITIES_ANSWER    12
#define SSH_AGENTC_SIGN_REQUEST        13
#define SSH_AGENT_SIGN_RESPONSE        14

static ohsm_ctx *g_ctx;
static uint32_t  g_keyid;
static uint8_t   g_pub[32];
static const char *g_comment = "openhsm";
static const char *g_pin = "123456";

/* ---- big-endian SSH wire helpers ---------------------------------------- */
typedef struct { uint8_t *p; size_t len, cap; } buf_t;

static void buf_need(buf_t *b, size_t n)
{
    if (b->len + n <= b->cap) return;
    size_t cap = b->cap ? b->cap * 2 : 256;
    while (cap < b->len + n) cap *= 2;
    b->p = realloc(b->p, cap);
    b->cap = cap;
}
static void put_u8(buf_t *b, uint8_t v)  { buf_need(b, 1); b->p[b->len++] = v; }
static void put_u32(buf_t *b, uint32_t v)
{
    buf_need(b, 4);
    b->p[b->len++] = (v >> 24) & 0xff; b->p[b->len++] = (v >> 16) & 0xff;
    b->p[b->len++] = (v >> 8) & 0xff;  b->p[b->len++] = v & 0xff;
}
static void put_str(buf_t *b, const void *d, uint32_t n)
{
    put_u32(b, n); buf_need(b, n); memcpy(b->p + b->len, d, n); b->len += n;
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* The standard "ssh-ed25519" public-key blob: string(type) || string(pub). */
static void put_ed25519_keyblob(buf_t *b)
{
    buf_t kb = {0};
    put_str(&kb, "ssh-ed25519", 11);
    put_str(&kb, g_pub, 32);
    put_str(b, kb.p, (uint32_t)kb.len);
    free(kb.p);
}

/* ---- device I/O --------------------------------------------------------- */
static int device_login(void)
{
    uint8_t resp[HSM_MAX_MSG]; int rl = 0;
    if (ohsm_cmd(g_ctx, HSM_CMD_AUTH, (const uint8_t *)g_pin, (uint16_t)strlen(g_pin),
                 resp, sizeof(resp), &rl) != 0) return -1;
    return ((hsm_header_t *)resp)->status == HSM_OK ? 0 : -1;
}

/* Resolve a key id by label (exact match, Ed25519 only). Returns 0 on success. */
static int resolve_label(const char *label, uint32_t *out_id)
{
    uint8_t resp[HSM_MAX_MSG]; int rl = 0;
    uint16_t offset = 0, total = 0, scanned = 0;
    do {
        hsm_find_req_t rq; memset(&rq, 0, sizeof(rq));
        rq.offset = offset;
        if (ohsm_cmd(g_ctx, HSM_CMD_FIND_OBJECT, (uint8_t *)&rq, 4, resp, sizeof(resp), &rl) != 0)
            return -1;
        if (((hsm_header_t *)resp)->status != HSM_OK) return -1;
        hsm_find_resp_t fr; memcpy(&fr, resp + HSM_HEADER_SIZE, sizeof(fr));
        total = fr.total;
        const uint8_t *p = resp + HSM_HEADER_SIZE + sizeof(fr);
        for (int i = 0; i < fr.count; i++) {
            hsm_obj_info_t o; memcpy(&o, p + i * sizeof(o), sizeof(o));
            if (o.algorithm == HSM_KEY_ED25519 &&
                strncmp((const char *)o.label, label, HSM_LABEL_LEN) == 0 &&
                (strlen(label) == HSM_LABEL_LEN || o.label[strlen(label)] == 0)) {
                *out_id = o.id; return 0;
            }
        }
        scanned += fr.count;
        if (fr.count == 0) break;
        offset = fr.next_offset;
    } while (scanned < total);
    return -1;
}

static int device_get_pubkey(uint32_t id, uint8_t pub[32])
{
    hsm_objid_req_t q = { .id = id };
    uint8_t resp[HSM_MAX_MSG]; int rl = 0;
    if (ohsm_cmd(g_ctx, HSM_CMD_GET_PUBLIC, (uint8_t *)&q, sizeof(q), resp, sizeof(resp), &rl) != 0)
        return -1;
    if (((hsm_header_t *)resp)->status != HSM_OK || rl < (int)(HSM_HEADER_SIZE + 32)) return -1;
    memcpy(pub, resp + HSM_HEADER_SIZE, 32);
    return 0;
}

static int device_sign(const uint8_t *data, uint32_t dlen, uint8_t sig[64])
{
    if (sizeof(hsm_keyop_req_t) + dlen > HSM_MAX_MSG_PAYLOAD) return -1;
    uint8_t req[HSM_MAX_MSG], resp[HSM_MAX_MSG]; int rl = 0;
    hsm_keyop_req_t r = { .id = g_keyid, .msg_len = (uint16_t)dlen };
    memcpy(req, &r, sizeof(r));
    if (dlen) memcpy(req + sizeof(r), data, dlen);
    if (ohsm_cmd(g_ctx, HSM_CMD_SIGN, req, (uint16_t)(sizeof(r) + dlen), resp, sizeof(resp), &rl) != 0)
        return -1;
    if (((hsm_header_t *)resp)->status != HSM_OK || rl < (int)(HSM_HEADER_SIZE + 64)) return -1;
    memcpy(sig, resp + HSM_HEADER_SIZE, 64);
    return 0;
}

/* ---- socket framing ----------------------------------------------------- */
static int read_all(int fd, uint8_t *p, size_t n)
{
    while (n) { ssize_t r = read(fd, p, n); if (r <= 0) return -1; p += r; n -= (size_t)r; }
    return 0;
}
static int write_all(int fd, const uint8_t *p, size_t n)
{
    while (n) { ssize_t r = write(fd, p, n); if (r <= 0) return -1; p += r; n -= (size_t)r; }
    return 0;
}
/* Send a framed agent message: uint32 length || payload. */
static int send_msg(int fd, const buf_t *b)
{
    uint8_t hdr[4] = { (b->len >> 24) & 0xff, (b->len >> 16) & 0xff, (b->len >> 8) & 0xff, b->len & 0xff };
    if (write_all(fd, hdr, 4) != 0) return -1;
    return write_all(fd, b->p, b->len);
}
static void send_fail(int fd) { buf_t r = {0}; put_u8(&r, SSH_AGENT_FAILURE); send_msg(fd, &r); free(r.p); }

/* ---- request handlers --------------------------------------------------- */
static void handle_identities(int fd)
{
    buf_t r = {0};
    put_u8(&r, SSH_AGENT_IDENTITIES_ANSWER);
    put_u32(&r, 1);                         /* one key */
    put_ed25519_keyblob(&r);
    put_str(&r, g_comment, (uint32_t)strlen(g_comment));
    send_msg(fd, &r);
    free(r.p);
}

static void handle_sign(int fd, const uint8_t *body, uint32_t blen)
{
    /* body = string(key_blob) || string(data) || uint32(flags) */
    uint32_t off = 0;
    if (blen < 4) { send_fail(fd); return; }
    uint32_t kl = get_u32(body + off); off += 4;
    if (off + kl + 4 > blen) { send_fail(fd); return; }
    /* The key blob must be ours (ssh-ed25519 || our pubkey). */
    int mine = (kl >= 4 + 11 + 4 + 32) &&
               memcmp(body + off + 4, "ssh-ed25519", 11) == 0 &&
               memcmp(body + off + kl - 32, g_pub, 32) == 0;
    off += kl;
    uint32_t dl = get_u32(body + off); off += 4;
    if (off + dl > blen || !mine) { send_fail(fd); return; }

    uint8_t sig[64];
    if (device_sign(body + off, dl, sig) != 0) { send_fail(fd); return; }

    /* signature blob = string("ssh-ed25519") || string(raw 64-byte sig) */
    buf_t sb = {0};
    put_str(&sb, "ssh-ed25519", 11);
    put_str(&sb, sig, 64);

    buf_t r = {0};
    put_u8(&r, SSH_AGENT_SIGN_RESPONSE);
    put_str(&r, sb.p, (uint32_t)sb.len);
    send_msg(fd, &r);
    free(sb.p); free(r.p);
}

static void serve(int fd)
{
    for (;;) {
        uint8_t lh[4];
        if (read_all(fd, lh, 4) != 0) return;
        uint32_t len = get_u32(lh);
        if (len == 0 || len > HSM_MAX_MSG_PAYLOAD + 4096) return;
        uint8_t *msg = malloc(len);
        if (!msg || read_all(fd, msg, len) != 0) { free(msg); return; }
        uint8_t type = msg[0];
        switch (type) {
        case SSH_AGENTC_REQUEST_IDENTITIES: handle_identities(fd); break;
        case SSH_AGENTC_SIGN_REQUEST:       handle_sign(fd, msg + 1, len - 1); break;
        default:                            send_fail(fd); break;  /* add/remove/lock: unsupported */
        }
        free(msg);
    }
}

int main(int argc, char **argv)
{
    const char *sock_path = NULL, *label = "myssh";
    uint32_t key_id = 0;
    if (getenv("OPENHSM_PIN")) g_pin = getenv("OPENHSM_PIN");

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-a") && i + 1 < argc)      sock_path = argv[++i];
        else if (!strcmp(argv[i], "-k") && i + 1 < argc) key_id = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "-l") && i + 1 < argc) label = argv[++i];
        else if (!strcmp(argv[i], "-c") && i + 1 < argc) g_comment = argv[++i];
        else if (!strcmp(argv[i], "--pin") && i + 1 < argc) g_pin = argv[++i];
        else if (!strcmp(argv[i], "--addr") && i + 1 < argc) setenv("OPENHSM_ADDR", argv[++i], 1);
        else { fprintf(stderr, "usage: %s [-a sock] [-k id|-l label] [-c comment] [--pin p] [--addr h:p]\n", argv[0]); return 2; }
    }

    signal(SIGPIPE, SIG_IGN);

    g_ctx = ohsm_open();
    if (!g_ctx) { fprintf(stderr, "cannot open device (USB or daemon)\n"); return 1; }
    if (device_login() != 0) { fprintf(stderr, "device login failed (wrong PIN?)\n"); return 1; }

    if (key_id == 0 && resolve_label(label, &key_id) != 0) {
        fprintf(stderr, "no Ed25519 key labelled \"%s\" on the device\n", label);
        return 1;
    }
    g_keyid = key_id;
    if (device_get_pubkey(g_keyid, g_pub) != 0) {
        fprintf(stderr, "could not read public key for id=%u\n", g_keyid);
        return 1;
    }

    /* Default socket path keyed by pid, like ssh-agent. */
    char defpath[128];
    if (!sock_path) {
        snprintf(defpath, sizeof(defpath), "/tmp/openhsm-ssh-agent.%d.sock", (int)getpid());
        sock_path = defpath;
    }
    unlink(sock_path);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa; memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", sock_path);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(srv, 8) != 0) {
        fprintf(stderr, "bind/listen %s: %s\n", sock_path, strerror(errno));
        return 1;
    }

    fprintf(stderr, "openhsm-ssh-agent: serving Ed25519 key id=%u (label \"%s\")\n", g_keyid, label);
    fprintf(stderr, "  SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", sock_path);
    fprintf(stderr, "  (Ctrl-C to stop)\n");

    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) { if (errno == EINTR) continue; break; }
        serve(fd);
        close(fd);
    }
    ohsm_close(g_ctx);
    unlink(sock_path);
    return 0;
}
