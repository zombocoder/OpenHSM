/**
 * @file    openhsm_transport.c
 * @brief   USB transport for the OpenHSM host stack, with an encrypted session.
 *
 * On open it performs the X25519 ECDH handshake and derives directional
 * AES-256-GCM keys; every ohsm_cmd after that is wrapped in an encrypted
 * HSM_CMD_SESSION_DATA envelope (AAD = outer header, per-message nonce with an
 * increasing counter). Falls back to plaintext only if the handshake fails.
 */
#include "openhsm_transport.h"
#include "hsm_proto.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libusb.h>
#include <sodium.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define OPENHSM_VID 0x0483
#define OPENHSM_PID 0x5750
#define EP_OUT      0x01
#define EP_IN       0x81
#define TIMEOUT_MS  2000

#define NONCE_DIR_C2D 0x00
#define NONCE_DIR_D2C 0x01
static const char HKDF_INFO[] = "OpenHSM/v1 session keys";

struct ohsm_ctx {
    /* transport: TCP to openhsm-daemon (sock >= 0) OR direct libusb */
    int                   sock;       /* -1 = USB mode                          */
    libusb_context       *usb;
    libusb_device_handle *dev;
    int                   claimed;
    /* secure session */
    int       session_ok;
    uint32_t  session_id;
    uint32_t  counter;        /* next c2d counter to use */
    uint8_t   k_c2d[32];
    uint8_t   k_d2c[32];
};

static int io_read_n(int fd, uint8_t *buf, int n)
{
    int off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r <= 0) return -1;
        off += (int)r;
    }
    return 0;
}

static int io_write_n(int fd, const uint8_t *buf, int n)
{
    int off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w <= 0) return -1;
        off += (int)w;
    }
    return 0;
}

/* TCP framing to openhsm-daemon: 4-byte BE length + packet, both ways. */
static int sock_exchange(ohsm_ctx *c, const uint8_t *out, int out_len,
                         uint8_t *resp, int resp_cap, int *resp_len)
{
    uint8_t lenbe[4] = { (uint8_t)(out_len >> 24), (uint8_t)(out_len >> 16),
                         (uint8_t)(out_len >> 8), (uint8_t)out_len };
    if (io_write_n(c->sock, lenbe, 4) != 0) return -1;
    if (io_write_n(c->sock, out, out_len) != 0) return -1;
    if (io_read_n(c->sock, lenbe, 4) != 0) return -1;
    uint32_t rlen = ((uint32_t)lenbe[0] << 24) | ((uint32_t)lenbe[1] << 16) |
                    ((uint32_t)lenbe[2] << 8) | lenbe[3];
    if (rlen == 0 || (int)rlen > resp_cap) return -1;
    if (io_read_n(c->sock, resp, (int)rlen) != 0) return -1;
    *resp_len = (int)rlen;
    return 0;
}

/* Raw exchange of a fully-formed packet (TCP daemon or direct USB). */
static int send_recv_raw(ohsm_ctx *c, const uint8_t *out, int out_len,
                         uint8_t *resp, int resp_cap, int *resp_len)
{
    if (c->sock >= 0) {
        return sock_exchange(c, out, out_len, resp, resp_cap, resp_len);
    }
    int transferred = 0;
    int rc = libusb_bulk_transfer(c->dev, EP_OUT, (uint8_t *)out, out_len,
                                  &transferred, TIMEOUT_MS);
    if (rc != 0) return rc;

    int got = 0;
    while (got < (int)HSM_HEADER_SIZE) {
        int n = 0, want = HSM_MAX_PACKET;
        if (want > resp_cap - got) want = resp_cap - got;
        rc = libusb_bulk_transfer(c->dev, EP_IN, resp + got, want, &n, TIMEOUT_MS);
        if (rc != 0) return rc;
        if (n == 0) break;
        got += n;
    }
    int total = got;
    if (got >= (int)HSM_HEADER_SIZE) {
        uint16_t pl = (uint16_t)(resp[12] | (resp[13] << 8));
        total = (int)HSM_HEADER_SIZE + pl;
        if (total > resp_cap) total = resp_cap;
    }
    while (got < total) {
        int n = 0, want = HSM_MAX_PACKET;
        if (want > resp_cap - got) want = resp_cap - got;
        rc = libusb_bulk_transfer(c->dev, EP_IN, resp + got, want, &n, TIMEOUT_MS);
        if (rc != 0) return rc;
        if (n == 0) break;
        got += n;
    }
    *resp_len = got;
    return 0;
}

/* Build and exchange a plaintext command. */
static int cmd_plain(ohsm_ctx *c, uint16_t command,
                     const uint8_t *payload, uint16_t plen,
                     uint8_t *resp, int resp_cap, int *resp_len)
{
    uint8_t pkt[HSM_MAX_MSG];
    if ((int)(HSM_HEADER_SIZE + plen) > (int)sizeof(pkt)) return -1;
    memset(pkt, 0, HSM_HEADER_SIZE);
    hsm_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.command = command;
    hdr.payload_length = plen;
    memcpy(pkt, &hdr, sizeof(hdr));
    if (plen && payload) memcpy(pkt + HSM_HEADER_SIZE, payload, plen);
    return send_recv_raw(c, pkt, HSM_HEADER_SIZE + plen, resp, resp_cap, resp_len);
}

static void make_nonce(uint8_t n[12], uint8_t dir, uint32_t sid, uint32_t ctr)
{
    n[0] = dir; n[1] = 0; n[2] = 0; n[3] = 0;
    n[4] = (uint8_t)sid;  n[5] = (uint8_t)(sid >> 8);
    n[6] = (uint8_t)(sid >> 16); n[7] = (uint8_t)(sid >> 24);
    n[8] = (uint8_t)ctr;  n[9] = (uint8_t)(ctr >> 8);
    n[10] = (uint8_t)(ctr >> 16); n[11] = (uint8_t)(ctr >> 24);
}

/* Establish the encrypted session (X25519 ECDH -> HKDF -> directional keys). */
static int establish_session(ohsm_ctx *c)
{
    uint8_t eph_priv[32], eph_pub[32], host_nonce[32];
    randombytes_buf(eph_priv, sizeof(eph_priv));
    randombytes_buf(host_nonce, sizeof(host_nonce));
    crypto_scalarmult_curve25519_base(eph_pub, eph_priv);

    uint8_t open_payload[64];
    memcpy(open_payload, eph_pub, 32);
    memcpy(open_payload + 32, host_nonce, 32);

    uint8_t resp[HSM_MAX_MSG]; int rl = 0;
    if (cmd_plain(c, HSM_CMD_OPEN_SESSION, open_payload, sizeof(open_payload),
                  resp, sizeof(resp), &rl) != 0) return -1;
    hsm_header_t rh; memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK || rl < (int)(HSM_HEADER_SIZE + 64)) return -1;

    uint8_t dev_pub[32], dev_nonce[32], shared[32];
    memcpy(dev_pub, resp + HSM_HEADER_SIZE, 32);
    memcpy(dev_nonce, resp + HSM_HEADER_SIZE + 32, 32);
    if (crypto_scalarmult_curve25519(shared, eph_priv, dev_pub) != 0) return -1;

    uint8_t salt[64], prk[crypto_kdf_hkdf_sha256_KEYBYTES], okm[64];
    memcpy(salt, host_nonce, 32);
    memcpy(salt + 32, dev_nonce, 32);
    crypto_kdf_hkdf_sha256_extract(prk, salt, sizeof(salt), shared, sizeof(shared));
    crypto_kdf_hkdf_sha256_expand(okm, sizeof(okm), HKDF_INFO, sizeof(HKDF_INFO) - 1, prk);

    memcpy(c->k_c2d, okm, 32);
    memcpy(c->k_d2c, okm + 32, 32);
    c->session_id = rh.session_id;
    c->counter = 1;
    c->session_ok = 1;

    sodium_memzero(eph_priv, sizeof(eph_priv));
    sodium_memzero(shared, sizeof(shared));
    sodium_memzero(okm, sizeof(okm));
    sodium_memzero(prk, sizeof(prk));
    return 0;
}

/* Connect to openhsm-daemon at "host:port" (from OPENHSM_ADDR). */
static int connect_daemon(const char *addr)
{
    char host[256]; int port = 11700;
    const char *colon = strrchr(addr, ':');
    if (colon) {
        size_t hl = (size_t)(colon - addr);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, addr, hl); host[hl] = 0;
        port = atoi(colon + 1);
    } else {
        snprintf(host, sizeof(host), "%s", addr);
    }
    char portstr[16]; snprintf(portstr, sizeof(portstr), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) { close(fd); freeaddrinfo(res); return -1; }
    freeaddrinfo(res);
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

ohsm_ctx *ohsm_open(void)
{
    ohsm_ctx *c = calloc(1, sizeof(*c));
    if (c == NULL) return NULL;
    c->sock = -1;
    if (sodium_init() < 0 || !crypto_aead_aes256gcm_is_available()) { free(c); return NULL; }

    const char *addr = getenv("OPENHSM_ADDR");
    if (addr && *addr) {
        /* Network transport via openhsm-daemon (containers / remote / k8s). */
        c->sock = connect_daemon(addr);
        if (c->sock < 0) { free(c); return NULL; }
    } else {
        /* Direct USB transport. */
        if (libusb_init(&c->usb) != 0) { free(c); return NULL; }
        c->dev = libusb_open_device_with_vid_pid(c->usb, OPENHSM_VID, OPENHSM_PID);
        if (c->dev == NULL) { libusb_exit(c->usb); free(c); return NULL; }
        if (libusb_claim_interface(c->dev, 0) != 0) {
            libusb_close(c->dev); libusb_exit(c->usb); free(c); return NULL;
        }
        c->claimed = 1;
    }
    establish_session(c);  /* best-effort; plaintext fallback if it fails */
    if (getenv("OPENHSM_DEBUG")) {
        if (c->session_ok)
            fprintf(stderr, "openhsm: secure session established (id=0x%08x)\n", c->session_id);
        else
            fprintf(stderr, "openhsm: WARNING running PLAINTEXT (handshake failed)\n");
    }
    return c;
}

void ohsm_close(ohsm_ctx *c)
{
    if (c == NULL) return;
    if (c->session_ok) {
        uint8_t resp[HSM_MAX_MSG]; int rl;
        /* CLOSE_SESSION carries the session id in the header; send plaintext. */
        uint8_t pkt[HSM_HEADER_SIZE];
        memset(pkt, 0, sizeof(pkt));
        hsm_header_t h; memset(&h, 0, sizeof(h));
        h.command = HSM_CMD_CLOSE_SESSION; h.session_id = c->session_id;
        memcpy(pkt, &h, sizeof(h));
        send_recv_raw(c, pkt, sizeof(pkt), resp, sizeof(resp), &rl);
        sodium_memzero(c->k_c2d, sizeof(c->k_c2d));
        sodium_memzero(c->k_d2c, sizeof(c->k_d2c));
    }
    if (c->sock >= 0) close(c->sock);
    if (c->claimed) libusb_release_interface(c->dev, 0);
    if (c->dev) libusb_close(c->dev);
    if (c->usb) libusb_exit(c->usb);
    free(c);
}

int ohsm_cmd(ohsm_ctx *c, uint16_t command,
             const uint8_t *payload, uint16_t plen,
             uint8_t *resp, int resp_cap, int *resp_len)
{
    if (c == NULL) return -1;
    if (!c->session_ok) {
        return cmd_plain(c, command, payload, plen, resp, resp_cap, resp_len);
    }

    /* Build the inner plaintext packet. */
    uint8_t inner[HSM_MAX_MSG];
    if ((int)(HSM_HEADER_SIZE + plen) > (int)sizeof(inner)) return -1;
    memset(inner, 0, HSM_HEADER_SIZE);
    hsm_header_t ih; memset(&ih, 0, sizeof(ih));
    ih.command = command; ih.payload_length = plen;
    memcpy(inner, &ih, sizeof(ih));
    if (plen && payload) memcpy(inner + HSM_HEADER_SIZE, payload, plen);
    int inner_len = HSM_HEADER_SIZE + plen;

    /* Outer envelope header. */
    uint32_t ctr = c->counter++;
    uint8_t pkt[HSM_MAX_MSG];
    hsm_header_t oh; memset(&oh, 0, sizeof(oh));
    oh.command = HSM_CMD_SESSION_DATA;
    oh.flags = HSM_FLAG_ENCRYPTED;
    oh.session_id = c->session_id;
    oh.counter = ctr;
    oh.payload_length = (uint16_t)(inner_len + 16);
    memcpy(pkt, &oh, HSM_HEADER_SIZE);

    uint8_t nonce[12];
    make_nonce(nonce, NONCE_DIR_C2D, c->session_id, ctr);
    uint8_t tag[16]; unsigned long long taglen = 0;
    crypto_aead_aes256gcm_encrypt_detached(pkt + HSM_HEADER_SIZE, tag, &taglen,
        inner, inner_len, pkt, HSM_HEADER_SIZE, NULL, nonce, c->k_c2d);
    memcpy(pkt + HSM_HEADER_SIZE + inner_len, tag, 16);

    uint8_t rbuf[HSM_MAX_MSG]; int rl = 0;
    if (send_recv_raw(c, pkt, HSM_HEADER_SIZE + inner_len + 16, rbuf, sizeof(rbuf), &rl) != 0)
        return -1;

    hsm_header_t rh; memcpy(&rh, rbuf, sizeof(rh));
    if (!(rh.flags & HSM_FLAG_ENCRYPTED)) {
        /* Unencrypted error reply (e.g. NO_SESSION); pass it through. */
        if (rl > resp_cap) rl = resp_cap;
        memcpy(resp, rbuf, rl);
        *resp_len = rl;
        return 0;
    }
    int ct_len = (int)rh.payload_length - 16;
    if (ct_len < (int)HSM_HEADER_SIZE) return -1;
    make_nonce(nonce, NONCE_DIR_D2C, c->session_id, rh.counter);
    if (crypto_aead_aes256gcm_decrypt_detached(resp, NULL,
            rbuf + HSM_HEADER_SIZE, ct_len, rbuf + HSM_HEADER_SIZE + ct_len,
            rbuf, HSM_HEADER_SIZE, nonce, c->k_d2c) != 0)
        return -1;   /* response authentication failed */
    *resp_len = ct_len;
    return 0;
}
