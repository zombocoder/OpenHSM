/**
 * @file    main.c
 * @brief   OpenHSM host test client: PING + GET_INFO over USB bulk via libusb.
 *
 * Usage: openhsm-ping
 *
 * Talks the OpenHSM packet protocol (see hsm_proto.h) to the firmware's
 * EP1 bulk endpoints. This is a milestone-1 smoke test, not the PKCS#11
 * provider.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <libusb.h>
#include <sodium.h>

#include "hsm_proto.h"

#define OPENHSM_VID 0x0483
#define OPENHSM_PID 0x5750
#define EP_OUT      0x01
#define EP_IN       0x81
#define TIMEOUT_MS  1000

/* Send a fully-formed packet and read the (multi-packet) response. */
static int bulk_xfer(libusb_device_handle *h, const uint8_t *out, int out_len,
                     uint8_t *resp, int resp_cap, int *resp_len)
{
    int transferred = 0;
    int rc = libusb_bulk_transfer(h, EP_OUT, (uint8_t *)out, out_len,
                                  &transferred, TIMEOUT_MS);
    if (rc != 0) {
        fprintf(stderr, "bulk OUT failed: %s\n", libusb_error_name(rc));
        return rc;
    }

    /* Read in 64-byte chunks until we have the full message, driven by the
     * header's payload_length (matches the device framing). */
    int got = 0;
    while (got < (int)HSM_HEADER_SIZE) {
        int n = 0, want = HSM_MAX_PACKET;
        if (want > resp_cap - got) want = resp_cap - got;
        rc = libusb_bulk_transfer(h, EP_IN, resp + got, want, &n, TIMEOUT_MS);
        if (rc != 0) { fprintf(stderr, "bulk IN failed: %s\n", libusb_error_name(rc)); return rc; }
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
        rc = libusb_bulk_transfer(h, EP_IN, resp + got, want, &n, TIMEOUT_MS);
        if (rc != 0) { fprintf(stderr, "bulk IN failed: %s\n", libusb_error_name(rc)); return rc; }
        if (n == 0) break;
        got += n;
    }
    *resp_len = got;
    return 0;
}

/* Build a plaintext packet (header + payload) and exchange it. */
static int send_command(libusb_device_handle *h, uint16_t command,
                         const uint8_t *payload, uint16_t payload_len,
                         uint8_t *resp, int resp_cap, int *resp_len)
{
    uint8_t pkt[HSM_MAX_MSG];
    memset(pkt, 0, HSM_HEADER_SIZE);
    hsm_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.command        = command;
    hdr.payload_length = payload_len;
    memcpy(pkt, &hdr, sizeof(hdr));
    if (payload_len > 0 && payload != NULL) {
        memcpy(pkt + HSM_HEADER_SIZE, payload, payload_len);
    }
    return bulk_xfer(h, pkt, HSM_HEADER_SIZE + payload_len, resp, resp_cap, resp_len);
}

static void make_nonce(uint8_t n[12], uint8_t dir, uint32_t sid, uint32_t ctr)
{
    n[0] = dir; n[1] = 0; n[2] = 0; n[3] = 0;
    n[4] = (uint8_t)sid;  n[5] = (uint8_t)(sid >> 8);
    n[6] = (uint8_t)(sid >> 16); n[7] = (uint8_t)(sid >> 24);
    n[8] = (uint8_t)ctr;  n[9] = (uint8_t)(ctr >> 8);
    n[10] = (uint8_t)(ctr >> 16); n[11] = (uint8_t)(ctr >> 24);
}

/* Full secure-session demo: ECDH handshake, then an encrypted RANDOM(32). */
static void do_session(libusb_device_handle *h)
{
    static const char INFO[] = "OpenHSM/v1 session keys";
    uint8_t resp[HSM_MAX_MSG];
    int resp_len = 0;

    /* 1. Ephemeral X25519 keypair + host nonce. */
    uint8_t eph_priv[32], eph_pub[32], host_nonce[32];
    randombytes_buf(eph_priv, sizeof(eph_priv));
    randombytes_buf(host_nonce, sizeof(host_nonce));
    crypto_scalarmult_curve25519_base(eph_pub, eph_priv);

    /* 2. OPEN_SESSION { eph_pub || host_nonce }. */
    uint8_t open_payload[64];
    memcpy(open_payload, eph_pub, 32);
    memcpy(open_payload + 32, host_nonce, 32);
    if (send_command(h, HSM_CMD_OPEN_SESSION, open_payload, sizeof(open_payload),
                     resp, sizeof(resp), &resp_len) != 0) return;
    hsm_header_t rh;
    memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK || resp_len < (int)(HSM_HEADER_SIZE + 64)) {
        printf("SESS  -> OPEN_SESSION failed (status=0x%04x)\n", rh.status);
        return;
    }
    uint32_t sid = rh.session_id;
    uint8_t dev_pub[32], dev_nonce[32];
    memcpy(dev_pub, resp + HSM_HEADER_SIZE, 32);
    memcpy(dev_nonce, resp + HSM_HEADER_SIZE + 32, 32);

    /* 3. Shared secret -> HKDF -> directional keys. */
    uint8_t shared[32];
    if (crypto_scalarmult_curve25519(shared, eph_priv, dev_pub) != 0) {
        printf("SESS  -> X25519 failed\n"); return;
    }
    uint8_t salt[64], prk[crypto_kdf_hkdf_sha256_KEYBYTES], okm[64];
    memcpy(salt, host_nonce, 32);
    memcpy(salt + 32, dev_nonce, 32);
    crypto_kdf_hkdf_sha256_extract(prk, salt, sizeof(salt), shared, sizeof(shared));
    crypto_kdf_hkdf_sha256_expand(okm, sizeof(okm), INFO, sizeof(INFO) - 1, prk);
    const uint8_t *k_c2d = okm, *k_d2c = okm + 32;

    /* 4. Encrypted RANDOM(32): inner packet -> GCM -> envelope. */
    uint8_t inner[HSM_HEADER_SIZE + 2];
    memset(inner, 0, sizeof(inner));
    { hsm_header_t ih; memset(&ih, 0, sizeof(ih));
      ih.command = HSM_CMD_RANDOM; ih.payload_length = 2;
      memcpy(inner, &ih, sizeof(ih)); inner[HSM_HEADER_SIZE] = 32; }

    uint32_t counter = 1;
    uint8_t pkt[HSM_MAX_MSG];
    hsm_header_t oh; memset(&oh, 0, sizeof(oh));
    oh.command = HSM_CMD_SESSION_DATA;
    oh.flags = HSM_FLAG_ENCRYPTED;
    oh.session_id = sid;
    oh.counter = counter;
    oh.payload_length = (uint16_t)(sizeof(inner) + 16);
    memcpy(pkt, &oh, HSM_HEADER_SIZE);

    uint8_t nonce[12];
    make_nonce(nonce, HSM_NONCE_DIR_C2D, sid, counter);
    uint8_t tag[16]; unsigned long long taglen = 0;
    crypto_aead_aes256gcm_encrypt_detached(
        pkt + HSM_HEADER_SIZE, tag, &taglen,
        inner, sizeof(inner), pkt, HSM_HEADER_SIZE, NULL, nonce, k_c2d);
    memcpy(pkt + HSM_HEADER_SIZE + sizeof(inner), tag, 16);

    if (bulk_xfer(h, pkt, HSM_HEADER_SIZE + sizeof(inner) + 16,
                  resp, sizeof(resp), &resp_len) != 0) return;

    /* 5. Decrypt the response envelope and read the inner result. */
    memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK || !(rh.flags & HSM_FLAG_ENCRYPTED)) {
        printf("SESS  -> encrypted cmd failed (status=0x%04x)\n", rh.status);
        return;
    }
    int ct_len = (int)rh.payload_length - 16;
    if (ct_len < (int)HSM_HEADER_SIZE) { printf("SESS  -> short envelope\n"); return; }
    make_nonce(nonce, HSM_NONCE_DIR_D2C, sid, rh.counter);
    uint8_t inner_out[HSM_MAX_MSG];
    if (crypto_aead_aes256gcm_decrypt_detached(
            inner_out, NULL, resp + HSM_HEADER_SIZE, ct_len,
            resp + HSM_HEADER_SIZE + ct_len, resp, HSM_HEADER_SIZE, nonce, k_d2c) != 0) {
        printf("SESS  -> response authentication FAILED\n");
        return;
    }
    hsm_header_t inh; memcpy(&inh, inner_out, sizeof(inh));
    printf("SESS  -> session 0x%08x established; encrypted RANDOM(32)=", sid);
    for (int i = 0; i < 32 && i < inh.payload_length; i++)
        printf("%02x", inner_out[HSM_HEADER_SIZE + i]);
    printf("  [%s]\n", inh.status == HSM_OK ? "OK" : "inner error");
}

static const char *alg_name(uint16_t a)
{
    switch (a) {
    case HSM_KEY_AES256:  return "AES256";
    case HSM_KEY_HMAC256: return "HMAC256";
    case HSM_KEY_ED25519: return "Ed25519";
    case HSM_KEY_X25519:  return "X25519";
    default:              return "?";
    }
}

/* Key store demo: list objects, generate a test key if absent (so a power
 * cycle without reflashing demonstrates persistence), fetch it back. */
static void do_keystore(libusb_device_handle *h)
{
    static const char TEST_LABEL[] = "openhsm-test-key";
    uint8_t resp[HSM_MAX_MSG];
    int resp_len = 0;

    /* FIND all */
    if (send_command(h, HSM_CMD_FIND_OBJECT, NULL, 0, resp, sizeof(resp), &resp_len) != 0) return;
    hsm_header_t rh; memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK) { printf("KEYS  -> FIND failed (0x%04x)\n", rh.status); return; }
    hsm_find_resp_t fr; memcpy(&fr, resp + HSM_HEADER_SIZE, sizeof(fr));
    printf("KEYS  -> %u object(s) in store:\n", fr.count);

    uint32_t found_id = 0;
    const uint8_t *p = resp + HSM_HEADER_SIZE + sizeof(fr);
    for (int i = 0; i < fr.count; i++) {
        hsm_obj_info_t o; memcpy(&o, p + i * sizeof(o), sizeof(o));
        char lbl[HSM_LABEL_LEN + 1] = {0};
        memcpy(lbl, o.label, HSM_LABEL_LEN);
        printf("         id=%u alg=%s caps=0x%04x bits=%u exp=%u seq=%u label=\"%s\"\n",
               o.id, alg_name(o.algorithm), o.capabilities, o.key_bits,
               o.exportable, o.created_seq, lbl);
        if (memcmp(o.label, TEST_LABEL, sizeof(TEST_LABEL) - 1) == 0 &&
            o.label[sizeof(TEST_LABEL) - 1] == 0)
            found_id = o.id;
    }

    if (found_id != 0) {
        printf("KEYS  -> test key persisted across boot: id=%u  [PERSIST OK]\n", found_id);
    } else {
        hsm_genkey_req_t rq;
        memset(&rq, 0, sizeof(rq));
        rq.algorithm = HSM_KEY_AES256;
        rq.key_bits = 256;
        rq.capabilities = HSM_CAP_ENCRYPT | HSM_CAP_DECRYPT;
        rq.exportable = 0;
        memcpy(rq.label, TEST_LABEL, sizeof(TEST_LABEL) - 1);
        if (send_command(h, HSM_CMD_GENERATE_KEY, (uint8_t *)&rq, sizeof(rq),
                         resp, sizeof(resp), &resp_len) != 0) return;
        memcpy(&rh, resp, sizeof(rh));
        if (rh.status != HSM_OK) { printf("KEYS  -> GENERATE failed (0x%04x)\n", rh.status); return; }
        hsm_obj_info_t o; memcpy(&o, resp + HSM_HEADER_SIZE, sizeof(o));
        found_id = o.id;
        printf("KEYS  -> generated AES-256 key id=%u (reset without reflashing to test persistence)\n", o.id);
    }

    /* GET_OBJECT round-trip */
    hsm_objid_req_t gq = { .id = found_id };
    if (send_command(h, HSM_CMD_GET_OBJECT, (uint8_t *)&gq, sizeof(gq),
                     resp, sizeof(resp), &resp_len) == 0) {
        memcpy(&rh, resp, sizeof(rh));
        if (rh.status == HSM_OK) {
            hsm_obj_info_t o; memcpy(&o, resp + HSM_HEADER_SIZE, sizeof(o));
            printf("KEYS  -> GET id=%u alg=%s usage=%u  [OK]\n",
                   o.id, alg_name(o.algorithm), o.usage_counter);
        } else {
            printf("KEYS  -> GET failed (0x%04x)\n", rh.status);
        }
    }
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        fprintf(stderr, "AES-256-GCM not available on this host CPU\n");
        return 1;
    }

    libusb_context *ctx = NULL;
    int rc = libusb_init(&ctx);
    if (rc != 0) {
        fprintf(stderr, "libusb_init failed: %s\n", libusb_error_name(rc));
        return 1;
    }

    libusb_device_handle *h =
        libusb_open_device_with_vid_pid(ctx, OPENHSM_VID, OPENHSM_PID);
    if (h == NULL) {
        fprintf(stderr, "device %04x:%04x not found (is the firmware running "
                        "and out of DFU mode?)\n", OPENHSM_VID, OPENHSM_PID);
        libusb_exit(ctx);
        return 1;
    }

    /* macOS: no kernel driver binds a vendor-class interface, so claiming
     * interface 0 succeeds directly. */
    rc = libusb_claim_interface(h, 0);
    if (rc != 0) {
        fprintf(stderr, "claim_interface failed: %s\n", libusb_error_name(rc));
        libusb_close(h);
        libusb_exit(ctx);
        return 1;
    }

    uint8_t resp[HSM_MAX_MSG];
    int resp_len = 0;

    /* ---- PING ---- */
    if (send_command(h, HSM_CMD_PING, NULL, 0, resp, sizeof(resp), &resp_len) == 0) {
        hsm_header_t *rh = (hsm_header_t *)resp;
        if (resp_len >= (int)(HSM_HEADER_SIZE + 4) && rh->status == HSM_OK) {
            uint32_t magic;
            memcpy(&magic, resp + HSM_HEADER_SIZE, 4);
            printf("PING  -> status=0x%04x magic=0x%08X %s\n",
                   rh->status, magic,
                   magic == HSM_PING_MAGIC ? "(OK)" : "(BAD MAGIC)");
        } else {
            printf("PING  -> unexpected response (len=%d status=0x%04x)\n",
                   resp_len, rh->status);
        }
    }

    /* ---- GET_INFO ---- */
    if (send_command(h, HSM_CMD_GET_INFO, NULL, 0, resp, sizeof(resp), &resp_len) == 0) {
        hsm_header_t *rh = (hsm_header_t *)resp;
        if (resp_len >= (int)(HSM_HEADER_SIZE + sizeof(hsm_info_t)) && rh->status == HSM_OK) {
            hsm_info_t info;
            memcpy(&info, resp + HSM_HEADER_SIZE, sizeof(info));
            printf("INFO  -> proto=0x%04x fw=%u.%u serial=",
                   info.proto_version,
                   (info.fw_version >> 8) & 0xFF, info.fw_version & 0xFF);
            for (int i = 0; i < 12; i++) printf("%02X", info.serial[i]);
            printf("\n");
        } else {
            printf("INFO  -> unexpected response (len=%d status=0x%04x)\n",
                   resp_len, rh->status);
        }
    }

    /* ---- SELFTEST (hardware crypto known-answer tests) ---- */
    if (send_command(h, HSM_CMD_SELFTEST, NULL, 0, resp, sizeof(resp), &resp_len) == 0) {
        hsm_header_t *rh = (hsm_header_t *)resp;
        if (rh->status == HSM_OK && resp_len >= (int)(HSM_HEADER_SIZE + sizeof(hsm_selftest_t))) {
            hsm_selftest_t st;
            memcpy(&st, resp + HSM_HEADER_SIZE, sizeof(st));
            printf("TEST  -> sha256=%s hmac=%s hkdf=%s gcm-enc=%s gcm-dec=%s x25519=%s x25519-pub=%s  [%s]\n",
                   st.sha256 ? "FAIL" : "ok", st.hmac ? "FAIL" : "ok",
                   st.hkdf ? "FAIL" : "ok", st.aesgcm_enc ? "FAIL" : "ok",
                   st.aesgcm_dec ? "FAIL" : "ok", st.x25519 ? "FAIL" : "ok",
                   st.x25519_pub ? "FAIL" : "ok",
                   st.overall ? "SELF-TEST FAILED" : "ALL PASS");
        } else {
            printf("TEST  -> unexpected response (len=%d status=0x%04x)\n",
                   resp_len, rh->status);
        }
    }

    /* ---- RANDOM (exercises multi-packet response framing) ---- */
    {
        uint16_t count = 128;
        uint8_t req[2] = { (uint8_t)(count & 0xFF), (uint8_t)(count >> 8) };
        if (send_command(h, HSM_CMD_RANDOM, req, sizeof(req), resp, sizeof(resp), &resp_len) == 0) {
            hsm_header_t *rh = (hsm_header_t *)resp;
            if (rh->status == HSM_OK && resp_len >= (int)(HSM_HEADER_SIZE + count)) {
                printf("RAND  -> %u bytes: ", count);
                for (int i = 0; i < (int)count; i++) printf("%02x", resp[HSM_HEADER_SIZE + i]);
                printf("\n");
            } else {
                printf("RAND  -> unexpected response (len=%d status=0x%04x)\n",
                       resp_len, rh->status);
            }
        }
    }

    /* ---- ECHO 64 bytes (exercises a MULTI-PACKET REQUEST: 80-byte send) ---- */
    {
        uint8_t pat[64];
        for (int i = 0; i < 64; i++) pat[i] = (uint8_t)(i * 7 + 3);
        if (send_command(h, HSM_CMD_ECHO, pat, sizeof(pat), resp, sizeof(resp), &resp_len) == 0) {
            hsm_header_t *rh = (hsm_header_t *)resp;
            int mismatch = -1;
            if (rh->status == HSM_OK && resp_len >= (int)(HSM_HEADER_SIZE + 64)) {
                for (int i = 0; i < 64; i++)
                    if (resp[HSM_HEADER_SIZE + i] != pat[i]) { mismatch = i; break; }
                printf("ECHO  -> 64 bytes %s%s\n",
                       mismatch < 0 ? "match (multi-packet request OK)" : "MISMATCH at byte ",
                       mismatch < 0 ? "" : "");
                if (mismatch >= 0)
                    printf("         first bad byte %d: sent 0x%02x got 0x%02x\n",
                           mismatch, pat[mismatch], resp[HSM_HEADER_SIZE + mismatch]);
            } else {
                printf("ECHO  -> unexpected (len=%d status=0x%04x)\n", resp_len, rh->status);
            }
        }
    }

    /* ---- Secure session (X25519 ECDH -> AES-256-GCM transport) ---- */
    do_session(h);

    /* ---- Key store (generate / find / get, persisted to flash) ---- */
    do_keystore(h);

    libusb_release_interface(h, 0);
    libusb_close(h);
    libusb_exit(ctx);
    return 0;
}
