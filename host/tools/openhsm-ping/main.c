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
    hsm_header_t rh;

    /* FIND all (paged) */
    uint32_t found_id = 0;
    uint16_t offset = 0, total = 0, scanned = 0;
    int header_done = 0;
    do {
        hsm_find_req_t freq; memset(&freq, 0, sizeof(freq));
        freq.offset = offset;   /* {offset, max=0}: page, no label filter */
        if (send_command(h, HSM_CMD_FIND_OBJECT, (uint8_t *)&freq, 4,
                         resp, sizeof(resp), &resp_len) != 0) return;
        memcpy(&rh, resp, sizeof(rh));
        if (rh.status != HSM_OK) { printf("KEYS  -> FIND failed (0x%04x)\n", rh.status); return; }
        hsm_find_resp_t fr; memcpy(&fr, resp + HSM_HEADER_SIZE, sizeof(fr));
        total = fr.total;
        if (!header_done) { printf("KEYS  -> %u object(s) in store:\n", total); header_done = 1; }
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
        scanned += fr.count;
        if (fr.count == 0) break;
        offset = fr.next_offset;
    } while (scanned < total);

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

/* Find an object by exact label, or generate one. Returns id (0 on failure). */
static uint32_t find_or_generate_ex(libusb_device_handle *h, const char *label,
                                    uint16_t algo, uint16_t caps, uint8_t exportable)
{
    uint8_t resp[HSM_MAX_MSG];
    int resp_len = 0;
    size_t llen = strlen(label);
    hsm_header_t rh;

    uint16_t offset = 0, total = 0, scanned = 0;
    do {
        hsm_find_req_t freq; memset(&freq, 0, sizeof(freq));
        freq.offset = offset;   /* {offset, max=0}: page, no label filter */
        if (send_command(h, HSM_CMD_FIND_OBJECT, (uint8_t *)&freq, 4,
                         resp, sizeof(resp), &resp_len) != 0)
            break;
        memcpy(&rh, resp, sizeof(rh));
        if (rh.status != HSM_OK) break;
        hsm_find_resp_t fr; memcpy(&fr, resp + HSM_HEADER_SIZE, sizeof(fr));
        total = fr.total;
        const uint8_t *p = resp + HSM_HEADER_SIZE + sizeof(fr);
        for (int i = 0; i < fr.count; i++) {
            hsm_obj_info_t o; memcpy(&o, p + i * sizeof(o), sizeof(o));
            if (o.algorithm == algo && memcmp(o.label, label, llen) == 0 &&
                (llen == HSM_LABEL_LEN || o.label[llen] == 0))
                return o.id;
        }
        scanned += fr.count;
        if (fr.count == 0) break;
        offset = fr.next_offset;
    } while (scanned < total);

    hsm_genkey_req_t rq;
    memset(&rq, 0, sizeof(rq));
    rq.algorithm = algo;
    rq.key_bits = 256;
    rq.capabilities = caps;
    rq.exportable = exportable;
    memcpy(rq.label, label, llen);
    if (send_command(h, HSM_CMD_GENERATE_KEY, (uint8_t *)&rq, sizeof(rq),
                     resp, sizeof(resp), &resp_len) != 0) return 0;
    memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK) {
        printf("       (GENERATE %s failed: status=0x%04x)\n", label, rh.status);
        return 0;
    }
    hsm_obj_info_t o; memcpy(&o, resp + HSM_HEADER_SIZE, sizeof(o));
    return o.id;
}

static uint32_t find_or_generate(libusb_device_handle *h, const char *label,
                                 uint16_t algo, uint16_t caps)
{
    return find_or_generate_ex(h, label, algo, caps, 0);
}

/* Key-using operations: Ed25519 sign (host-verified) + HMAC (determinism). */
static void do_keyops(libusb_device_handle *h)
{
    uint8_t resp[HSM_MAX_MSG];
    int resp_len = 0;
    const char msg[] = "OpenHSM signs this message";

    /* ---- HMAC-SHA256 ---- */
    {
        const char *hmsg = msg;  /* 26 bytes (len % 4 == 2): arbitrary length */
        uint32_t mid = find_or_generate(h, "openhsm-mac-key", HSM_KEY_HMAC256, HSM_CAP_SIGN);
        if (mid == 0) { printf("HMAC  -> could not obtain HMAC key\n"); }
        else {
            uint8_t mac1[32], mac2[32];
            int hok = 1;
            for (int pass = 0; pass < 2; pass++) {
                uint8_t req[sizeof(hsm_keyop_req_t) + 64];
                hsm_keyop_req_t op = { .id = mid, .msg_len = (uint16_t)strlen(hmsg) };
                memcpy(req, &op, sizeof(op));
                memcpy(req + sizeof(op), hmsg, strlen(hmsg));
                if (send_command(h, HSM_CMD_HMAC, req, sizeof(op) + strlen(hmsg),
                                 resp, sizeof(resp), &resp_len) != 0) { hok = 0; break; }
                hsm_header_t rh; memcpy(&rh, resp, sizeof(rh));
                if (rh.status != HSM_OK || resp_len < (int)(HSM_HEADER_SIZE + 32)) {
                    printf("HMAC  -> failed (0x%04x)\n", rh.status); hok = 0; break;
                }
                memcpy(pass == 0 ? mac1 : mac2, resp + HSM_HEADER_SIZE, 32);
            }
            if (hok) {
                printf("HMAC  -> id=%u mac=", mid);
                for (int i = 0; i < 8; i++) printf("%02x", mac1[i]);
                printf("..  deterministic=%s  [%s]\n",
                       memcmp(mac1, mac2, 32) == 0 ? "yes" : "NO",
                       memcmp(mac1, mac2, 32) == 0 ? "OK" : "FAIL");
            }
        }
    }

    /* ---- Ed25519 SIGN, verified on the host with the public key ---- */
    uint32_t sid = find_or_generate(h, "openhsm-sign-key", HSM_KEY_ED25519, HSM_CAP_SIGN);
    if (sid == 0) { printf("SIGN  -> could not obtain Ed25519 key\n"); }
    else {
        /* GET_PUBLIC */
        uint8_t pub[32];
        hsm_objid_req_t gq = { .id = sid };
        if (send_command(h, HSM_CMD_GET_PUBLIC, (uint8_t *)&gq, sizeof(gq),
                         resp, sizeof(resp), &resp_len) != 0) return;
        hsm_header_t rh; memcpy(&rh, resp, sizeof(rh));
        if (rh.status != HSM_OK) { printf("SIGN  -> GET_PUBLIC failed (0x%04x)\n", rh.status); return; }
        memcpy(pub, resp + HSM_HEADER_SIZE, 32);

        /* SIGN */
        uint8_t req[sizeof(hsm_keyop_req_t) + 64];
        hsm_keyop_req_t op = { .id = sid, .msg_len = (uint16_t)strlen(msg) };
        memcpy(req, &op, sizeof(op));
        memcpy(req + sizeof(op), msg, strlen(msg));
        if (send_command(h, HSM_CMD_SIGN, req, sizeof(op) + strlen(msg),
                         resp, sizeof(resp), &resp_len) != 0) return;
        memcpy(&rh, resp, sizeof(rh));
        if (rh.status != HSM_OK || resp_len < (int)(HSM_HEADER_SIZE + 64)) {
            printf("SIGN  -> failed (0x%04x)\n", rh.status); return;
        }
        const uint8_t *sig = resp + HSM_HEADER_SIZE;

        int ok = crypto_sign_verify_detached(sig, (const uint8_t *)msg,
                                             strlen(msg), pub) == 0;
        /* Negative control: a tampered message must NOT verify. */
        uint8_t bad[sizeof(msg)]; memcpy(bad, msg, strlen(msg)); bad[0] ^= 1;
        int bad_ok = crypto_sign_verify_detached(sig, bad, strlen(msg), pub) == 0;

        printf("SIGN  -> Ed25519 id=%u pub=", sid);
        for (int i = 0; i < 8; i++) printf("%02x", pub[i]);
        printf("..  verify=%s tamper-rejected=%s  [%s]\n",
               ok ? "OK" : "FAIL", bad_ok ? "NO" : "yes",
               (ok && !bad_ok) ? "OK" : "FAIL");
    }

}

/* Fetch the public key of an asymmetric object into pub[32]. Returns 1 on ok. */
static int get_public(libusb_device_handle *h, uint32_t id, uint8_t pub[32])
{
    uint8_t resp[HSM_MAX_MSG]; int rl;
    hsm_objid_req_t q = { .id = id };
    if (send_command(h, HSM_CMD_GET_PUBLIC, (uint8_t *)&q, sizeof(q), resp, sizeof(resp), &rl) != 0)
        return 0;
    hsm_header_t rh; memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK || rl < (int)(HSM_HEADER_SIZE + 32)) return 0;
    memcpy(pub, resp + HSM_HEADER_SIZE, 32);
    return 1;
}

/* Wrapped export round-trip: WRAP an exportable key under a wrapping key, then
 * UNWRAP it into a new object; verify the key survived (same Ed25519 pubkey). */
static void do_wrap(libusb_device_handle *h)
{
    uint8_t resp[HSM_MAX_MSG]; int rl;
    hsm_header_t rh;

    uint32_t wid = find_or_generate(h, "openhsm-wrap-key", HSM_KEY_AES256,
                                    HSM_CAP_WRAP | HSM_CAP_UNWRAP);
    /* An EXPORTABLE Ed25519 target (distinct from the non-exportable sign key). */
    uint32_t tid = find_or_generate_ex(h, "openhsm-exp-key", HSM_KEY_ED25519,
                                       HSM_CAP_SIGN, 1);
    if (wid == 0 || tid == 0) { printf("WRAP  -> could not obtain keys\n"); return; }

    uint8_t tpub[32];
    if (!get_public(h, tid, tpub)) { printf("WRAP  -> GET_PUBLIC(target) failed\n"); return; }

    /* WRAP */
    hsm_wrap_req_t wq = { .wrap_id = wid, .target_id = tid };
    if (send_command(h, HSM_CMD_WRAP, (uint8_t *)&wq, sizeof(wq), resp, sizeof(resp), &rl) != 0) return;
    memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK) { printf("WRAP  -> failed (0x%04x)%s\n", rh.status,
        rh.status == HSM_ERR_NOT_AUTHORIZED ? " (target not exportable?)" : ""); return; }
    int blob_len = rh.payload_length;
    uint8_t blob[256];
    memcpy(blob, resp + HSM_HEADER_SIZE, blob_len);
    printf("WRAP  -> %d-byte blob from key id=%u under wrap-key id=%u\n", blob_len, tid, wid);

    /* UNWRAP into a new object */
    uint8_t ureq[sizeof(hsm_unwrap_req_t) + 256];
    hsm_unwrap_req_t uq;
    memset(&uq, 0, sizeof(uq));
    uq.wrap_id = wid;
    uq.capabilities = HSM_CAP_SIGN;
    uq.exportable = 0;
    memcpy(uq.label, "openhsm-unwrapped", 17);
    memcpy(ureq, &uq, sizeof(uq));
    memcpy(ureq + sizeof(uq), blob, blob_len);
    if (send_command(h, HSM_CMD_UNWRAP, ureq, sizeof(uq) + blob_len, resp, sizeof(resp), &rl) != 0) return;
    memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK) { printf("UNWRAP-> failed (0x%04x)\n", rh.status); return; }
    hsm_obj_info_t o; memcpy(&o, resp + HSM_HEADER_SIZE, sizeof(o));

    /* Verify: the unwrapped key has the SAME public key as the original. */
    uint8_t upub[32];
    if (!get_public(h, o.id, upub)) { printf("UNWRAP-> GET_PUBLIC(new) failed\n"); return; }
    printf("UNWRAP-> new id=%u  pubkey-matches-original=%s  [%s]\n",
           o.id, memcmp(tpub, upub, 32) == 0 ? "yes" : "NO",
           memcmp(tpub, upub, 32) == 0 ? "OK" : "FAIL");

    /* Clean up the imported object so repeated runs don't fill the store. */
    hsm_objid_req_t dq = { .id = o.id };
    send_command(h, HSM_CMD_DELETE_OBJECT, (uint8_t *)&dq, sizeof(dq), resp, sizeof(resp), &rl);
}

/* AES-256-GCM encrypt/decrypt with a stored key: round-trip + tamper-reject. */
static void do_aead(libusb_device_handle *h)
{
    uint8_t resp[HSM_MAX_MSG]; int rl;
    hsm_header_t rh;
    uint32_t kid = find_or_generate(h, "openhsm-aead-key", HSM_KEY_AES256,
                                    HSM_CAP_ENCRYPT | HSM_CAP_DECRYPT);
    if (kid == 0) { printf("AEAD  -> could not obtain AES key\n"); return; }

    const char pt[] = "Vault seal master-key material (test)";
    uint16_t pt_len = (uint16_t)strlen(pt);
    uint8_t aad[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t nonce[12];
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0x10 + i);

    /* ENCRYPT: req(20) + aad + pt */
    uint8_t req[256];
    hsm_aead_req_t er = { .key_id = kid, .aad_len = sizeof(aad), .data_len = pt_len };
    memcpy(er.nonce, nonce, 12);
    memcpy(req, &er, sizeof(er));
    memcpy(req + sizeof(er), aad, sizeof(aad));
    memcpy(req + sizeof(er) + sizeof(aad), pt, pt_len);
    if (send_command(h, HSM_CMD_ENCRYPT, req, sizeof(er) + sizeof(aad) + pt_len,
                     resp, sizeof(resp), &rl) != 0) return;
    memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK || rh.payload_length != pt_len + 16) {
        printf("AEAD  -> ENCRYPT failed (0x%04x)\n", rh.status); return;
    }
    uint8_t ct[256], tag[16];
    memcpy(ct, resp + HSM_HEADER_SIZE, pt_len);
    memcpy(tag, resp + HSM_HEADER_SIZE + pt_len, 16);
    printf("AEAD  -> ENCRYPT id=%u ct[0:8]=", kid);
    for (int i = 0; i < 8; i++) printf("%02x", ct[i]);
    printf("\n");

    /* DECRYPT: req(20) + aad + ct + tag */
    hsm_aead_req_t dr = { .key_id = kid, .aad_len = sizeof(aad), .data_len = pt_len };
    memcpy(dr.nonce, nonce, 12);
    memcpy(req, &dr, sizeof(dr));
    memcpy(req + sizeof(dr), aad, sizeof(aad));
    memcpy(req + sizeof(dr) + sizeof(aad), ct, pt_len);
    memcpy(req + sizeof(dr) + sizeof(aad) + pt_len, tag, 16);
    int dlen = sizeof(dr) + sizeof(aad) + pt_len + 16;
    if (send_command(h, HSM_CMD_DECRYPT, req, dlen, resp, sizeof(resp), &rl) != 0) return;
    memcpy(&rh, resp, sizeof(rh));
    int roundtrip = (rh.status == HSM_OK && rh.payload_length == pt_len &&
                     memcmp(resp + HSM_HEADER_SIZE, pt, pt_len) == 0);

    /* Negative: flip a tag byte → decrypt must fail. */
    req[sizeof(dr) + sizeof(aad) + pt_len] ^= 1;
    int tamper_rejected = 0;
    if (send_command(h, HSM_CMD_DECRYPT, req, dlen, resp, sizeof(resp), &rl) == 0) {
        memcpy(&rh, resp, sizeof(rh));
        tamper_rejected = (rh.status != HSM_OK);
    }
    printf("AEAD  -> DECRYPT roundtrip=%s tamper-rejected=%s  [%s]\n",
           roundtrip ? "OK" : "FAIL", tamper_rejected ? "yes" : "NO",
           (roundtrip && tamper_rejected) ? "OK" : "FAIL");
}

/* Send a SET_PIN(old,new); returns the device status. */
static uint16_t set_pin(libusb_device_handle *h, const char *oldp, const char *newp)
{
    uint8_t req[2 + 64]; uint8_t resp[HSM_MAX_MSG]; int rl;
    req[0] = (uint8_t)strlen(oldp); req[1] = (uint8_t)strlen(newp);
    memcpy(req + 2, oldp, strlen(oldp));
    memcpy(req + 2 + strlen(oldp), newp, strlen(newp));
    if (send_command(h, HSM_CMD_SET_PIN, req, 2 + strlen(oldp) + strlen(newp),
                     resp, sizeof(resp), &rl) != 0) return HSM_ERR_INTERNAL;
    hsm_header_t *rh = (hsm_header_t *)resp;
    return rh->status;
}

static uint16_t auth_pin(libusb_device_handle *h, const char *pin)
{
    uint8_t resp[HSM_MAX_MSG]; int rl;
    if (send_command(h, HSM_CMD_AUTH, (const uint8_t *)pin, (uint16_t)strlen(pin),
                     resp, sizeof(resp), &rl) != 0) return HSM_ERR_INTERNAL;
    return ((hsm_header_t *)resp)->status;
}

/* Change the PIN to a new value, verify login, then restore the default. */
static void do_setpin(libusb_device_handle *h)
{
    uint16_t s1 = set_pin(h, "123456", "654321");
    uint16_t a1 = auth_pin(h, "654321");          /* new PIN works */
    uint16_t s2 = set_pin(h, "654321", "123456");  /* restore default */
    uint16_t a2 = auth_pin(h, "123456");
    int ok = (s1 == HSM_OK && a1 == HSM_OK && s2 == HSM_OK && a2 == HSM_OK);
    printf("PIN   -> change=0x%04x login-new=0x%04x restore=0x%04x login-default=0x%04x  [%s]\n",
           s1, a1, s2, a2, ok ? "OK" : "FAIL");
}

static const char *ev_name(uint16_t e)
{
    switch (e) {
    case HSM_EV_BOOT: return "BOOT"; case HSM_EV_AUTH_OK: return "AUTH_OK";
    case HSM_EV_AUTH_FAIL: return "AUTH_FAIL"; case HSM_EV_KEYGEN: return "KEYGEN";
    case HSM_EV_KEYDEL: return "KEYDEL"; case HSM_EV_SIGN: return "SIGN";
    case HSM_EV_HMAC: return "HMAC"; case HSM_EV_WRAP: return "WRAP";
    case HSM_EV_UNWRAP: return "UNWRAP"; case HSM_EV_ENCRYPT: return "ENCRYPT";
    case HSM_EV_DECRYPT: return "DECRYPT"; case HSM_EV_SET_PIN: return "SET_PIN";
    default: return "?";
    }
}

/* Read the audit log and verify the sequence is strictly increasing. */
static void do_audit(libusb_device_handle *h)
{
    uint8_t resp[HSM_MAX_MSG]; int rl;
    hsm_auditlog_req_t rq = { .max_entries = 20 };
    if (send_command(h, HSM_CMD_GET_AUDIT_LOG, (uint8_t *)&rq, sizeof(rq),
                     resp, sizeof(resp), &rl) != 0) return;
    hsm_header_t rh; memcpy(&rh, resp, sizeof(rh));
    if (rh.status != HSM_OK) { printf("AUDIT -> failed (0x%04x)\n", rh.status); return; }
    hsm_auditlog_resp_t ar; memcpy(&ar, resp + HSM_HEADER_SIZE, sizeof(ar));
    const uint8_t *p = resp + HSM_HEADER_SIZE + sizeof(ar);
    printf("AUDIT -> %u recent entries (next_seq=%u):\n", ar.count, ar.next_seq);
    uint32_t prev = 0; int mono = 1;
    for (int i = 0; i < ar.count; i++) {
        hsm_audit_entry_t e; memcpy(&e, p + i * sizeof(e), sizeof(e));
        printf("         seq=%-4u %-9s arg=%-4u mac=", e.seq, ev_name(e.event), e.arg);
        for (int j = 0; j < 4; j++) printf("%02x", e.mac[j]);
        printf("\n");
        if (i > 0 && e.seq <= prev) mono = 0;
        prev = e.seq;
    }
    printf("AUDIT -> monotonic seq = %s  [%s]\n", mono ? "yes" : "NO", mono ? "OK" : "FAIL");
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

    /* ---- AUTH (default PIN); key operations are gated behind login ---- */
    if (send_command(h, HSM_CMD_AUTH, (const uint8_t *)"123456", 6,
                     resp, sizeof(resp), &resp_len) == 0) {
        hsm_header_t *rh = (hsm_header_t *)resp;
        const hsm_auth_resp_t *ar = (const hsm_auth_resp_t *)(resp + HSM_HEADER_SIZE);
        printf("AUTH  -> status=0x%04x tries_left=%u  [%s]\n",
               rh->status, ar->tries_left, rh->status == HSM_OK ? "OK" : "FAIL");
    }

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

    /* ---- Key-using ops (Ed25519 sign verified on host, HMAC) ---- */
    do_keyops(h);

    /* ---- Wrapped export round-trip (WRAP -> UNWRAP -> verify) ---- */
    do_wrap(h);

    /* ---- AES-256-GCM encrypt/decrypt with a stored key ---- */
    do_aead(h);

    /* ---- Change PIN (and restore the default) ---- */
    do_setpin(h);

    /* ---- Audit log (events recorded for the operations above) ---- */
    do_audit(h);

    libusb_release_interface(h, 0);
    libusb_close(h);
    libusb_exit(ctx);
    return 0;
}
