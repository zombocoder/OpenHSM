/**
 * @file    hsm_command.c
 * @brief   OpenHSM command dispatcher.
 *
 * HSM_ProcessPacket routes: encrypted envelopes and session setup go to the
 * session layer; everything else is handled as plaintext here.
 */
#include "hsm_command.h"
#include "hsm_proto.h"
#include "hsm_rng.h"
#include "hsm_crypto.h"
#include "hsm_session.h"
#include "hsm_keystore.h"
#include "hsm_eddsa.h"
#include "hsm_x25519.h"
#include "hsm_hash.h"
#include "hsm_audit.h"

#include <string.h>
#include "stm32u5xx.h"

#define FW_VERSION_MAJOR 0u
#define FW_VERSION_MINOR 1u

/* Login state (RAM, cleared on power cycle). Sensitive key operations require
 * a prior successful AUTH. */
static int g_authenticated = 0;

/* Commands that operate on or create key material require login. */
static int command_needs_auth(uint16_t cmd)
{
    switch (cmd) {
    case HSM_CMD_GENERATE_KEY:
    case HSM_CMD_DELETE_OBJECT:
    case HSM_CMD_GET_PUBLIC:
    case HSM_CMD_HMAC:
    case HSM_CMD_SIGN:
    case HSM_CMD_WRAP:
    case HSM_CMD_UNWRAP:
    case HSM_CMD_ENCRYPT:
    case HSM_CMD_DECRYPT:
        return 1;
    default:
        return 0;   /* PING/INFO/SELFTEST/RANDOM/FIND/GET/AUTH/session: open */
    }
}

size_t HSM_BuildResponse(uint8_t *resp, const uint8_t *req_hdr,
                         uint16_t status, uint16_t payload_len)
{
    hsm_header_t hdr;
    memcpy(&hdr, req_hdr, sizeof(hdr));
    hdr.flags          = (uint16_t)(hdr.flags | HSM_FLAG_RESPONSE);
    hdr.payload_length = payload_len;
    hdr.status         = status;
    memcpy(resp, &hdr, sizeof(hdr));
    return sizeof(hdr) + payload_len;
}

static size_t build_response(uint8_t *resp, const hsm_header_t *req_hdr,
                             uint16_t status, uint16_t payload_len)
{
    return HSM_BuildResponse(resp, (const uint8_t *)req_hdr, status, payload_len);
}

/* Read the 96-bit STM32 unique device ID into a 12-byte buffer. */
static void read_uid(uint8_t out[12])
{
    const volatile uint32_t *uid = (const volatile uint32_t *)UID_BASE;
    uint32_t w;
    for (unsigned i = 0; i < 3; i++) {
        w = uid[i];
        out[i * 4 + 0] = (uint8_t)(w & 0xFF);
        out[i * 4 + 1] = (uint8_t)((w >> 8) & 0xFF);
        out[i * 4 + 2] = (uint8_t)((w >> 16) & 0xFF);
        out[i * 4 + 3] = (uint8_t)((w >> 24) & 0xFF);
    }
}

size_t HSM_ProcessPacket(const uint8_t *req, size_t req_len,
                         uint8_t *resp, size_t resp_cap)
{
    if (req_len < HSM_HEADER_SIZE || resp_cap < HSM_HEADER_SIZE) {
        return 0;
    }

    hsm_header_t hdr;
    memcpy(&hdr, req, sizeof(hdr));

    if (hdr.flags & HSM_FLAG_ENCRYPTED) {
        return HSM_Session_Unwrap(req, req_len, resp, resp_cap);
    }
    switch (hdr.command) {
    case HSM_CMD_OPEN_SESSION:
        return HSM_Session_Open(req, req_len, resp, resp_cap);
    case HSM_CMD_CLOSE_SESSION:
        return HSM_Session_Close(req, req_len, resp, resp_cap);
    default:
        return HSM_ProcessPlaintext(req, req_len, resp, resp_cap);
    }
}

size_t HSM_ProcessPlaintext(const uint8_t *req, size_t req_len,
                            uint8_t *resp, size_t resp_cap)
{
    if (req_len < HSM_HEADER_SIZE || resp_cap < HSM_HEADER_SIZE) {
        return 0; /* too short to be a packet, or output buffer too small */
    }

    hsm_header_t hdr;
    memcpy(&hdr, req, sizeof(hdr));

    const uint8_t *payload = req + HSM_HEADER_SIZE;
    size_t avail_payload = req_len - HSM_HEADER_SIZE;
    if (hdr.payload_length > avail_payload) {
        return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
    }

    if (command_needs_auth(hdr.command) && !g_authenticated) {
        return build_response(resp, &hdr, HSM_ERR_NOT_AUTHORIZED, 0);
    }

    switch (hdr.command) {
    case HSM_CMD_AUTH: {
        uint8_t tries = 0;
        uint16_t st = HSM_KeyStore_Auth(payload, hdr.payload_length, &tries);
        g_authenticated = (st == HSM_OK);
        HSM_Audit_Log(st == HSM_OK ? HSM_EV_AUTH_OK : HSM_EV_AUTH_FAIL, tries);
        hsm_auth_resp_t ar = { .authenticated = (st == HSM_OK), .tries_left = tries };
        memcpy(resp + HSM_HEADER_SIZE, &ar, sizeof(ar));
        return build_response(resp, &hdr, st, (uint16_t)sizeof(ar));
    }

    case HSM_CMD_SET_PIN: {
        if (hdr.payload_length < sizeof(hsm_setpin_req_t)) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_setpin_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        if ((size_t)sizeof(rq) + rq.old_len + rq.new_len > hdr.payload_length) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        const uint8_t *old_pin = payload + sizeof(rq);
        const uint8_t *new_pin = old_pin + rq.old_len;
        uint8_t tries = 0;
        uint16_t st = HSM_KeyStore_SetPin(old_pin, rq.old_len, new_pin, rq.new_len, &tries);
        hsm_auth_resp_t ar = { .authenticated = 0, .tries_left = tries };
        memcpy(resp + HSM_HEADER_SIZE, &ar, sizeof(ar));
        return build_response(resp, &hdr, st, (uint16_t)sizeof(ar));
    }

    case HSM_CMD_PING: {
        /* Echo a 4-byte magic so the host can verify a live device. */
        uint32_t magic = HSM_PING_MAGIC;
        memcpy(resp + HSM_HEADER_SIZE, &magic, sizeof(magic));
        return build_response(resp, &hdr, HSM_OK, (uint16_t)sizeof(magic));
    }

    case HSM_CMD_GET_INFO: {
        hsm_info_t info;
        memset(&info, 0, sizeof(info));
        info.proto_version = HSM_PROTO_VERSION;
        info.fw_version    = (FW_VERSION_MAJOR << 8) | FW_VERSION_MINOR;
        read_uid(info.serial);
        info.flags = 0u; /* secure session not yet supported */
        memcpy(resp + HSM_HEADER_SIZE, &info, sizeof(info));
        return build_response(resp, &hdr, HSM_OK, (uint16_t)sizeof(info));
    }

    case HSM_CMD_ECHO: {
        uint16_t n = hdr.payload_length;
        if (HSM_HEADER_SIZE + n > resp_cap) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        memcpy(resp + HSM_HEADER_SIZE, payload, n);
        return build_response(resp, &hdr, HSM_OK, n);
    }

    case HSM_CMD_SELFTEST: {
        if (resp_cap < HSM_HEADER_SIZE + sizeof(hsm_selftest_t)) {
            return build_response(resp, &hdr, HSM_ERR_INTERNAL, 0);
        }
        hsm_selftest_t st;
        HSM_Crypto_SelfTest(&st);
        memcpy(resp + HSM_HEADER_SIZE, &st, sizeof(st));
        return build_response(resp, &hdr, HSM_OK, (uint16_t)sizeof(st));
    }

    case HSM_CMD_GENERATE_KEY: {
        if (hdr.payload_length < sizeof(hsm_genkey_req_t) ||
            resp_cap < HSM_HEADER_SIZE + sizeof(hsm_obj_info_t)) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_genkey_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        hsm_obj_info_t info;
        uint16_t st = HSM_KeyStore_Generate(&rq, &info);
        if (st != HSM_OK) {
            return build_response(resp, &hdr, st, 0);
        }
        HSM_Audit_Log(HSM_EV_KEYGEN, (uint16_t)info.id);
        memcpy(resp + HSM_HEADER_SIZE, &info, sizeof(info));
        return build_response(resp, &hdr, HSM_OK, (uint16_t)sizeof(info));
    }

    case HSM_CMD_FIND_OBJECT: {
        /* Optional 32-byte label filter; empty payload = list all. */
        const uint8_t *label = (hdr.payload_length >= HSM_LABEL_LEN) ? payload : NULL;
        hsm_find_resp_t fr;
        hsm_obj_info_t infos[HSM_MAX_OBJECTS];
        uint16_t fit = (uint16_t)((resp_cap - HSM_HEADER_SIZE - sizeof(fr)) / sizeof(hsm_obj_info_t));
        if (fit > HSM_MAX_OBJECTS) fit = HSM_MAX_OBJECTS;
        fr.count = HSM_KeyStore_Find(label, infos, fit);
        memcpy(resp + HSM_HEADER_SIZE, &fr, sizeof(fr));
        memcpy(resp + HSM_HEADER_SIZE + sizeof(fr), infos,
               fr.count * sizeof(hsm_obj_info_t));
        return build_response(resp, &hdr, HSM_OK,
                              (uint16_t)(sizeof(fr) + fr.count * sizeof(hsm_obj_info_t)));
    }

    case HSM_CMD_GET_OBJECT: {
        if (hdr.payload_length < sizeof(hsm_objid_req_t) ||
            resp_cap < HSM_HEADER_SIZE + sizeof(hsm_obj_info_t)) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_objid_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        hsm_obj_info_t info;
        uint16_t st = HSM_KeyStore_Get(rq.id, &info);
        if (st != HSM_OK) return build_response(resp, &hdr, st, 0);
        memcpy(resp + HSM_HEADER_SIZE, &info, sizeof(info));
        return build_response(resp, &hdr, HSM_OK, (uint16_t)sizeof(info));
    }

    case HSM_CMD_DELETE_OBJECT: {
        if (hdr.payload_length < sizeof(hsm_objid_req_t)) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_objid_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        uint16_t st = HSM_KeyStore_Delete(rq.id);
        if (st == HSM_OK) HSM_Audit_Log(HSM_EV_KEYDEL, (uint16_t)rq.id);
        return build_response(resp, &hdr, st, 0);
    }

    case HSM_CMD_GET_PUBLIC: {
        if (hdr.payload_length < sizeof(hsm_objid_req_t) ||
            resp_cap < HSM_HEADER_SIZE + 32) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_objid_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        hsm_obj_info_t info;
        if (HSM_KeyStore_Get(rq.id, &info) != HSM_OK) {
            return build_response(resp, &hdr, HSM_ERR_INVALID_PARAM, 0);
        }
        uint8_t seed[64]; uint16_t seed_len;
        if (HSM_KeyStore_LoadKey(rq.id, seed, &seed_len) != HSM_OK) {
            return build_response(resp, &hdr, HSM_ERR_INTERNAL, 0);
        }
        uint8_t pub[32];
        if (info.algorithm == HSM_KEY_ED25519) {
            HSM_Ed25519_Public(seed, pub);
        } else if (info.algorithm == HSM_KEY_X25519) {
            HSM_X25519_PublicKey(pub, seed);
        } else {
            memset(seed, 0, sizeof(seed));
            return build_response(resp, &hdr, HSM_ERR_INVALID_PARAM, 0);
        }
        memset(seed, 0, sizeof(seed));
        memcpy(resp + HSM_HEADER_SIZE, pub, 32);
        return build_response(resp, &hdr, HSM_OK, 32);
    }

    case HSM_CMD_SIGN: {
        if (hdr.payload_length < sizeof(hsm_keyop_req_t) ||
            resp_cap < HSM_HEADER_SIZE + HSM_ED25519_SIG_LEN) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_keyop_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        if (sizeof(rq) + rq.msg_len > hdr.payload_length) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_obj_info_t info;
        if (HSM_KeyStore_Get(rq.id, &info) != HSM_OK) {
            return build_response(resp, &hdr, HSM_ERR_INVALID_PARAM, 0);
        }
        if (info.algorithm != HSM_KEY_ED25519 || !(info.capabilities & HSM_CAP_SIGN)) {
            return build_response(resp, &hdr, HSM_ERR_NOT_AUTHORIZED, 0);
        }
        uint8_t seed[64]; uint16_t seed_len;
        if (HSM_KeyStore_LoadKey(rq.id, seed, &seed_len) != HSM_OK) {
            return build_response(resp, &hdr, HSM_ERR_INTERNAL, 0);
        }
        uint8_t sig[HSM_ED25519_SIG_LEN];
        HSM_Ed25519_Sign(seed, payload + sizeof(rq), rq.msg_len, sig);
        memset(seed, 0, sizeof(seed));
        HSM_KeyStore_BumpUsage(rq.id);
        HSM_Audit_Log(HSM_EV_SIGN, (uint16_t)rq.id);
        memcpy(resp + HSM_HEADER_SIZE, sig, sizeof(sig));
        return build_response(resp, &hdr, HSM_OK, (uint16_t)sizeof(sig));
    }

    case HSM_CMD_HMAC: {
        if (hdr.payload_length < sizeof(hsm_keyop_req_t) ||
            resp_cap < HSM_HEADER_SIZE + HSM_SHA256_LEN) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_keyop_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        if (sizeof(rq) + rq.msg_len > hdr.payload_length) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_obj_info_t info;
        if (HSM_KeyStore_Get(rq.id, &info) != HSM_OK) {
            return build_response(resp, &hdr, HSM_ERR_INVALID_PARAM, 0);
        }
        if (info.algorithm != HSM_KEY_HMAC256 || !(info.capabilities & HSM_CAP_SIGN)) {
            return build_response(resp, &hdr, HSM_ERR_NOT_AUTHORIZED, 0);
        }
        uint8_t key[64]; uint16_t key_len;
        if (HSM_KeyStore_LoadKey(rq.id, key, &key_len) != HSM_OK) {
            return build_response(resp, &hdr, HSM_ERR_INTERNAL, 0);
        }
        uint8_t mac[HSM_SHA256_LEN];
        int rc = HSM_HmacSha256(key, key_len, payload + sizeof(rq), rq.msg_len, mac);
        memset(key, 0, sizeof(key));
        if (rc != 0) {
            return build_response(resp, &hdr, HSM_ERR_INTERNAL, 0);
        }
        HSM_KeyStore_BumpUsage(rq.id);
        HSM_Audit_Log(HSM_EV_HMAC, (uint16_t)rq.id);
        memcpy(resp + HSM_HEADER_SIZE, mac, sizeof(mac));
        return build_response(resp, &hdr, HSM_OK, (uint16_t)sizeof(mac));
    }

    case HSM_CMD_WRAP: {
        if (hdr.payload_length < sizeof(hsm_wrap_req_t) ||
            resp_cap < HSM_HEADER_SIZE + 128) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_wrap_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        uint16_t blob_len = 0;
        uint16_t st = HSM_KeyStore_Wrap(rq.wrap_id, rq.target_id,
                                        resp + HSM_HEADER_SIZE, &blob_len);
        if (st != HSM_OK) return build_response(resp, &hdr, st, 0);
        HSM_Audit_Log(HSM_EV_WRAP, (uint16_t)rq.target_id);
        return build_response(resp, &hdr, HSM_OK, blob_len);
    }

    case HSM_CMD_UNWRAP: {
        if (hdr.payload_length < sizeof(hsm_unwrap_req_t) ||
            resp_cap < HSM_HEADER_SIZE + sizeof(hsm_obj_info_t)) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_unwrap_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        const uint8_t *blob = payload + sizeof(rq);
        uint16_t blob_len = (uint16_t)(hdr.payload_length - sizeof(rq));
        hsm_obj_info_t info;
        uint16_t st = HSM_KeyStore_Unwrap(rq.wrap_id, blob, blob_len,
                                          rq.capabilities, rq.exportable,
                                          rq.auth_domain, rq.label, &info);
        if (st != HSM_OK) return build_response(resp, &hdr, st, 0);
        HSM_Audit_Log(HSM_EV_UNWRAP, (uint16_t)info.id);
        memcpy(resp + HSM_HEADER_SIZE, &info, sizeof(info));
        return build_response(resp, &hdr, HSM_OK, (uint16_t)sizeof(info));
    }

    case HSM_CMD_ENCRYPT: {
        if (hdr.payload_length < sizeof(hsm_aead_req_t)) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_aead_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        if ((size_t)sizeof(rq) + rq.aad_len + rq.data_len > hdr.payload_length ||
            resp_cap < HSM_HEADER_SIZE + rq.data_len + 16) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        const uint8_t *aad = payload + sizeof(rq);
        const uint8_t *pt  = aad + rq.aad_len;
        uint8_t *ct  = resp + HSM_HEADER_SIZE;
        uint8_t *tag = ct + rq.data_len;
        uint16_t st = HSM_KeyStore_Encrypt(rq.key_id, rq.nonce, aad, rq.aad_len,
                                           pt, rq.data_len, ct, tag);
        if (st != HSM_OK) return build_response(resp, &hdr, st, 0);
        HSM_Audit_Log(HSM_EV_ENCRYPT, (uint16_t)rq.key_id);
        return build_response(resp, &hdr, HSM_OK, (uint16_t)(rq.data_len + 16));
    }

    case HSM_CMD_DECRYPT: {
        if (hdr.payload_length < sizeof(hsm_aead_req_t)) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_aead_req_t rq;
        memcpy(&rq, payload, sizeof(rq));
        if ((size_t)sizeof(rq) + rq.aad_len + rq.data_len + 16 > hdr.payload_length ||
            resp_cap < HSM_HEADER_SIZE + rq.data_len) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        const uint8_t *aad = payload + sizeof(rq);
        const uint8_t *ct  = aad + rq.aad_len;
        const uint8_t *tag = ct + rq.data_len;
        uint8_t *pt = resp + HSM_HEADER_SIZE;
        uint16_t st = HSM_KeyStore_Decrypt(rq.key_id, rq.nonce, aad, rq.aad_len,
                                           ct, rq.data_len, tag, pt);
        if (st != HSM_OK) return build_response(resp, &hdr, st, 0);
        HSM_Audit_Log(HSM_EV_DECRYPT, (uint16_t)rq.key_id);
        return build_response(resp, &hdr, HSM_OK, rq.data_len);
    }

    case HSM_CMD_GET_AUDIT_LOG: {
        hsm_auditlog_resp_t hdr_resp;
        uint16_t fit = (uint16_t)((resp_cap - HSM_HEADER_SIZE - sizeof(hdr_resp))
                                  / sizeof(hsm_audit_entry_t));
        uint16_t req_max = fit;
        if (hdr.payload_length >= sizeof(hsm_auditlog_req_t)) {
            hsm_auditlog_req_t rq; memcpy(&rq, payload, sizeof(rq));
            if (rq.max_entries < req_max) req_max = rq.max_entries;
        }
        hsm_audit_entry_t entries[64];
        if (req_max > 64) req_max = 64;
        uint32_t next = 0;
        uint16_t n = HSM_Audit_Get(req_max, entries, &next);
        hdr_resp.count = n;
        hdr_resp.reserved = 0;
        hdr_resp.next_seq = next;
        memcpy(resp + HSM_HEADER_SIZE, &hdr_resp, sizeof(hdr_resp));
        memcpy(resp + HSM_HEADER_SIZE + sizeof(hdr_resp), entries,
               n * sizeof(hsm_audit_entry_t));
        return build_response(resp, &hdr, HSM_OK,
                              (uint16_t)(sizeof(hdr_resp) + n * sizeof(hsm_audit_entry_t)));
    }

    case HSM_CMD_RANDOM: {
        if (hdr.payload_length < sizeof(hsm_random_req_t)) {
            return build_response(resp, &hdr, HSM_ERR_BAD_LENGTH, 0);
        }
        hsm_random_req_t rq;
        memcpy(&rq, payload, sizeof(rq));

        uint16_t count = rq.count;
        uint16_t max_fit = (uint16_t)(resp_cap - HSM_HEADER_SIZE);
        if (count > HSM_RANDOM_MAX) count = HSM_RANDOM_MAX;
        if (count > max_fit)        count = max_fit;

        if (HSM_Rng_Fill(resp + HSM_HEADER_SIZE, count) != 0) {
            return build_response(resp, &hdr, HSM_ERR_INTERNAL, 0);
        }
        return build_response(resp, &hdr, HSM_OK, count);
    }

    default:
        (void)payload;
        return build_response(resp, &hdr, HSM_ERR_NOT_IMPLEMENTED, 0);
    }
}
