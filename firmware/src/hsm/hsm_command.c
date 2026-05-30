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

#include <string.h>
#include "stm32u5xx.h"

#define FW_VERSION_MAJOR 0u
#define FW_VERSION_MINOR 1u

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

    switch (hdr.command) {
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
