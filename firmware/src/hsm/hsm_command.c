/**
 * @file    hsm_command.c
 * @brief   OpenHSM command dispatcher.
 *
 * Milestone 1 implements PING and GET_INFO. All other commands return
 * HSM_ERR_NOT_IMPLEMENTED so the host can already enumerate the surface.
 */
#include "hsm_command.h"
#include "hsm_proto.h"

#include <string.h>
#include "stm32u5xx.h"

#define FW_VERSION_MAJOR 0u
#define FW_VERSION_MINOR 1u

/* Helper: assemble a response header in-place. Returns total packet length. */
static size_t build_response(uint8_t *resp, const hsm_header_t *req_hdr,
                             uint16_t status, uint16_t payload_len)
{
    hsm_header_t hdr;
    hdr.command        = req_hdr->command;
    hdr.flags          = (uint16_t)(req_hdr->flags | HSM_FLAG_RESPONSE);
    hdr.session_id     = req_hdr->session_id;
    hdr.counter        = req_hdr->counter;
    hdr.payload_length = payload_len;
    hdr.status         = status;
    memcpy(resp, &hdr, sizeof(hdr));
    return sizeof(hdr) + payload_len;
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
    if (req_len < HSM_HEADER_SIZE || resp_cap < HSM_MAX_PACKET) {
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

    default:
        (void)payload;
        return build_response(resp, &hdr, HSM_ERR_NOT_IMPLEMENTED, 0);
    }
}
