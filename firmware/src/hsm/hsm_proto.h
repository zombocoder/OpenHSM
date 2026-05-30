/**
 * @file    hsm_proto.h
 * @brief   OpenHSM USB packet protocol — shared between firmware and host.
 *
 * This header is intentionally dependency-free (only <stdint.h>) so the host
 * PKCS#11 provider / tools can include it verbatim.
 *
 * Milestone 1 scope: a single request/response fits in one USB FS bulk packet
 * (<= 64 bytes). Framing for multi-packet payloads (length-prefixed streaming)
 * and the encrypted session layer (X25519 + AES-256-GCM) are added later; the
 * `flags`, `session_id` and `counter` header fields are already reserved for
 * them so the wire format does not change.
 */
#ifndef OPENHSM_HSM_PROTO_H
#define OPENHSM_HSM_PROTO_H

#include <stdint.h>

#define HSM_PROTO_VERSION        0x0001u

/* USB transport limits (Full-Speed bulk max packet size). */
#define HSM_MAX_PACKET           64u
#define HSM_HEADER_SIZE          16u
#define HSM_MAX_PAYLOAD          (HSM_MAX_PACKET - HSM_HEADER_SIZE) /* 48 bytes */

/* Packet header (little-endian on the wire). Mirrors the spec's hsm_packet_t. */
typedef struct __attribute__((packed)) {
    uint16_t command;         /* hsm_command_t                                 */
    uint16_t flags;           /* HSM_FLAG_* (reserved for session/encryption)  */
    uint32_t session_id;      /* 0 before a secure session is established       */
    uint32_t counter;         /* anti-replay counter (reserved)                 */
    uint16_t payload_length;  /* bytes of payload following the header          */
    uint16_t status;          /* hsm_status_t — meaningful on responses         */
    /* payload[] follows */
} hsm_header_t;

/* Header flags (reserved; unused in milestone 1). */
#define HSM_FLAG_NONE            0x0000u
#define HSM_FLAG_ENCRYPTED       0x0001u  /* payload is AES-256-GCM protected   */
#define HSM_FLAG_RESPONSE        0x8000u  /* set by device on replies           */

/* Command identifiers. Values are stable wire constants — append, never renumber. */
typedef enum {
    HSM_CMD_PING            = 0x0001,
    HSM_CMD_GET_INFO        = 0x0002,
    HSM_CMD_OPEN_SESSION    = 0x0010,
    HSM_CMD_CLOSE_SESSION   = 0x0011,
    HSM_CMD_AUTH            = 0x0012,
    HSM_CMD_GENERATE_KEY    = 0x0020,
    HSM_CMD_IMPORT_WRAPPED  = 0x0021,
    HSM_CMD_EXPORT_WRAPPED  = 0x0022,
    HSM_CMD_FIND_OBJECT     = 0x0023,
    HSM_CMD_DELETE_OBJECT   = 0x0024,
    HSM_CMD_HMAC            = 0x0030,
    HSM_CMD_WRAP            = 0x0031,
    HSM_CMD_UNWRAP          = 0x0032,
    HSM_CMD_RANDOM          = 0x0040,
    HSM_CMD_GET_AUDIT_LOG   = 0x0050,
} hsm_command_t;

/* Response status codes. */
typedef enum {
    HSM_OK                  = 0x0000,
    HSM_ERR_UNKNOWN_CMD     = 0x0001,
    HSM_ERR_BAD_LENGTH      = 0x0002,
    HSM_ERR_NOT_AUTHORIZED  = 0x0003,
    HSM_ERR_NO_SESSION      = 0x0004,
    HSM_ERR_INVALID_PARAM   = 0x0005,
    HSM_ERR_NOT_IMPLEMENTED = 0x0006,
    HSM_ERR_INTERNAL        = 0x00FF,
} hsm_status_t;

/* GET_INFO response payload (little-endian). */
typedef struct __attribute__((packed)) {
    uint16_t proto_version;   /* HSM_PROTO_VERSION                              */
    uint16_t fw_version;      /* firmware version, BCD-ish (major<<8 | minor)   */
    uint8_t  serial[12];      /* STM32 96-bit unique device ID                  */
    uint8_t  flags;           /* bit0: secure-session supported (0 in M1)       */
    uint8_t  reserved[3];
} hsm_info_t;

/* Magic the PING command echoes back, to prove a live round-trip. */
#define HSM_PING_MAGIC           0x4F48534Du /* "OHSM" */

#endif /* OPENHSM_HSM_PROTO_H */
