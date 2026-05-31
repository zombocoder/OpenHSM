/**
 * @file    image_header.h
 * @brief   Signed-firmware image header — shared by the bootloader and the
 *          host signing tool (firmware/tools/sign_image.c).
 *
 * Flash layout (bank 1):
 *   0x08000000  bootloader        (64 KB)
 *   0x08010000  this header       (8 KB page; only the fixed fields are used)
 *   0x08012000  application image (vectors + code), `img_len` bytes
 *
 * The signature is Ed25519 (RFC 8032) over the little-endian serialization
 *   u32 version || u32 img_len || app_bytes[0 .. img_len)
 * and is verified by the bootloader against the baked-in vendor public key.
 * Keep this file free of device/HAL dependencies so it compiles on the host.
 */
#ifndef OPENHSM_IMAGE_HEADER_H
#define OPENHSM_IMAGE_HEADER_H

#include <stdint.h>

#define IMG_MAGIC          0x4F484253u  /* "OHBS" — OpenHSM Boot Signed */

#define BOOT_BL_BASE       0x08000000u
#define BOOT_BL_SIZE       0x00010000u  /* 64 KB reserved for the bootloader */
#define BOOT_HEADER_ADDR   0x08010000u  /* = BL_BASE + BL_SIZE                */
#define BOOT_HEADER_SIZE   0x00002000u  /* 8 KB (one flash page)              */
#define BOOT_APP_ADDR      0x08012000u  /* = HEADER_ADDR + HEADER_SIZE        */

/* Largest app we will verify (bank 1 minus BL+header). */
#define BOOT_APP_MAX_LEN   (0x00100000u - (BOOT_APP_ADDR - BOOT_BL_BASE))

/* Anti-rollback: highest booted version, stored in a free bank-2 page so the
 * bootloader refuses to run an image older than one already accepted. */
#define ROLLBACK_ADDR      0x081F8000u  /* bank 2, page 124 (free) */
#define ROLLBACK_PAGE      124u
#define ROLLBACK_MAGIC     0x4F485242u  /* "OHRB" */

typedef struct {
    uint32_t magic;       /* IMG_MAGIC                                          */
    uint32_t version;     /* monotonic; anti-rollback compares against this     */
    uint32_t img_len;     /* application byte count following BOOT_APP_ADDR     */
    uint32_t reserved;
    uint8_t  sig[64];     /* Ed25519 over version||img_len||app[]               */
} img_header_t;

#endif /* OPENHSM_IMAGE_HEADER_H */
