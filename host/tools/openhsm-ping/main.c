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

#include "hsm_proto.h"

#define OPENHSM_VID 0x0483
#define OPENHSM_PID 0x5750
#define EP_OUT      0x01
#define EP_IN       0x81
#define TIMEOUT_MS  1000

static int send_command(libusb_device_handle *h, uint16_t command,
                         const uint8_t *payload, uint16_t payload_len,
                         uint8_t *resp, int resp_cap, int *resp_len)
{
    uint8_t pkt[HSM_MAX_PACKET];
    memset(pkt, 0, sizeof(pkt));

    hsm_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.command        = command;
    hdr.payload_length = payload_len;
    memcpy(pkt, &hdr, sizeof(hdr));
    if (payload_len > 0 && payload != NULL) {
        memcpy(pkt + HSM_HEADER_SIZE, payload, payload_len);
    }

    int transferred = 0;
    int rc = libusb_bulk_transfer(h, EP_OUT, pkt,
                                  HSM_HEADER_SIZE + payload_len,
                                  &transferred, TIMEOUT_MS);
    if (rc != 0) {
        fprintf(stderr, "bulk OUT failed: %s\n", libusb_error_name(rc));
        return rc;
    }

    rc = libusb_bulk_transfer(h, EP_IN, resp, resp_cap, resp_len, TIMEOUT_MS);
    if (rc != 0) {
        fprintf(stderr, "bulk IN failed: %s\n", libusb_error_name(rc));
        return rc;
    }
    return 0;
}

int main(void)
{
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

    uint8_t resp[HSM_MAX_PACKET];
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

    libusb_release_interface(h, 0);
    libusb_close(h);
    libusb_exit(ctx);
    return 0;
}
