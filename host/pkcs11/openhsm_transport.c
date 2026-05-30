/**
 * @file    openhsm_transport.c
 * @brief   USB transport for the OpenHSM host stack.
 */
#include "openhsm_transport.h"
#include "hsm_proto.h"

#include <stdlib.h>
#include <string.h>
#include <libusb.h>

#define OPENHSM_VID 0x0483
#define OPENHSM_PID 0x5750
#define EP_OUT      0x01
#define EP_IN       0x81
#define TIMEOUT_MS  2000

struct ohsm_ctx {
    libusb_context       *usb;
    libusb_device_handle *dev;
    int                   claimed;
};

ohsm_ctx *ohsm_open(void)
{
    ohsm_ctx *c = calloc(1, sizeof(*c));
    if (c == NULL) return NULL;

    if (libusb_init(&c->usb) != 0) {
        free(c);
        return NULL;
    }
    c->dev = libusb_open_device_with_vid_pid(c->usb, OPENHSM_VID, OPENHSM_PID);
    if (c->dev == NULL) {
        libusb_exit(c->usb);
        free(c);
        return NULL;
    }
    if (libusb_claim_interface(c->dev, 0) != 0) {
        libusb_close(c->dev);
        libusb_exit(c->usb);
        free(c);
        return NULL;
    }
    c->claimed = 1;
    return c;
}

void ohsm_close(ohsm_ctx *c)
{
    if (c == NULL) return;
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

    uint8_t pkt[HSM_MAX_MSG];
    if ((int)(HSM_HEADER_SIZE + plen) > (int)sizeof(pkt)) return -1;
    memset(pkt, 0, HSM_HEADER_SIZE);
    hsm_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.command = command;
    hdr.payload_length = plen;
    memcpy(pkt, &hdr, sizeof(hdr));
    if (plen && payload) memcpy(pkt + HSM_HEADER_SIZE, payload, plen);

    int transferred = 0;
    int rc = libusb_bulk_transfer(c->dev, EP_OUT, pkt, HSM_HEADER_SIZE + plen,
                                  &transferred, TIMEOUT_MS);
    if (rc != 0) return rc;

    /* Read in 64-byte packets until the header's payload_length is satisfied. */
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
