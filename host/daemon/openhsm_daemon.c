/**
 * @file    openhsm_daemon.c
 * @brief   USB-to-TCP bridge for the OpenHSM appliance (spec §21 openhsm-daemon).
 *
 * Owns the USB device (libusb) and exposes the raw HSM packet protocol over TCP
 * so containerized / remote PKCS#11 clients can reach a USB-attached HSM. It is
 * a dumb pipe: the encrypted session (X25519/AES-GCM) is end-to-end between the
 * client module and the device, so the daemon and the network see only
 * ciphertext.
 *
 * TCP framing (both directions): 4-byte big-endian length, then that many bytes
 * of one HSM packet. The daemon writes a request to EP1 OUT and reads the
 * response from EP1 IN (re-assembled by header payload_length / short packet).
 *
 * One client at a time (the USB device is a single shared resource).
 *
 *   usage: openhsm-daemon [bind_addr] [port]   (default 0.0.0.0 11700)
 */
#include "hsm_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libusb.h>

#define OPENHSM_VID 0x0483
#define OPENHSM_PID 0x5750
#define EP_OUT      0x01
#define EP_IN       0x81
#define USB_TIMEOUT 3000

static libusb_context       *g_usb;
static libusb_device_handle *g_dev;

static int usb_open(void)
{
    if (libusb_init(&g_usb) != 0) return -1;
    g_dev = libusb_open_device_with_vid_pid(g_usb, OPENHSM_VID, OPENHSM_PID);
    if (!g_dev) { libusb_exit(g_usb); g_usb = NULL; return -1; }
    if (libusb_claim_interface(g_dev, 0) != 0) {
        libusb_close(g_dev); libusb_exit(g_usb); g_dev = NULL; g_usb = NULL; return -1;
    }
    return 0;
}

static void usb_close(void)
{
    if (g_dev) { libusb_release_interface(g_dev, 0); libusb_close(g_dev); }
    if (g_usb) libusb_exit(g_usb);
    g_dev = NULL; g_usb = NULL;
}

/* Exchange one packet with the device. Returns response length or <0. */
static int usb_exchange(const uint8_t *req, int req_len, uint8_t *resp, int cap)
{
    int transferred = 0;
    int rc = libusb_bulk_transfer(g_dev, EP_OUT, (uint8_t *)req, req_len,
                                  &transferred, USB_TIMEOUT);
    if (rc != 0) return -1;

    int got = 0;
    while (got < (int)HSM_HEADER_SIZE) {
        int n = 0, want = HSM_MAX_PACKET;
        if (want > cap - got) want = cap - got;
        rc = libusb_bulk_transfer(g_dev, EP_IN, resp + got, want, &n, USB_TIMEOUT);
        if (rc != 0) return -1;
        if (n == 0) break;
        got += n;
    }
    int total = got;
    if (got >= (int)HSM_HEADER_SIZE) {
        uint16_t pl = (uint16_t)(resp[12] | (resp[13] << 8));
        total = (int)HSM_HEADER_SIZE + pl;
        if (total > cap) total = cap;
    }
    while (got < total) {
        int n = 0, want = HSM_MAX_PACKET;
        if (want > cap - got) want = cap - got;
        rc = libusb_bulk_transfer(g_dev, EP_IN, resp + got, want, &n, USB_TIMEOUT);
        if (rc != 0) return -1;
        if (n == 0) break;
        got += n;
    }
    return got;
}

static int read_n(int fd, uint8_t *buf, int n)
{
    int off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r <= 0) return -1;
        off += (int)r;
    }
    return 0;
}

static int write_n(int fd, const uint8_t *buf, int n)
{
    int off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w <= 0) return -1;
        off += (int)w;
    }
    return 0;
}

/* Serve one client: [len][pkt] in -> USB -> [len][resp] out, until EOF. */
static void serve(int fd)
{
    uint8_t req[HSM_MAX_MSG], resp[HSM_MAX_MSG];
    for (;;) {
        uint8_t lenbe[4];
        if (read_n(fd, lenbe, 4) != 0) return;
        uint32_t len = ((uint32_t)lenbe[0] << 24) | ((uint32_t)lenbe[1] << 16) |
                       ((uint32_t)lenbe[2] << 8) | lenbe[3];
        if (len == 0 || len > sizeof(req)) return;
        if (read_n(fd, req, (int)len) != 0) return;

        int rlen = usb_exchange(req, (int)len, resp, sizeof(resp));
        if (rlen < 0) return;

        uint8_t rbe[4] = { (uint8_t)(rlen >> 24), (uint8_t)(rlen >> 16),
                           (uint8_t)(rlen >> 8), (uint8_t)rlen };
        if (write_n(fd, rbe, 4) != 0) return;
        if (write_n(fd, resp, rlen) != 0) return;
    }
}

int main(int argc, char **argv)
{
    const char *bind_addr = argc > 1 ? argv[1] : "0.0.0.0";
    int port = argc > 2 ? atoi(argv[2]) : 11700;

    if (usb_open() != 0) {
        fprintf(stderr, "openhsm-daemon: cannot open USB device %04x:%04x\n",
                OPENHSM_VID, OPENHSM_PID);
        return 1;
    }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = inet_addr(bind_addr);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(srv, 4) != 0) {
        fprintf(stderr, "openhsm-daemon: bind/listen failed: %s\n", strerror(errno));
        usb_close();
        return 1;
    }
    printf("openhsm-daemon: bridging USB %04x:%04x <-> tcp %s:%d\n",
           OPENHSM_VID, OPENHSM_PID, bind_addr, port);
    fflush(stdout);

    /* TCP carries only ciphertext; disable Nagle for latency. */
    for (;;) {
        struct sockaddr_in ca; socklen_t cl = sizeof(ca);
        int fd = accept(srv, (struct sockaddr *)&ca, &cl);
        if (fd < 0) continue;
        int one = 1; setsockopt(fd, IPPROTO_TCP, 1 /*TCP_NODELAY*/, &one, sizeof(one));
        printf("openhsm-daemon: client %s connected\n", inet_ntoa(ca.sin_addr));
        fflush(stdout);
        serve(fd);
        close(fd);
        printf("openhsm-daemon: client disconnected\n");
        fflush(stdout);
    }
}
