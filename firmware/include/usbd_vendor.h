/**
 * @file    usbd_vendor.h
 * @brief   OpenHSM USB vendor-specific class (EP1 bulk IN/OUT).
 */
#ifndef USBD_VENDOR_H
#define USBD_VENDOR_H

#include "usbd_ioreq.h"
#include "hsm_proto.h"

#define VENDOR_IN_EP    0x81u  /* EP1 IN  (device -> host) */
#define VENDOR_OUT_EP   0x01u  /* EP1 OUT (host -> device) */
#define VENDOR_EP_SIZE  HSM_MAX_PACKET

typedef struct {
    uint8_t  rx_buffer[HSM_MAX_PACKET];
    uint8_t  tx_buffer[HSM_MAX_PACKET];
    volatile uint32_t rx_length;
    volatile uint8_t  rx_ready;  /* a packet is waiting to be processed */
    volatile uint8_t  tx_busy;   /* an IN transfer is in flight */
} USBD_Vendor_HandleTypeDef;

extern USBD_ClassTypeDef USBD_Vendor;

/**
 * @brief Process any pending received packet. Call from the main loop.
 *        Heavy command handling (crypto) belongs here, not in the USB ISR.
 */
void USBD_Vendor_Poll(USBD_HandleTypeDef *pdev);

#endif /* USBD_VENDOR_H */
