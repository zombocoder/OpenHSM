/**
 * @file    usbd_desc.h
 * @brief   USB descriptors for the OpenHSM vendor-specific device.
 */
#ifndef USBD_DESC_H
#define USBD_DESC_H

#include "usbd_def.h"

/* USB Vendor/Product IDs.
 * NOTE: 0x0483 is STMicroelectronics' VID, used here with a custom PID for
 * development only. Replace with an allocated VID/PID before production. */
#define OPENHSM_USB_VID   0x0483u
#define OPENHSM_USB_PID   0x5750u

extern USBD_DescriptorsTypeDef OpenHSM_Desc;

#endif /* USBD_DESC_H */
