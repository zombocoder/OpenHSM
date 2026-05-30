/**
 * @file    usb_device.h
 * @brief   USB device init glue for OpenHSM.
 */
#ifndef USB_DEVICE_H
#define USB_DEVICE_H

#include "usbd_def.h"

#define DEVICE_FS 0

extern USBD_HandleTypeDef hUsbDeviceFS;

void MX_USB_Device_Init(void);

#endif /* USB_DEVICE_H */
