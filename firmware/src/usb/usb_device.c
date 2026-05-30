/**
 * @file    usb_device.c
 * @brief   USB device initialization for OpenHSM.
 */
#include "usb_device.h"
#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_vendor.h"
#include "main.h"

USBD_HandleTypeDef hUsbDeviceFS;

void MX_USB_Device_Init(void)
{
    if (USBD_Init(&hUsbDeviceFS, &OpenHSM_Desc, DEVICE_FS) != USBD_OK) {
        Error_Handler();
    }
    if (USBD_RegisterClass(&hUsbDeviceFS, &USBD_Vendor) != USBD_OK) {
        Error_Handler();
    }
    if (USBD_Start(&hUsbDeviceFS) != USBD_OK) {
        Error_Handler();
    }
}
