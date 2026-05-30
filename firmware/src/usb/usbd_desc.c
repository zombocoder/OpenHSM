/**
 * @file    usbd_desc.c
 * @brief   USB descriptors for the OpenHSM vendor-specific device.
 */
#include "usbd_desc.h"
#include "usbd_core.h"
#include "stm32u5xx.h"

#define USBD_LANGID_STRING        0x0409 /* English (US) */
#define USBD_MANUFACTURER_STRING  "OpenHSM Project"
#define USBD_PRODUCT_STRING       "OpenHSM Token"
#define USBD_CONFIGURATION_STRING "OpenHSM Config"
#define USBD_INTERFACE_STRING     "OpenHSM Vendor Interface"

/* Descriptor callbacks ------------------------------------------------------*/
static uint8_t *OpenHSM_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
static uint8_t *OpenHSM_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
static uint8_t *OpenHSM_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
static uint8_t *OpenHSM_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
static uint8_t *OpenHSM_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
static uint8_t *OpenHSM_ConfigStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
static uint8_t *OpenHSM_InterfaceStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);

USBD_DescriptorsTypeDef OpenHSM_Desc = {
    OpenHSM_DeviceDescriptor,
    OpenHSM_LangIDStrDescriptor,
    OpenHSM_ManufacturerStrDescriptor,
    OpenHSM_ProductStrDescriptor,
    OpenHSM_SerialStrDescriptor,
    OpenHSM_ConfigStrDescriptor,
    OpenHSM_InterfaceStrDescriptor,
};

/* Device descriptor (18 bytes). */
__ALIGN_BEGIN static uint8_t OpenHSM_DeviceDesc[USB_LEN_DEV_DESC] __ALIGN_END = {
    0x12,                       /* bLength */
    USB_DESC_TYPE_DEVICE,       /* bDescriptorType */
    0x00, 0x02,                 /* bcdUSB 2.00 */
    0xFF,                       /* bDeviceClass: vendor-specific */
    0x00,                       /* bDeviceSubClass */
    0x00,                       /* bDeviceProtocol */
    USB_MAX_EP0_SIZE,           /* bMaxPacketSize0 */
    LOBYTE(OPENHSM_USB_VID), HIBYTE(OPENHSM_USB_VID),
    LOBYTE(OPENHSM_USB_PID), HIBYTE(OPENHSM_USB_PID),
    0x00, 0x01,                 /* bcdDevice 1.00 */
    USBD_IDX_MFC_STR,           /* iManufacturer */
    USBD_IDX_PRODUCT_STR,       /* iProduct */
    USBD_IDX_SERIAL_STR,        /* iSerialNumber */
    USBD_MAX_NUM_CONFIGURATION, /* bNumConfigurations */
};

/* LangID string descriptor. */
__ALIGN_BEGIN static uint8_t OpenHSM_LangIDDesc[USB_LEN_LANGID_STR_DESC] __ALIGN_END = {
    USB_LEN_LANGID_STR_DESC,
    USB_DESC_TYPE_STRING,
    LOBYTE(USBD_LANGID_STRING), HIBYTE(USBD_LANGID_STRING),
};

/* Scratch buffer for runtime-built string descriptors. */
__ALIGN_BEGIN static uint8_t OpenHSM_StrDesc[USBD_MAX_STR_DESC_SIZ] __ALIGN_END;

/* Serial number string (built from UID, 24 hex chars + header). */
__ALIGN_BEGIN static uint8_t OpenHSM_SerialDesc[26] __ALIGN_END = {
    26,                   /* bLength: 2 + 24 (12 chars * 2) */
    USB_DESC_TYPE_STRING,
};

static void uid_nibble_to_unicode(uint8_t *dst, uint8_t value)
{
    value &= 0x0F;
    *dst = (uint8_t)(value < 10 ? ('0' + value) : ('A' + (value - 10)));
}

static void build_serial(void)
{
    const volatile uint32_t *uid = (const volatile uint32_t *)UID_BASE;
    uint8_t bytes[12];
    for (unsigned i = 0; i < 3; i++) {
        uint32_t w = uid[i];
        bytes[i * 4 + 0] = (uint8_t)(w & 0xFF);
        bytes[i * 4 + 1] = (uint8_t)((w >> 8) & 0xFF);
        bytes[i * 4 + 2] = (uint8_t)((w >> 16) & 0xFF);
        bytes[i * 4 + 3] = (uint8_t)((w >> 24) & 0xFF);
    }
    /* 12 bytes -> 24 hex chars, UTF-16LE (ascii char + 0x00). */
    for (unsigned i = 0; i < 12; i++) {
        uid_nibble_to_unicode(&OpenHSM_SerialDesc[2 + i * 4 + 0], bytes[i] >> 4);
        OpenHSM_SerialDesc[2 + i * 4 + 1] = 0x00;
        uid_nibble_to_unicode(&OpenHSM_SerialDesc[2 + i * 4 + 2], bytes[i] & 0x0F);
        OpenHSM_SerialDesc[2 + i * 4 + 3] = 0x00;
    }
}

static uint8_t *OpenHSM_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    *length = sizeof(OpenHSM_DeviceDesc);
    return OpenHSM_DeviceDesc;
}

static uint8_t *OpenHSM_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    *length = sizeof(OpenHSM_LangIDDesc);
    return OpenHSM_LangIDDesc;
}

static uint8_t *OpenHSM_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    USBD_GetString((uint8_t *)USBD_MANUFACTURER_STRING, OpenHSM_StrDesc, length);
    return OpenHSM_StrDesc;
}

static uint8_t *OpenHSM_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    USBD_GetString((uint8_t *)USBD_PRODUCT_STRING, OpenHSM_StrDesc, length);
    return OpenHSM_StrDesc;
}

static uint8_t *OpenHSM_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    build_serial();
    *length = OpenHSM_SerialDesc[0];
    return OpenHSM_SerialDesc;
}

static uint8_t *OpenHSM_ConfigStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    USBD_GetString((uint8_t *)USBD_CONFIGURATION_STRING, OpenHSM_StrDesc, length);
    return OpenHSM_StrDesc;
}

static uint8_t *OpenHSM_InterfaceStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    (void)speed;
    USBD_GetString((uint8_t *)USBD_INTERFACE_STRING, OpenHSM_StrDesc, length);
    return OpenHSM_StrDesc;
}
