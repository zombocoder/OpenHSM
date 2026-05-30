/**
 * @file    usbd_vendor.c
 * @brief   OpenHSM USB vendor-specific class implementation.
 *
 * One configuration, one interface (class 0xFF), two bulk endpoints:
 *   EP1 OUT — host -> device requests
 *   EP1 IN  — device -> host responses
 *
 * Received packets are buffered and processed in USBD_Vendor_Poll() from the
 * main loop, keeping the USB interrupt handler short.
 */
#include "usbd_vendor.h"
#include "usbd_ctlreq.h"
#include "usbd_desc.h"
#include "hsm_command.h"

#include <string.h>

/* Class callbacks -----------------------------------------------------------*/
static uint8_t Vendor_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t Vendor_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t Vendor_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
static uint8_t Vendor_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum);
static uint8_t Vendor_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum);
static uint8_t *Vendor_GetFSCfgDesc(uint16_t *length);
static uint8_t *Vendor_GetHSCfgDesc(uint16_t *length);
static uint8_t *Vendor_GetOtherSpeedCfgDesc(uint16_t *length);
static uint8_t *Vendor_GetDeviceQualifierDesc(uint16_t *length);

USBD_ClassTypeDef USBD_Vendor = {
    Vendor_Init,
    Vendor_DeInit,
    Vendor_Setup,
    NULL,                       /* EP0_TxSent */
    NULL,                       /* EP0_RxReady */
    Vendor_DataIn,
    Vendor_DataOut,
    NULL,                       /* SOF */
    NULL,                       /* IsoINIncomplete */
    NULL,                       /* IsoOUTIncomplete */
    Vendor_GetHSCfgDesc,
    Vendor_GetFSCfgDesc,
    Vendor_GetOtherSpeedCfgDesc,
    Vendor_GetDeviceQualifierDesc,
};

/* Configuration descriptor (32 bytes total). */
#define VENDOR_CONFIG_DESC_SIZE  32u
__ALIGN_BEGIN static uint8_t Vendor_CfgDesc[VENDOR_CONFIG_DESC_SIZE] __ALIGN_END = {
    /* Configuration descriptor */
    0x09, USB_DESC_TYPE_CONFIGURATION,
    LOBYTE(VENDOR_CONFIG_DESC_SIZE), HIBYTE(VENDOR_CONFIG_DESC_SIZE),
    0x01,                       /* bNumInterfaces */
    0x01,                       /* bConfigurationValue */
    USBD_IDX_CONFIG_STR,        /* iConfiguration */
    0xC0,                       /* bmAttributes: self-powered */
    USBD_MAX_POWER,             /* bMaxPower */

    /* Interface descriptor */
    0x09, USB_DESC_TYPE_INTERFACE,
    0x00,                       /* bInterfaceNumber */
    0x00,                       /* bAlternateSetting */
    0x02,                       /* bNumEndpoints */
    0xFF,                       /* bInterfaceClass: vendor-specific */
    0x00,                       /* bInterfaceSubClass */
    0x00,                       /* bInterfaceProtocol */
    USBD_IDX_INTERFACE_STR,     /* iInterface */

    /* EP1 OUT (bulk) */
    0x07, USB_DESC_TYPE_ENDPOINT,
    VENDOR_OUT_EP,
    0x02,                       /* bmAttributes: bulk */
    LOBYTE(VENDOR_EP_SIZE), HIBYTE(VENDOR_EP_SIZE),
    0x00,                       /* bInterval */

    /* EP1 IN (bulk) */
    0x07, USB_DESC_TYPE_ENDPOINT,
    VENDOR_IN_EP,
    0x02,                       /* bmAttributes: bulk */
    LOBYTE(VENDOR_EP_SIZE), HIBYTE(VENDOR_EP_SIZE),
    0x00,                       /* bInterval */
};

/* Device qualifier (returned for FS device on GET_DESCRIPTOR qualifier). */
__ALIGN_BEGIN static uint8_t Vendor_DeviceQualifierDesc[USB_LEN_DEV_QUALIFIER_DESC] __ALIGN_END = {
    USB_LEN_DEV_QUALIFIER_DESC,
    USB_DESC_TYPE_DEVICE_QUALIFIER,
    0x00, 0x02,
    0xFF, 0x00, 0x00,
    0x40,                       /* bMaxPacketSize0 */
    0x01,                       /* bNumConfigurations */
    0x00,
};

/* Single static class handle (no dynamic allocation on a HSM). */
static USBD_Vendor_HandleTypeDef vendor_handle;

/* ------------------------------------------------------------------------- */

static uint8_t Vendor_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
    (void)cfgidx;

    USBD_LL_OpenEP(pdev, VENDOR_IN_EP, USBD_EP_TYPE_BULK, VENDOR_EP_SIZE);
    pdev->ep_in[VENDOR_IN_EP & 0x0FU].is_used = 1U;

    USBD_LL_OpenEP(pdev, VENDOR_OUT_EP, USBD_EP_TYPE_BULK, VENDOR_EP_SIZE);
    pdev->ep_out[VENDOR_OUT_EP & 0x0FU].is_used = 1U;

    memset(&vendor_handle, 0, sizeof(vendor_handle));
    pdev->pClassDataCmsit[pdev->classId] = &vendor_handle;
    pdev->pClassData = &vendor_handle;

    /* Arm the first reception. */
    USBD_LL_PrepareReceive(pdev, VENDOR_OUT_EP, vendor_handle.rx_buffer, VENDOR_EP_SIZE);
    return USBD_OK;
}

static uint8_t Vendor_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
    (void)cfgidx;

    USBD_LL_CloseEP(pdev, VENDOR_IN_EP);
    pdev->ep_in[VENDOR_IN_EP & 0x0FU].is_used = 0U;

    USBD_LL_CloseEP(pdev, VENDOR_OUT_EP);
    pdev->ep_out[VENDOR_OUT_EP & 0x0FU].is_used = 0U;

    pdev->pClassDataCmsit[pdev->classId] = NULL;
    pdev->pClassData = NULL;
    return USBD_OK;
}

static uint8_t Vendor_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req)
{
    /* Milestone 1 defines no class/vendor control requests. Acknowledge
     * standard requests the core routes here; stall the rest. */
    switch (req->bmRequest & USB_REQ_TYPE_MASK) {
    case USB_REQ_TYPE_STANDARD:
        switch (req->bRequest) {
        case USB_REQ_GET_STATUS:
            if (pdev->dev_state == USBD_STATE_CONFIGURED) {
                uint16_t status = 0U;
                USBD_CtlSendData(pdev, (uint8_t *)&status, 2U);
            } else {
                USBD_CtlError(pdev, req);
                return USBD_FAIL;
            }
            break;
        default:
            USBD_CtlError(pdev, req);
            return USBD_FAIL;
        }
        break;

    case USB_REQ_TYPE_CLASS:
    case USB_REQ_TYPE_VENDOR:
        /* No control-transfer commands yet; commands ride the bulk pipe. */
        if (req->wLength == 0U) {
            USBD_CtlSendStatus(pdev);
        } else {
            USBD_CtlError(pdev, req);
            return USBD_FAIL;
        }
        break;

    default:
        USBD_CtlError(pdev, req);
        return USBD_FAIL;
    }
    return USBD_OK;
}

static uint8_t Vendor_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    USBD_Vendor_HandleTypeDef *h = (USBD_Vendor_HandleTypeDef *)pdev->pClassData;
    if (h != NULL && (epnum | 0x80U) == VENDOR_IN_EP) {
        h->tx_busy = 0U;
    }
    return USBD_OK;
}

static uint8_t Vendor_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    USBD_Vendor_HandleTypeDef *h = (USBD_Vendor_HandleTypeDef *)pdev->pClassData;
    if (h == NULL || epnum != (VENDOR_OUT_EP & 0x0FU)) {
        return USBD_OK;
    }
    if (h->rx_ready) {
        /* Previous message not yet consumed; drop this packet's data. */
        return USBD_OK;
    }

    uint32_t n = USBD_LL_GetRxDataSize(pdev, epnum);
    h->rx_offset += n;

    /* Once the header is in, we know the total message length. */
    if (h->rx_expected == 0U && h->rx_offset >= HSM_HEADER_SIZE) {
        uint16_t pl = (uint16_t)(h->rx_buffer[12] | (h->rx_buffer[13] << 8));
        if (pl > HSM_MAX_MSG_PAYLOAD) {
            pl = HSM_MAX_MSG_PAYLOAD; /* clamp; dispatcher returns BAD_LENGTH */
        }
        h->rx_expected = HSM_HEADER_SIZE + pl;
    }

    /* A short packet ends the host transfer; the length field is the backup
     * completion signal. Either way, cap at the buffer size. */
    uint8_t complete = (n < VENDOR_EP_SIZE) ||
                       (h->rx_expected != 0U && h->rx_offset >= h->rx_expected) ||
                       (h->rx_offset >= HSM_MAX_MSG);

    if (complete) {
        h->rx_length = h->rx_offset;
        h->rx_ready = 1U; /* hand off to USBD_Vendor_Poll() */
    } else {
        uint32_t space = HSM_MAX_MSG - h->rx_offset;
        uint32_t want = space < VENDOR_EP_SIZE ? space : VENDOR_EP_SIZE;
        USBD_LL_PrepareReceive(pdev, VENDOR_OUT_EP, h->rx_buffer + h->rx_offset, want);
    }
    return USBD_OK;
}

void USBD_Vendor_Poll(USBD_HandleTypeDef *pdev)
{
    if (pdev->dev_state != USBD_STATE_CONFIGURED) {
        return;
    }
    USBD_Vendor_HandleTypeDef *h = (USBD_Vendor_HandleTypeDef *)pdev->pClassData;
    if (h == NULL || !h->rx_ready) {
        return;
    }

    size_t resp_len = HSM_ProcessPacket(h->rx_buffer, h->rx_length,
                                        h->tx_buffer, sizeof(h->tx_buffer));

    /* Reset reassembly state and re-arm reception before transmitting, so the
     * next request is never lost. The HAL splits a >64-byte IN transfer into
     * USB packets automatically. */
    h->rx_offset = 0U;
    h->rx_expected = 0U;
    h->rx_ready = 0U;
    USBD_LL_PrepareReceive(pdev, VENDOR_OUT_EP, h->rx_buffer, VENDOR_EP_SIZE);

    if (resp_len > 0U) {
        h->tx_busy = 1U;
        USBD_LL_Transmit(pdev, VENDOR_IN_EP, h->tx_buffer, (uint32_t)resp_len);
    }
}

static uint8_t *Vendor_GetFSCfgDesc(uint16_t *length)
{
    *length = (uint16_t)sizeof(Vendor_CfgDesc);
    return Vendor_CfgDesc;
}

static uint8_t *Vendor_GetHSCfgDesc(uint16_t *length)
{
    *length = (uint16_t)sizeof(Vendor_CfgDesc);
    return Vendor_CfgDesc;
}

static uint8_t *Vendor_GetOtherSpeedCfgDesc(uint16_t *length)
{
    *length = (uint16_t)sizeof(Vendor_CfgDesc);
    return Vendor_CfgDesc;
}

static uint8_t *Vendor_GetDeviceQualifierDesc(uint16_t *length)
{
    *length = (uint16_t)sizeof(Vendor_DeviceQualifierDesc);
    return Vendor_DeviceQualifierDesc;
}
