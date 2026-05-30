/**
 * @file    openhsm_pkcs11.c
 * @brief   OpenHSM PKCS#11 provider (libopenhsm_pkcs11).
 *
 * Phase A: module load, slot/token enumeration, mechanism list. Sessions,
 * login, object search and crypto operations are layered on in later phases.
 *
 * Maps the PKCS#11 C ABI onto the OpenHSM USB command protocol (hsm_proto.h).
 */
#define CRYPTOKI_COMPAT 1
#include "pkcs11.h"

#include "openhsm_transport.h"
#include "hsm_proto.h"

#include <string.h>
#include <stdio.h>

/* Single static slot/token. */
#define OPENHSM_SLOT_ID  0
#define LIB_VERSION_MAJOR 0
#define LIB_VERSION_MINOR 1

static ohsm_ctx  *g_ctx;
static CK_BBOOL   g_initialized;
static hsm_info_t g_info;       /* cached device GET_INFO */
static CK_BBOOL   g_have_info;

/* Copy a C string into a PKCS#11 space-padded (not NUL-terminated) field. */
static void pad_set(CK_UTF8CHAR *dst, size_t n, const char *src)
{
    size_t l = strlen(src);
    if (l > n) l = n;
    memcpy(dst, src, l);
    for (size_t i = l; i < n; i++) dst[i] = ' ';
}

static void refresh_info(void)
{
    uint8_t resp[HSM_MAX_MSG];
    int rl = 0;
    if (g_ctx && ohsm_cmd(g_ctx, HSM_CMD_GET_INFO, NULL, 0, resp, sizeof(resp), &rl) == 0) {
        hsm_header_t *rh = (hsm_header_t *)resp;
        if (rh->status == HSM_OK && rl >= (int)(HSM_HEADER_SIZE + sizeof(hsm_info_t))) {
            memcpy(&g_info, resp + HSM_HEADER_SIZE, sizeof(g_info));
            g_have_info = CK_TRUE;
        }
    }
}

/* ===========================================================================
 *  General
 * ===========================================================================*/
CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    (void)pInitArgs;
    if (g_initialized) return CKR_CRYPTOKI_ALREADY_INITIALIZED;

    g_ctx = ohsm_open();
    /* Absence of the device is not fatal for C_Initialize; slot will report
     * token-not-present. But for this appliance we require it. */
    if (g_ctx == NULL) return CKR_DEVICE_REMOVED;

    refresh_info();
    g_initialized = CK_TRUE;
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    (void)pReserved;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    ohsm_close(g_ctx);
    g_ctx = NULL;
    g_have_info = CK_FALSE;
    g_initialized = CK_FALSE;
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL) return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    pad_set(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "OpenHSM Project");
    pInfo->flags = 0;
    pad_set(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), "OpenHSM PKCS#11");
    pInfo->libraryVersion.major = LIB_VERSION_MAJOR;
    pInfo->libraryVersion.minor = LIB_VERSION_MINOR;
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount)
{
    (void)tokenPresent;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pulCount == NULL) return CKR_ARGUMENTS_BAD;

    if (pSlotList == NULL) {
        *pulCount = 1;
        return CKR_OK;
    }
    if (*pulCount < 1) {
        *pulCount = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    pSlotList[0] = OPENHSM_SLOT_ID;
    *pulCount = 1;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != OPENHSM_SLOT_ID || pInfo == NULL) return CKR_SLOT_ID_INVALID;
    memset(pInfo, 0, sizeof(*pInfo));
    pad_set(pInfo->slotDescription, sizeof(pInfo->slotDescription),
            "OpenHSM USB Slot");
    pad_set(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "OpenHSM Project");
    pInfo->flags = CKF_HW_SLOT;
    if (g_ctx) pInfo->flags |= CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = (g_info.fw_version >> 8) & 0xFF;
    pInfo->firmwareVersion.minor = g_info.fw_version & 0xFF;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != OPENHSM_SLOT_ID || pInfo == NULL) return CKR_SLOT_ID_INVALID;
    if (!g_have_info) refresh_info();

    memset(pInfo, 0, sizeof(*pInfo));
    pad_set(pInfo->label, sizeof(pInfo->label), "OpenHSM Token");
    pad_set(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "OpenHSM Project");
    pad_set(pInfo->model, sizeof(pInfo->model), "STM32U585");

    /* Serial number = hex of the device's 96-bit UID (16 chars). */
    char serial[17];
    for (int i = 0; i < 6; i++)
        snprintf(serial + i * 2, 3, "%02X", g_info.serial[i]);
    pad_set(pInfo->serialNumber, sizeof(pInfo->serialNumber), serial);

    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_RNG | CKF_LOGIN_REQUIRED;
    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxPinLen = 32;
    pInfo->ulMinPinLen = 4;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = (g_info.fw_version >> 8) & 0xFF;
    pInfo->firmwareVersion.minor = g_info.fw_version & 0xFF;
    return CKR_OK;
}

/* Mechanisms supported by the token. */
static const CK_MECHANISM_TYPE g_mechs[] = {
    CKM_SHA256_HMAC,
    CKM_AES_GCM,
    CKM_AES_KEY_WRAP,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_EDDSA,
    CKM_AES_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
};

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pList,
                         CK_ULONG_PTR pulCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != OPENHSM_SLOT_ID || pulCount == NULL) return CKR_SLOT_ID_INVALID;
    CK_ULONG n = sizeof(g_mechs) / sizeof(g_mechs[0]);
    if (pList == NULL) { *pulCount = n; return CKR_OK; }
    if (*pulCount < n) { *pulCount = n; return CKR_BUFFER_TOO_SMALL; }
    memcpy(pList, g_mechs, sizeof(g_mechs));
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != OPENHSM_SLOT_ID || pInfo == NULL) return CKR_SLOT_ID_INVALID;
    memset(pInfo, 0, sizeof(*pInfo));
    switch (type) {
    case CKM_AES_GCM:
        pInfo->ulMinKeySize = 32; pInfo->ulMaxKeySize = 32;
        pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
        break;
    case CKM_SHA256_HMAC:
        pInfo->ulMinKeySize = 32; pInfo->ulMaxKeySize = 32;
        pInfo->flags = CKF_SIGN | CKF_VERIFY;
        break;
    case CKM_AES_KEY_WRAP:
        pInfo->ulMinKeySize = 32; pInfo->ulMaxKeySize = 32;
        pInfo->flags = CKF_WRAP | CKF_UNWRAP;
        break;
    case CKM_EDDSA:
        pInfo->ulMinKeySize = 32; pInfo->ulMaxKeySize = 32;
        pInfo->flags = CKF_SIGN | CKF_VERIFY;
        break;
    case CKM_AES_KEY_GEN:
    case CKM_GENERIC_SECRET_KEY_GEN:
    case CKM_EC_EDWARDS_KEY_PAIR_GEN:
        pInfo->ulMinKeySize = 32; pInfo->ulMaxKeySize = 32;
        pInfo->flags = CKF_GENERATE | CKF_GENERATE_KEY_PAIR;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }
    return CKR_OK;
}

/* ===========================================================================
 *  Function list
 * ===========================================================================*/
static CK_FUNCTION_LIST function_list = {
    .version = { 2, 40 },
    .C_Initialize        = C_Initialize,
    .C_Finalize          = C_Finalize,
    .C_GetInfo           = C_GetInfo,
    .C_GetFunctionList   = C_GetFunctionList,
    .C_GetSlotList       = C_GetSlotList,
    .C_GetSlotInfo       = C_GetSlotInfo,
    .C_GetTokenInfo      = C_GetTokenInfo,
    .C_GetMechanismList  = C_GetMechanismList,
    .C_GetMechanismInfo  = C_GetMechanismInfo,
    /* later phases: sessions, login, find, crypto */
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
