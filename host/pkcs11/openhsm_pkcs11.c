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
#include <stdlib.h>

/* Optional call tracing for bring-up against real PKCS#11 consumers. */
#define DBG(...) do { if (getenv("OPENHSM_DEBUG")) { \
    fprintf(stderr, "[p11] " __VA_ARGS__); fputc('\n', stderr); } } while (0)

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
 *  Sessions
 * ===========================================================================*/
#define MAX_SESSIONS 8

typedef struct {
    CK_BBOOL       in_use;
    CK_FLAGS       flags;
    /* find-objects state */
    CK_BBOOL       find_active;
    hsm_obj_info_t objs[HSM_MAX_OBJECTS];
    int            nobjs;
    CK_OBJECT_HANDLE matches[HSM_MAX_OBJECTS];
    int            nmatch;
    int            find_pos;
    /* crypto-operation state (one of each kind may be active) */
    CK_BBOOL       enc_active, dec_active, sign_active;
    CK_MECHANISM_TYPE enc_mech, dec_mech, sign_mech;
    CK_OBJECT_HANDLE  enc_key, dec_key, sign_key;
    uint8_t        gcm_iv[16];   CK_ULONG gcm_iv_len;
    uint8_t        gcm_aad[128]; CK_ULONG gcm_aad_len;   /* for encrypt */
    uint8_t        dec_iv[16];   CK_ULONG dec_iv_len;
    uint8_t        dec_aad[128]; CK_ULONG dec_aad_len;   /* for decrypt */
} session_t;

static session_t g_sessions[MAX_SESSIONS];
static CK_BBOOL  g_logged_in;

static session_t *session_of(CK_SESSION_HANDLE h)
{
    if (h == CK_INVALID_HANDLE || h > MAX_SESSIONS) return NULL;
    session_t *s = &g_sessions[h - 1];
    return s->in_use ? s : NULL;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApp,
                    CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
    (void)pApp; (void)notify;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != OPENHSM_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (phSession == NULL) return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION)) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].in_use = CK_TRUE;
            g_sessions[i].flags = flags;
            *phSession = (CK_SESSION_HANDLE)(i + 1);
            return CKR_OK;
        }
    }
    return CKR_SESSION_COUNT;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    memset(s, 0, sizeof(*s));
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != OPENHSM_SLOT_ID) return CKR_SLOT_ID_INVALID;
    memset(g_sessions, 0, sizeof(g_sessions));
    g_logged_in = CK_FALSE;
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (pInfo == NULL) return CKR_ARGUMENTS_BAD;
    pInfo->slotID = OPENHSM_SLOT_ID;
    pInfo->flags = s->flags;
    pInfo->ulDeviceError = 0;
    if (g_logged_in)
        pInfo->state = (s->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS
                                                   : CKS_RO_USER_FUNCTIONS;
    else
        pInfo->state = (s->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION
                                                   : CKS_RO_PUBLIC_SESSION;
    return CKR_OK;
}

/* Login: forward the PIN to the device's AUTH command, which verifies it and
 * manages the persistent retry counter / lockout. */
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_of(hSession) == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (userType != CKU_USER && userType != CKU_SO) return CKR_USER_TYPE_INVALID;
    DBG("C_Login userType=%lu pinLen=%lu", (unsigned long)userType, (unsigned long)ulPinLen);
    if (g_logged_in) return CKR_USER_ALREADY_LOGGED_IN;
    if (pPin == NULL || ulPinLen == 0) return CKR_PIN_INCORRECT;

    uint8_t resp[HSM_MAX_MSG]; int rl = 0;
    if (ohsm_cmd(g_ctx, HSM_CMD_AUTH, pPin, (uint16_t)ulPinLen,
                 resp, sizeof(resp), &rl) != 0) return CKR_DEVICE_ERROR;
    hsm_header_t *rh = (hsm_header_t *)resp;
    DBG("C_Login device AUTH status=0x%04x", rh->status);
    switch (rh->status) {
    case HSM_OK:               g_logged_in = CK_TRUE; return CKR_OK;
    case HSM_ERR_LOCKED:       return CKR_PIN_LOCKED;
    case HSM_ERR_NOT_AUTHORIZED: return CKR_PIN_INCORRECT;
    default:                   return CKR_FUNCTION_FAILED;
    }
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_of(hSession) == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (!g_logged_in) return CKR_USER_NOT_LOGGED_IN;
    g_logged_in = CK_FALSE;
    return CKR_OK;
}

/* ===========================================================================
 *  Object search + attributes
 * ===========================================================================*/
static CK_OBJECT_CLASS class_of(uint16_t alg)
{
    switch (alg) {
    case HSM_KEY_AES256:
    case HSM_KEY_HMAC256: return CKO_SECRET_KEY;
    case HSM_KEY_ED25519:
    case HSM_KEY_X25519:  return CKO_PRIVATE_KEY;
    default:              return CKO_SECRET_KEY;
    }
}

static CK_KEY_TYPE keytype_of(uint16_t alg)
{
    switch (alg) {
    case HSM_KEY_AES256:  return CKK_AES;
    case HSM_KEY_HMAC256: return CKK_GENERIC_SECRET;
    case HSM_KEY_ED25519: return CKK_EC_EDWARDS;
    case HSM_KEY_X25519:  return CKK_EC_MONTGOMERY;
    default:              return CKK_GENERIC_SECRET;
    }
}

/* Load all objects from the device into the session cache. */
static CK_RV load_objects(session_t *s)
{
    uint8_t resp[HSM_MAX_MSG];
    int rl = 0;
    s->nobjs = 0;
    if (ohsm_cmd(g_ctx, HSM_CMD_FIND_OBJECT, NULL, 0, resp, sizeof(resp), &rl) != 0)
        return CKR_DEVICE_ERROR;
    hsm_header_t *rh = (hsm_header_t *)resp;
    if (rh->status != HSM_OK) return CKR_DEVICE_ERROR;
    hsm_find_resp_t fr;
    memcpy(&fr, resp + HSM_HEADER_SIZE, sizeof(fr));
    int n = fr.count;
    if (n > (int)HSM_MAX_OBJECTS) n = (int)HSM_MAX_OBJECTS;
    const uint8_t *p = resp + HSM_HEADER_SIZE + sizeof(fr);
    for (int i = 0; i < n; i++)
        memcpy(&s->objs[i], p + i * sizeof(hsm_obj_info_t), sizeof(hsm_obj_info_t));
    s->nobjs = n;
    return CKR_OK;
}

static const hsm_obj_info_t *obj_by_handle(session_t *s, CK_OBJECT_HANDLE h)
{
    for (int i = 0; i < s->nobjs; i++)
        if (s->objs[i].id == (uint32_t)h) return &s->objs[i];
    return NULL;
}

/* Does object o match every attribute in the template? */
static int obj_matches(const hsm_obj_info_t *o, CK_ATTRIBUTE_PTR t, CK_ULONG n)
{
    for (CK_ULONG i = 0; i < n; i++) {
        switch (t[i].type) {
        case CKA_CLASS:
            if (*(CK_OBJECT_CLASS *)t[i].pValue != class_of(o->algorithm)) return 0;
            break;
        case CKA_KEY_TYPE:
            if (*(CK_KEY_TYPE *)t[i].pValue != keytype_of(o->algorithm)) return 0;
            break;
        case CKA_LABEL: {
            size_t l = strnlen((const char *)o->label, HSM_LABEL_LEN);
            if (t[i].ulValueLen != l || memcmp(t[i].pValue, o->label, l) != 0) return 0;
            break;
        }
        case CKA_ID: {
            uint32_t want = 0;
            memcpy(&want, t[i].pValue, t[i].ulValueLen < 4 ? t[i].ulValueLen : 4);
            if (want != o->id) return 0;
            break;
        }
        default: /* ignore unsupported match attributes */
            break;
        }
    }
    return 1;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (s->find_active) return CKR_OPERATION_ACTIVE;

    DBG("C_FindObjectsInit nattr=%lu", (unsigned long)ulCount);
    for (CK_ULONG i = 0; i < ulCount; i++) {
        if (pTemplate[i].type == CKA_LABEL)
            DBG("  filter CKA_LABEL=\"%.*s\"", (int)pTemplate[i].ulValueLen, (char *)pTemplate[i].pValue);
        else if (pTemplate[i].type == CKA_CLASS)
            DBG("  filter CKA_CLASS=%lu", (unsigned long)*(CK_OBJECT_CLASS *)pTemplate[i].pValue);
        else DBG("  filter type=0x%lx", (unsigned long)pTemplate[i].type);
    }
    CK_RV rv = load_objects(s);
    if (rv != CKR_OK) return rv;

    s->nmatch = 0;
    for (int i = 0; i < s->nobjs; i++) {
        if (obj_matches(&s->objs[i], pTemplate, ulCount))
            s->matches[s->nmatch++] = (CK_OBJECT_HANDLE)s->objs[i].id;
    }
    s->find_pos = 0;
    s->find_active = CK_TRUE;
    DBG("C_FindObjectsInit matched=%d of %d objects", s->nmatch, s->nobjs);
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (!s->find_active) return CKR_OPERATION_NOT_INITIALIZED;
    if (phObject == NULL || pulObjectCount == NULL) return CKR_ARGUMENTS_BAD;

    CK_ULONG out = 0;
    while (s->find_pos < s->nmatch && out < ulMaxObjectCount)
        phObject[out++] = s->matches[s->find_pos++];
    *pulObjectCount = out;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    s->find_active = CK_FALSE;
    return CKR_OK;
}

/* Set one attribute's value into the template entry (PKCS#11 size/copy rules). */
static CK_RV set_attr(CK_ATTRIBUTE_PTR a, const void *val, CK_ULONG len)
{
    if (a->pValue == NULL) { a->ulValueLen = len; return CKR_OK; }
    if (a->ulValueLen < len) { a->ulValueLen = CK_UNAVAILABLE_INFORMATION; return CKR_BUFFER_TOO_SMALL; }
    memcpy(a->pValue, val, len);
    a->ulValueLen = len;
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    const hsm_obj_info_t *o = obj_by_handle(s, hObject);
    if (o == NULL) return CKR_OBJECT_HANDLE_INVALID;

    CK_RV result = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE_PTR a = &pTemplate[i];
        switch (a->type) {
        case CKA_CLASS:        { CK_OBJECT_CLASS v = class_of(o->algorithm); set_attr(a, &v, sizeof(v)); break; }
        case CKA_KEY_TYPE:     { CK_KEY_TYPE v = keytype_of(o->algorithm); set_attr(a, &v, sizeof(v)); break; }
        case CKA_TOKEN:        { CK_BBOOL v = CK_TRUE; set_attr(a, &v, sizeof(v)); break; }
        case CKA_PRIVATE:      { CK_BBOOL v = (class_of(o->algorithm) == CKO_PRIVATE_KEY); set_attr(a, &v, sizeof(v)); break; }
        case CKA_SENSITIVE:    { CK_BBOOL v = CK_TRUE; set_attr(a, &v, sizeof(v)); break; }
        case CKA_EXTRACTABLE:  { CK_BBOOL v = o->exportable ? CK_TRUE : CK_FALSE; set_attr(a, &v, sizeof(v)); break; }
        case CKA_SIGN:         { CK_BBOOL v = (o->capabilities & HSM_CAP_SIGN) ? CK_TRUE : CK_FALSE; set_attr(a, &v, sizeof(v)); break; }
        case CKA_VERIFY:       { CK_BBOOL v = (o->capabilities & HSM_CAP_VERIFY) ? CK_TRUE : CK_FALSE; set_attr(a, &v, sizeof(v)); break; }
        case CKA_ENCRYPT:      { CK_BBOOL v = (o->capabilities & HSM_CAP_ENCRYPT) ? CK_TRUE : CK_FALSE; set_attr(a, &v, sizeof(v)); break; }
        case CKA_DECRYPT:      { CK_BBOOL v = (o->capabilities & HSM_CAP_DECRYPT) ? CK_TRUE : CK_FALSE; set_attr(a, &v, sizeof(v)); break; }
        case CKA_WRAP:         { CK_BBOOL v = (o->capabilities & HSM_CAP_WRAP) ? CK_TRUE : CK_FALSE; set_attr(a, &v, sizeof(v)); break; }
        case CKA_UNWRAP:       { CK_BBOOL v = (o->capabilities & HSM_CAP_UNWRAP) ? CK_TRUE : CK_FALSE; set_attr(a, &v, sizeof(v)); break; }
        case CKA_LABEL:        set_attr(a, o->label, strnlen((const char *)o->label, HSM_LABEL_LEN)); break;
        case CKA_ID:           { uint8_t id[4] = { (uint8_t)o->id, (uint8_t)(o->id>>8), (uint8_t)(o->id>>16), (uint8_t)(o->id>>24) }; set_attr(a, id, 4); break; }
        case CKA_VALUE_LEN:    { CK_ULONG v = o->key_bits / 8; set_attr(a, &v, sizeof(v)); break; }
        default:
            a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            result = CKR_ATTRIBUTE_TYPE_INVALID;
            break;
        }
    }
    return result;
}

/* ===========================================================================
 *  Crypto operations
 * ===========================================================================*/

/* Send a command and return the response header + payload pointer/len. */
static CK_RV device_cmd(uint16_t cmd, const uint8_t *payload, uint16_t plen,
                        uint8_t *resp, int cap, const uint8_t **out, int *out_len)
{
    int rl = 0;
    if (ohsm_cmd(g_ctx, cmd, payload, plen, resp, cap, &rl) != 0) return CKR_DEVICE_ERROR;
    hsm_header_t *rh = (hsm_header_t *)resp;
    if (rh->status != HSM_OK) return CKR_FUNCTION_FAILED;
    if (out) *out = resp + HSM_HEADER_SIZE;
    if (out_len) *out_len = rh->payload_length;
    return CKR_OK;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulLen)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_of(hSession) == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (pData == NULL && ulLen) return CKR_ARGUMENTS_BAD;

    uint8_t resp[HSM_MAX_MSG];
    CK_ULONG done = 0;
    while (done < ulLen) {
        uint16_t chunk = (ulLen - done) > 256 ? 256 : (uint16_t)(ulLen - done);
        uint8_t req[2] = { (uint8_t)chunk, (uint8_t)(chunk >> 8) };
        const uint8_t *out; int olen;
        if (device_cmd(HSM_CMD_RANDOM, req, 2, resp, sizeof(resp), &out, &olen) != CKR_OK)
            return CKR_DEVICE_ERROR;
        if (olen < chunk) return CKR_DEVICE_ERROR;
        memcpy(pData + done, out, chunk);
        done += chunk;
    }
    return CKR_OK;
}

/* ---- AES-GCM encrypt/decrypt ---- */
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMech, CK_OBJECT_HANDLE hKey)
{
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (pMech == NULL || pMech->mechanism != CKM_AES_GCM) return CKR_MECHANISM_INVALID;
    CK_GCM_PARAMS *p = (CK_GCM_PARAMS *)pMech->pParameter;
    if (p == NULL || p->pIv == NULL || p->ulIvLen > sizeof(s->gcm_iv) ||
        p->ulAADLen > sizeof(s->gcm_aad)) return CKR_MECHANISM_PARAM_INVALID;
    memcpy(s->gcm_iv, p->pIv, p->ulIvLen);     s->gcm_iv_len = p->ulIvLen;
    s->gcm_aad_len = p->ulAADLen;
    if (p->ulAADLen) memcpy(s->gcm_aad, p->pAAD, p->ulAADLen);
    s->enc_key = hKey; s->enc_mech = pMech->mechanism; s->enc_active = CK_TRUE;
    return CKR_OK;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEnc, CK_ULONG_PTR pulEncLen)
{
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (!s->enc_active) return CKR_OPERATION_NOT_INITIALIZED;
    CK_ULONG need = ulDataLen + 16;            /* ciphertext || GCM tag */
    if (pEnc == NULL) { *pulEncLen = need; return CKR_OK; }
    if (*pulEncLen < need) { *pulEncLen = need; return CKR_BUFFER_TOO_SMALL; }

    uint8_t req[HSM_MAX_MSG], resp[HSM_MAX_MSG];
    hsm_aead_req_t r = { .key_id = (uint32_t)s->enc_key,
                         .aad_len = (uint16_t)s->gcm_aad_len,
                         .data_len = (uint16_t)ulDataLen };
    memset(r.nonce, 0, 12);
    memcpy(r.nonce, s->gcm_iv, s->gcm_iv_len < 12 ? s->gcm_iv_len : 12);
    size_t off = 0;
    memcpy(req, &r, sizeof(r)); off += sizeof(r);
    memcpy(req + off, s->gcm_aad, s->gcm_aad_len); off += s->gcm_aad_len;
    memcpy(req + off, pData, ulDataLen); off += ulDataLen;

    const uint8_t *out; int olen;
    CK_RV rv = device_cmd(HSM_CMD_ENCRYPT, req, (uint16_t)off, resp, sizeof(resp), &out, &olen);
    s->enc_active = CK_FALSE;
    if (rv != CKR_OK) return rv;
    if (olen != (int)need) return CKR_DEVICE_ERROR;
    memcpy(pEnc, out, need);
    *pulEncLen = need;
    return CKR_OK;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMech, CK_OBJECT_HANDLE hKey)
{
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (pMech == NULL || pMech->mechanism != CKM_AES_GCM) return CKR_MECHANISM_INVALID;
    CK_GCM_PARAMS *p = (CK_GCM_PARAMS *)pMech->pParameter;
    if (p == NULL || p->pIv == NULL || p->ulIvLen > sizeof(s->dec_iv) ||
        p->ulAADLen > sizeof(s->dec_aad)) return CKR_MECHANISM_PARAM_INVALID;
    memcpy(s->dec_iv, p->pIv, p->ulIvLen);     s->dec_iv_len = p->ulIvLen;
    s->dec_aad_len = p->ulAADLen;
    if (p->ulAADLen) memcpy(s->dec_aad, p->pAAD, p->ulAADLen);
    s->dec_key = hKey; s->dec_mech = pMech->mechanism; s->dec_active = CK_TRUE;
    return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEnc, CK_ULONG ulEncLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (!s->dec_active) return CKR_OPERATION_NOT_INITIALIZED;
    if (ulEncLen < 16) return CKR_ENCRYPTED_DATA_LEN_RANGE;
    CK_ULONG ptlen = ulEncLen - 16;            /* strip the GCM tag */
    if (pData == NULL) { *pulDataLen = ptlen; return CKR_OK; }
    if (*pulDataLen < ptlen) { *pulDataLen = ptlen; return CKR_BUFFER_TOO_SMALL; }

    uint8_t req[HSM_MAX_MSG], resp[HSM_MAX_MSG];
    hsm_aead_req_t r = { .key_id = (uint32_t)s->dec_key,
                         .aad_len = (uint16_t)s->dec_aad_len,
                         .data_len = (uint16_t)ptlen };
    memset(r.nonce, 0, 12);
    memcpy(r.nonce, s->dec_iv, s->dec_iv_len < 12 ? s->dec_iv_len : 12);
    size_t off = 0;
    memcpy(req, &r, sizeof(r)); off += sizeof(r);
    memcpy(req + off, s->dec_aad, s->dec_aad_len); off += s->dec_aad_len;
    memcpy(req + off, pEnc, ulEncLen); off += ulEncLen;   /* ct || tag */

    const uint8_t *out; int olen;
    CK_RV rv = device_cmd(HSM_CMD_DECRYPT, req, (uint16_t)off, resp, sizeof(resp), &out, &olen);
    s->dec_active = CK_FALSE;
    if (rv != CKR_OK) return CKR_ENCRYPTED_DATA_INVALID;   /* tag failure etc. */
    if (olen != (int)ptlen) return CKR_DEVICE_ERROR;
    memcpy(pData, out, ptlen);
    *pulDataLen = ptlen;
    return CKR_OK;
}

/* ---- Sign (HMAC-SHA256 / EdDSA) ---- */
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMech, CK_OBJECT_HANDLE hKey)
{
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (pMech == NULL) return CKR_ARGUMENTS_BAD;
    if (pMech->mechanism != CKM_SHA256_HMAC && pMech->mechanism != CKM_EDDSA)
        return CKR_MECHANISM_INVALID;
    s->sign_key = hKey; s->sign_mech = pMech->mechanism; s->sign_active = CK_TRUE;
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSig, CK_ULONG_PTR pulSigLen)
{
    session_t *s = session_of(hSession);
    if (s == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (!s->sign_active) return CKR_OPERATION_NOT_INITIALIZED;
    CK_ULONG siglen = (s->sign_mech == CKM_EDDSA) ? 64 : 32;
    uint16_t devcmd = (s->sign_mech == CKM_EDDSA) ? HSM_CMD_SIGN : HSM_CMD_HMAC;
    if (pSig == NULL) { *pulSigLen = siglen; return CKR_OK; }
    if (*pulSigLen < siglen) { *pulSigLen = siglen; return CKR_BUFFER_TOO_SMALL; }

    uint8_t req[HSM_MAX_MSG], resp[HSM_MAX_MSG];
    hsm_keyop_req_t r = { .id = (uint32_t)s->sign_key, .msg_len = (uint16_t)ulDataLen };
    memcpy(req, &r, sizeof(r));
    memcpy(req + sizeof(r), pData, ulDataLen);

    const uint8_t *out; int olen;
    CK_RV rv = device_cmd(devcmd, req, (uint16_t)(sizeof(r) + ulDataLen),
                          resp, sizeof(resp), &out, &olen);
    s->sign_active = CK_FALSE;
    if (rv != CKR_OK) return rv;
    if (olen != (int)siglen) return CKR_DEVICE_ERROR;
    memcpy(pSig, out, siglen);
    *pulSigLen = siglen;
    return CKR_OK;
}

/* ---- Key generation ---- */
static void parse_keygen_template(CK_ATTRIBUTE_PTR t, CK_ULONG n,
                                  hsm_genkey_req_t *rq)
{
    for (CK_ULONG i = 0; i < n; i++) {
        CK_BBOOL b = (t[i].pValue && t[i].ulValueLen >= 1) ? *(CK_BBOOL *)t[i].pValue : CK_FALSE;
        switch (t[i].type) {
        case CKA_LABEL: {
            CK_ULONG l = t[i].ulValueLen; if (l > HSM_LABEL_LEN) l = HSM_LABEL_LEN;
            memcpy(rq->label, t[i].pValue, l);
            break;
        }
        case CKA_ENCRYPT:    if (b) rq->capabilities |= HSM_CAP_ENCRYPT; break;
        case CKA_DECRYPT:    if (b) rq->capabilities |= HSM_CAP_DECRYPT; break;
        case CKA_SIGN:       if (b) rq->capabilities |= HSM_CAP_SIGN; break;
        case CKA_VERIFY:     if (b) rq->capabilities |= HSM_CAP_VERIFY; break;
        case CKA_WRAP:       if (b) rq->capabilities |= HSM_CAP_WRAP; break;
        case CKA_UNWRAP:     if (b) rq->capabilities |= HSM_CAP_UNWRAP; break;
        case CKA_DERIVE:     if (b) rq->capabilities |= HSM_CAP_DERIVE; break;
        case CKA_EXTRACTABLE: rq->exportable = b ? 1 : 0; break;
        default: break;
        }
    }
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMech,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey)
{
    if (session_of(hSession) == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (pMech == NULL || phKey == NULL) return CKR_ARGUMENTS_BAD;

    hsm_genkey_req_t rq;
    memset(&rq, 0, sizeof(rq));
    rq.key_bits = 256;
    if (pMech->mechanism == CKM_AES_KEY_GEN) rq.algorithm = HSM_KEY_AES256;
    else if (pMech->mechanism == CKM_GENERIC_SECRET_KEY_GEN) rq.algorithm = HSM_KEY_HMAC256;
    else { DBG("C_GenerateKey bad mech 0x%lx", (unsigned long)pMech->mechanism); return CKR_MECHANISM_INVALID; }
    parse_keygen_template(pTemplate, ulCount, &rq);
    DBG("C_GenerateKey mech=0x%lx alg=%u caps=0x%04x label=\"%.32s\"",
        (unsigned long)pMech->mechanism, rq.algorithm, rq.capabilities, rq.label);

    uint8_t resp[HSM_MAX_MSG]; const uint8_t *out; int olen;
    CK_RV rv = device_cmd(HSM_CMD_GENERATE_KEY, (uint8_t *)&rq, sizeof(rq),
                          resp, sizeof(resp), &out, &olen);
    if (rv != CKR_OK) { DBG("C_GenerateKey device rv=0x%lx", (unsigned long)rv); return rv; }
    hsm_obj_info_t o; memcpy(&o, out, sizeof(o));
    *phKey = (CK_OBJECT_HANDLE)o.id;
    DBG("C_GenerateKey -> handle=%lu", (unsigned long)o.id);
    return CKR_OK;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMech,
                        CK_ATTRIBUTE_PTR pPubT, CK_ULONG ulPubN,
                        CK_ATTRIBUTE_PTR pPrivT, CK_ULONG ulPrivN,
                        CK_OBJECT_HANDLE_PTR phPub, CK_OBJECT_HANDLE_PTR phPriv)
{
    (void)pPubT; (void)ulPubN;
    if (session_of(hSession) == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (pMech == NULL || phPub == NULL || phPriv == NULL) return CKR_ARGUMENTS_BAD;
    if (pMech->mechanism != CKM_EC_EDWARDS_KEY_PAIR_GEN) return CKR_MECHANISM_INVALID;

    hsm_genkey_req_t rq;
    memset(&rq, 0, sizeof(rq));
    rq.algorithm = HSM_KEY_ED25519;
    rq.key_bits = 256;
    parse_keygen_template(pPrivT, ulPrivN, &rq);

    uint8_t resp[HSM_MAX_MSG]; const uint8_t *out; int olen;
    CK_RV rv = device_cmd(HSM_CMD_GENERATE_KEY, (uint8_t *)&rq, sizeof(rq),
                          resp, sizeof(resp), &out, &olen);
    if (rv != CKR_OK) return rv;
    hsm_obj_info_t o; memcpy(&o, out, sizeof(o));
    /* One device object models the keypair; both handles map to it. The public
     * key bytes are retrievable via CKA_EC_POINT / GET_PUBLIC (future). */
    *phPriv = (CK_OBJECT_HANDLE)o.id;
    *phPub  = (CK_OBJECT_HANDLE)o.id;
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
    .C_OpenSession       = C_OpenSession,
    .C_CloseSession      = C_CloseSession,
    .C_CloseAllSessions  = C_CloseAllSessions,
    .C_GetSessionInfo    = C_GetSessionInfo,
    .C_Login             = C_Login,
    .C_Logout            = C_Logout,
    .C_FindObjectsInit   = C_FindObjectsInit,
    .C_FindObjects       = C_FindObjects,
    .C_FindObjectsFinal  = C_FindObjectsFinal,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_GenerateRandom    = C_GenerateRandom,
    .C_EncryptInit       = C_EncryptInit,
    .C_Encrypt           = C_Encrypt,
    .C_DecryptInit       = C_DecryptInit,
    .C_Decrypt           = C_Decrypt,
    .C_SignInit          = C_SignInit,
    .C_Sign              = C_Sign,
    .C_GenerateKey       = C_GenerateKey,
    .C_GenerateKeyPair   = C_GenerateKeyPair,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
