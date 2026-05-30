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

/* Login: PIN is accepted host-side for now. Real PIN verification with retry/
 * lockout is a future firmware feature (HSM_CMD_AUTH); track state so the
 * PKCS#11 flow (and Vault) works end to end. */
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    (void)pPin; (void)ulPinLen;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_of(hSession) == NULL) return CKR_SESSION_HANDLE_INVALID;
    if (userType != CKU_USER && userType != CKU_SO) return CKR_USER_TYPE_INVALID;
    if (g_logged_in) return CKR_USER_ALREADY_LOGGED_IN;
    g_logged_in = CK_TRUE;
    return CKR_OK;
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

    CK_RV rv = load_objects(s);
    if (rv != CKR_OK) return rv;

    s->nmatch = 0;
    for (int i = 0; i < s->nobjs; i++) {
        if (obj_matches(&s->objs[i], pTemplate, ulCount))
            s->matches[s->nmatch++] = (CK_OBJECT_HANDLE)s->objs[i].id;
    }
    s->find_pos = 0;
    s->find_active = CK_TRUE;
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
    /* later phase: crypto */
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
