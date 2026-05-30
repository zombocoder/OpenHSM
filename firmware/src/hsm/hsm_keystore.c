/**
 * @file    hsm_keystore.c
 * @brief   Encrypted object key store.
 *
 * Key hierarchy:
 *   HUK = HKDF(salt="OpenHSM-HUK-v1", ikm = 96-bit device UID)
 *   KEK = HKDF(salt="OpenHSM-KEK-v1", ikm = HUK)
 *   object key blob = AES-256-GCM(KEK, random nonce, AAD = object metadata)
 *
 * SECURITY NOTE (milestone limitation): the HUK is derived from the readable
 * device UID with an in-firmware KDF, so the KEK is recoverable by anyone who
 * can read the chip. This satisfies "no plaintext key material in flash" but
 * NOT confidentiality of the KEK — that requires RDP level 2 + TrustZone +
 * a provisioned device secret (a later milestone). Object keys themselves are
 * never stored or exported in plaintext.
 *
 * Persistence: the whole store lives in one flash page mirrored by a RAM image;
 * any change rewrites the page (erase + program + read-back verify).
 */
#include "hsm_keystore.h"
#include "hsm_flash.h"
#include "hsm_hash.h"
#include "hsm_aead.h"
#include "hsm_rng.h"
#include "stm32u5xx.h"

#include <string.h>

#define STORE_MAGIC 0x4F485354u  /* "OHST" */
#define SLOT_MAGIC  0x4F484B31u  /* "OHK1" */
#define STORE_VERSION 5u  /* usage_counter moved out of the authenticated AAD */
#define KEY_BLOB_MAX 64u

/* One object slot (160 bytes, multiple of the 16-byte flash quad-word). */
typedef struct __attribute__((packed)) {
    uint32_t magic;        /* SLOT_MAGIC = occupied, else free                  */
    uint32_t id;
    uint16_t algorithm;
    uint16_t capabilities;
    uint16_t key_bits;
    uint8_t  exportable;
    uint8_t  auth_domain;
    uint32_t created_seq;
    uint8_t  label[HSM_LABEL_LEN];
    uint16_t key_len;
    uint8_t  reserved[2];
    /* --- everything above is the IMMUTABLE metadata, authenticated as GCM AAD.
     *     usage_counter is mutable and MUST stay out of the AAD, else bumping it
     *     invalidates the GCM tag and the key can never be loaded again. --- */
    uint8_t  nonce[12];
    uint8_t  tag[16];
    uint8_t  enc_key[KEY_BLOB_MAX];
    uint32_t usage_counter; /* mutable; deliberately AFTER the AAD region        */
    uint8_t  slot_pad[8];   /* pad to 160 bytes so every slot is 16-byte aligned */
} keyslot_t;
_Static_assert(sizeof(((keyslot_t *)0)->enc_key) == 64, "enc_key size");
/* keyslot_t must be a multiple of 16 so slots[i] stay 16-aligned (store header
 * is 16 bytes); the AES engine misbehaves on a 16-misaligned GCM AAD pointer. */
_Static_assert((sizeof(keyslot_t) % 16) == 0, "keyslot not 16-aligned");

#define SLOT_AAD_LEN  offsetof(keyslot_t, nonce)  /* metadata authenticated */

typedef struct __attribute__((packed)) {
    uint32_t  magic;
    uint32_t  version;
    uint32_t  next_id;
    uint32_t  next_seq;
    keyslot_t slots[HSM_MAX_OBJECTS];
} store_t;

static store_t   store __attribute__((aligned(16)));  /* RAM image, 16-aligned
                                  so each slot's GCM AAD pointer is 16-aligned */
static uint8_t   kek[32];        /* derived at boot, kept in RAM only */

/* ------------------------------------------------------------------------- */

static void derive_kek(void)
{
    const volatile uint32_t *uid = (const volatile uint32_t *)UID_BASE;
    uint8_t uidb[12], huk[32];
    for (unsigned i = 0; i < 3; i++) {
        uint32_t w = uid[i];
        uidb[i*4+0] = (uint8_t)w;       uidb[i*4+1] = (uint8_t)(w >> 8);
        uidb[i*4+2] = (uint8_t)(w >> 16); uidb[i*4+3] = (uint8_t)(w >> 24);
    }
    HSM_HkdfSha256((const uint8_t *)"OpenHSM-HUK-v1", 14, uidb, sizeof(uidb),
                   NULL, 0, huk, sizeof(huk));
    HSM_HkdfSha256((const uint8_t *)"OpenHSM-KEK-v1", 14, huk, sizeof(huk),
                   NULL, 0, kek, sizeof(kek));
    memset(huk, 0, sizeof(huk));
    memset(uidb, 0, sizeof(uidb));
}

static void store_reset(void)
{
    memset(&store, 0, sizeof(store));
    store.magic   = STORE_MAGIC;
    store.version = STORE_VERSION;
    store.next_id = 1;
    store.next_seq = 1;
}

static int persist(void)
{
    return HSM_Flash_WriteRegion(&store, sizeof(store));
}

void HSM_KeyStore_Init(void)
{
    derive_kek();
    HSM_Flash_Read(0, &store, sizeof(store));
    if (store.magic != STORE_MAGIC || store.version != STORE_VERSION) {
        store_reset();   /* fresh / blank flash */
    }
}

static keyslot_t *find_slot(uint32_t id)
{
    for (unsigned i = 0; i < HSM_MAX_OBJECTS; i++) {
        if (store.slots[i].magic == SLOT_MAGIC && store.slots[i].id == id) {
            return &store.slots[i];
        }
    }
    return NULL;
}

static void fill_info(const keyslot_t *s, hsm_obj_info_t *out)
{
    out->id            = s->id;
    out->algorithm     = s->algorithm;
    out->capabilities  = s->capabilities;
    out->key_bits      = s->key_bits;
    out->exportable    = s->exportable;
    out->auth_domain   = s->auth_domain;
    out->usage_counter = s->usage_counter;
    out->created_seq   = s->created_seq;
    memcpy(out->label, s->label, HSM_LABEL_LEN);
}

uint16_t HSM_KeyStore_Generate(const hsm_genkey_req_t *req, hsm_obj_info_t *out)
{
    uint16_t key_len;
    switch (req->algorithm) {
    case HSM_KEY_AES256:
    case HSM_KEY_HMAC256:
    case HSM_KEY_ED25519:
    case HSM_KEY_X25519:
        key_len = 32;
        break;
    default:
        return HSM_ERR_INVALID_PARAM;
    }

    keyslot_t *s = NULL;
    for (unsigned i = 0; i < HSM_MAX_OBJECTS; i++) {
        if (store.slots[i].magic != SLOT_MAGIC) { s = &store.slots[i]; break; }
    }
    if (s == NULL) {
        return HSM_ERR_INTERNAL;  /* store full */
    }

    uint8_t key[KEY_BLOB_MAX];
    if (HSM_Rng_Fill(key, key_len) != 0) {
        return HSM_ERR_INTERNAL;
    }

    /* Populate metadata first (it is the GCM AAD). */
    memset(s, 0, sizeof(*s));
    s->magic        = SLOT_MAGIC;
    s->id           = store.next_id;
    s->algorithm    = req->algorithm;
    s->capabilities = req->capabilities;
    s->key_bits     = req->key_bits;
    s->exportable   = req->exportable;
    s->auth_domain  = req->auth_domain;
    s->usage_counter = 0;
    s->created_seq  = store.next_seq;
    memcpy(s->label, req->label, HSM_LABEL_LEN);
    s->key_len      = key_len;

    if (HSM_Rng_Fill(s->nonce, sizeof(s->nonce)) != 0 ||
        HSM_AesGcmEncrypt(kek, s->nonce, (const uint8_t *)s, SLOT_AAD_LEN,
                          key, key_len, s->enc_key, s->tag) != 0) {
        memset(s, 0, sizeof(*s));
        memset(key, 0, sizeof(key));
        return HSM_ERR_INTERNAL;
    }
    memset(key, 0, sizeof(key));

    if (persist() != 0) {
        memset(s, 0, sizeof(*s));  /* roll back RAM image on flash failure */
        return HSM_ERR_INTERNAL;
    }
    store.next_id++;
    store.next_seq++;
    /* next_id/next_seq advanced in RAM; persisted on the next change. The slot
     * is already durable, so a power loss here only "wastes" an id at worst. */
    persist();

    /* Self-verify: the freshly stored key must decrypt back. Catches a born-
     * corrupt blob immediately instead of at first use. */
    uint8_t vk[KEY_BLOB_MAX]; uint16_t vlen;
    uint16_t vst = HSM_KeyStore_LoadKey(s->id, vk, &vlen);
    memset(vk, 0, sizeof(vk));
    if (vst != HSM_OK) {
        return HSM_ERR_KEY_VERIFY;
    }

    fill_info(s, out);
    return HSM_OK;
}

uint16_t HSM_KeyStore_Find(const uint8_t *label, hsm_obj_info_t *out, uint16_t max)
{
    uint16_t n = 0;
    for (unsigned i = 0; i < HSM_MAX_OBJECTS && n < max; i++) {
        keyslot_t *s = &store.slots[i];
        if (s->magic != SLOT_MAGIC) continue;
        if (label != NULL && memcmp(s->label, label, HSM_LABEL_LEN) != 0) continue;
        fill_info(s, &out[n++]);
    }
    return n;
}

uint16_t HSM_KeyStore_Get(uint32_t id, hsm_obj_info_t *out)
{
    keyslot_t *s = find_slot(id);
    if (s == NULL) return HSM_ERR_INVALID_PARAM;
    fill_info(s, out);
    return HSM_OK;
}

uint16_t HSM_KeyStore_Delete(uint32_t id)
{
    keyslot_t *s = find_slot(id);
    if (s == NULL) return HSM_ERR_INVALID_PARAM;
    memset(s, 0, sizeof(*s));   /* zeroize slot (incl. encrypted key + tag) */
    if (persist() != 0) return HSM_ERR_INTERNAL;
    return HSM_OK;
}

uint16_t HSM_KeyStore_LoadKey(uint32_t id, uint8_t *out, uint16_t *out_len)
{
    keyslot_t *s = find_slot(id);
    if (s == NULL) return HSM_ERR_INVALID_PARAM;
    if (HSM_AesGcmDecrypt(kek, s->nonce, (const uint8_t *)s, SLOT_AAD_LEN,
                          s->enc_key, s->key_len, s->tag, out) != 0) {
        return HSM_ERR_INTERNAL;   /* tamper / corruption */
    }
    *out_len = s->key_len;
    return HSM_OK;
}

void HSM_KeyStore_BumpUsage(uint32_t id)
{
    keyslot_t *s = find_slot(id);
    if (s != NULL) s->usage_counter++;
}

