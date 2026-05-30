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
#define STORE_VERSION 6u  /* reset: clear stale test keys that filled the store */
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

static uint16_t key_len_for(uint16_t algorithm)
{
    switch (algorithm) {
    case HSM_KEY_AES256:
    case HSM_KEY_HMAC256:
    case HSM_KEY_ED25519:
    case HSM_KEY_X25519:
        return 32;
    default:
        return 0;
    }
}

/* Store given key material into a fresh slot, encrypted under the KEK. */
static uint16_t store_key(uint16_t algorithm, uint16_t key_bits, uint16_t caps,
                          uint8_t exportable, uint8_t auth_domain,
                          const uint8_t *label, const uint8_t *material,
                          uint16_t mat_len, hsm_obj_info_t *out)
{
    if (mat_len == 0 || mat_len > KEY_BLOB_MAX) {
        return HSM_ERR_INVALID_PARAM;
    }
    keyslot_t *s = NULL;
    for (unsigned i = 0; i < HSM_MAX_OBJECTS; i++) {
        if (store.slots[i].magic != SLOT_MAGIC) { s = &store.slots[i]; break; }
    }
    if (s == NULL) {
        return HSM_ERR_INTERNAL;  /* store full */
    }

    /* Populate metadata first (it is the GCM AAD). */
    memset(s, 0, sizeof(*s));
    s->magic        = SLOT_MAGIC;
    s->id           = store.next_id;
    s->algorithm    = algorithm;
    s->capabilities = caps;
    s->key_bits     = key_bits;
    s->exportable   = exportable;
    s->auth_domain  = auth_domain;
    s->usage_counter = 0;
    s->created_seq  = store.next_seq;
    memcpy(s->label, label, HSM_LABEL_LEN);
    s->key_len      = mat_len;

    if (HSM_Rng_Fill(s->nonce, sizeof(s->nonce)) != 0 ||
        HSM_AesGcmEncrypt(kek, s->nonce, (const uint8_t *)s, SLOT_AAD_LEN,
                          material, mat_len, s->enc_key, s->tag) != 0) {
        memset(s, 0, sizeof(*s));
        return HSM_ERR_INTERNAL;
    }

    if (persist() != 0) {
        memset(s, 0, sizeof(*s));  /* roll back RAM image on flash failure */
        return HSM_ERR_INTERNAL;
    }
    store.next_id++;
    store.next_seq++;
    /* next_id/next_seq advanced in RAM; persisted on the next change. The slot
     * is already durable, so a power loss here only "wastes" an id at worst. */
    persist();

    /* Self-verify: the freshly stored key must decrypt back. */
    uint8_t vk[KEY_BLOB_MAX]; uint16_t vlen;
    uint16_t vst = HSM_KeyStore_LoadKey(s->id, vk, &vlen);
    memset(vk, 0, sizeof(vk));
    if (vst != HSM_OK) {
        return HSM_ERR_KEY_VERIFY;
    }

    fill_info(s, out);
    return HSM_OK;
}

uint16_t HSM_KeyStore_Generate(const hsm_genkey_req_t *req, hsm_obj_info_t *out)
{
    uint16_t key_len = key_len_for(req->algorithm);
    if (key_len == 0) {
        return HSM_ERR_INVALID_PARAM;
    }
    uint8_t key[KEY_BLOB_MAX];
    if (HSM_Rng_Fill(key, key_len) != 0) {
        return HSM_ERR_INTERNAL;
    }
    uint16_t st = store_key(req->algorithm, req->key_bits, req->capabilities,
                            req->exportable, req->auth_domain, req->label,
                            key, key_len, out);
    memset(key, 0, sizeof(key));
    return st;
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

uint16_t HSM_KeyStore_Encrypt(uint32_t id, const uint8_t nonce[12],
                              const uint8_t *aad, uint16_t aad_len,
                              const uint8_t *pt, uint16_t pt_len,
                              uint8_t *ct_out, uint8_t tag_out[16])
{
    keyslot_t *s = find_slot(id);
    if (s == NULL) return HSM_ERR_INVALID_PARAM;
    if (s->algorithm != HSM_KEY_AES256 || !(s->capabilities & HSM_CAP_ENCRYPT)) {
        return HSM_ERR_NOT_AUTHORIZED;
    }
    uint8_t key[KEY_BLOB_MAX]; uint16_t klen;
    uint16_t st = HSM_KeyStore_LoadKey(id, key, &klen);
    if (st != HSM_OK) return st;
    int rc = HSM_AesGcmEncrypt(key, nonce, aad, aad_len, pt, pt_len, ct_out, tag_out);
    memset(key, 0, sizeof(key));
    if (rc != 0) return HSM_ERR_INTERNAL;
    s->usage_counter++;
    return HSM_OK;
}

uint16_t HSM_KeyStore_Decrypt(uint32_t id, const uint8_t nonce[12],
                              const uint8_t *aad, uint16_t aad_len,
                              const uint8_t *ct, uint16_t ct_len,
                              const uint8_t tag[16], uint8_t *pt_out)
{
    keyslot_t *s = find_slot(id);
    if (s == NULL) return HSM_ERR_INVALID_PARAM;
    if (s->algorithm != HSM_KEY_AES256 || !(s->capabilities & HSM_CAP_DECRYPT)) {
        return HSM_ERR_NOT_AUTHORIZED;
    }
    uint8_t key[KEY_BLOB_MAX]; uint16_t klen;
    uint16_t st = HSM_KeyStore_LoadKey(id, key, &klen);
    if (st != HSM_OK) return st;
    int rc = HSM_AesGcmDecrypt(key, nonce, aad, aad_len, ct, ct_len, tag, pt_out);
    memset(key, 0, sizeof(key));
    if (rc != 0) return HSM_ERR_NOT_AUTHORIZED;  /* bad tag / wrong key */
    s->usage_counter++;
    return HSM_OK;
}

/* Load an AES-256 wrapping key by id, enforcing the required capability. */
static uint16_t load_wrapping_key(uint32_t id, uint16_t need_cap, uint8_t out[32])
{
    keyslot_t *s = find_slot(id);
    if (s == NULL) return HSM_ERR_INVALID_PARAM;
    if (s->algorithm != HSM_KEY_AES256 || !(s->capabilities & need_cap)) {
        return HSM_ERR_NOT_AUTHORIZED;
    }
    uint16_t len;
    return HSM_KeyStore_LoadKey(id, out, &len);
}

uint16_t HSM_KeyStore_Wrap(uint32_t wrap_id, uint32_t target_id,
                           uint8_t *out_blob, uint16_t *out_len)
{
    keyslot_t *t = find_slot(target_id);
    if (t == NULL) return HSM_ERR_INVALID_PARAM;
    if (!t->exportable) return HSM_ERR_NOT_AUTHORIZED;  /* wrapped export only */

    uint8_t wk[32];
    uint16_t st = load_wrapping_key(wrap_id, HSM_CAP_WRAP, wk);
    if (st != HSM_OK) return st;

    uint8_t material[KEY_BLOB_MAX]; uint16_t mat_len;
    st = HSM_KeyStore_LoadKey(target_id, material, &mat_len);
    if (st != HSM_OK) { memset(wk, 0, sizeof(wk)); return st; }

    /* blob = hdr(8) | nonce(12) | ct(mat_len) | tag(16) */
    hsm_wrap_hdr_t hdr = { HSM_WRAP_ALG_AES256GCM, t->algorithm, mat_len, 0 };
    memcpy(out_blob, &hdr, HSM_WRAP_HDR_LEN);
    uint8_t *nonce = out_blob + HSM_WRAP_HDR_LEN;
    uint8_t *ct    = nonce + HSM_WRAP_NONCE_LEN;
    uint8_t *tag   = ct + mat_len;

    int rc = HSM_Rng_Fill(nonce, HSM_WRAP_NONCE_LEN);
    if (rc == 0) {
        rc = HSM_AesGcmEncrypt(wk, nonce, out_blob, HSM_WRAP_HDR_LEN,
                               material, mat_len, ct, tag);
    }
    memset(wk, 0, sizeof(wk));
    memset(material, 0, sizeof(material));
    if (rc != 0) return HSM_ERR_INTERNAL;

    *out_len = (uint16_t)(HSM_WRAP_HDR_LEN + HSM_WRAP_NONCE_LEN + mat_len + HSM_WRAP_TAG_LEN);
    return HSM_OK;
}

uint16_t HSM_KeyStore_Unwrap(uint32_t wrap_id, const uint8_t *blob, uint16_t blob_len,
                             uint16_t caps, uint8_t exportable, uint8_t auth_domain,
                             const uint8_t *label, hsm_obj_info_t *out)
{
    if (blob_len < HSM_WRAP_HDR_LEN + HSM_WRAP_NONCE_LEN + HSM_WRAP_TAG_LEN) {
        return HSM_ERR_BAD_LENGTH;
    }
    hsm_wrap_hdr_t hdr;
    memcpy(&hdr, blob, HSM_WRAP_HDR_LEN);
    if (hdr.wrap_alg != HSM_WRAP_ALG_AES256GCM ||
        key_len_for(hdr.key_type) == 0 || hdr.key_len != key_len_for(hdr.key_type)) {
        return HSM_ERR_INVALID_PARAM;
    }
    if ((uint32_t)HSM_WRAP_HDR_LEN + HSM_WRAP_NONCE_LEN + hdr.key_len + HSM_WRAP_TAG_LEN
        != blob_len) {
        return HSM_ERR_BAD_LENGTH;
    }

    uint8_t wk[32];
    uint16_t st = load_wrapping_key(wrap_id, HSM_CAP_UNWRAP, wk);
    if (st != HSM_OK) return st;

    const uint8_t *nonce = blob + HSM_WRAP_HDR_LEN;
    const uint8_t *ct    = nonce + HSM_WRAP_NONCE_LEN;
    const uint8_t *tag   = ct + hdr.key_len;

    uint8_t material[KEY_BLOB_MAX];
    int rc = HSM_AesGcmDecrypt(wk, nonce, blob, HSM_WRAP_HDR_LEN,
                               ct, hdr.key_len, tag, material);
    memset(wk, 0, sizeof(wk));
    if (rc != 0) {
        memset(material, 0, sizeof(material));
        return HSM_ERR_NOT_AUTHORIZED;  /* bad wrapping key or tampered blob */
    }

    st = store_key(hdr.key_type, 256, caps, exportable, auth_domain,
                   label, material, hdr.key_len, out);
    memset(material, 0, sizeof(material));
    return st;
}

