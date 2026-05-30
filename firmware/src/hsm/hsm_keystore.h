/**
 * @file    hsm_keystore.h
 * @brief   Encrypted object key store (HUK -> KEK -> per-object AES-256-GCM).
 */
#ifndef OPENHSM_HSM_KEYSTORE_H
#define OPENHSM_HSM_KEYSTORE_H

#include <stdint.h>
#include <stddef.h>
#include "hsm_proto.h"

/** @brief Derive the KEK and load the store from flash. Call once at boot. */
void HSM_KeyStore_Init(void);

/**
 * @brief Verify a PIN, managing the persistent retry counter / lockout.
 * @return HSM_OK, HSM_ERR_LOCKED, or HSM_ERR_NOT_AUTHORIZED; *tries_left updated.
 */
uint16_t HSM_KeyStore_Auth(const uint8_t *pin, uint16_t len, uint8_t *tries_left);

/**
 * @brief Generate a new random key, encrypt it under the KEK, persist it.
 * @return HSM_OK or an hsm_status_t error.
 */
uint16_t HSM_KeyStore_Generate(const hsm_genkey_req_t *req, hsm_obj_info_t *out);

/**
 * @brief List objects. If @p label is non-NULL (32 bytes), only matching
 *        labels are returned. Writes up to @p max records to @p out.
 * @return number of records written.
 */
uint16_t HSM_KeyStore_Find(const uint8_t *label, hsm_obj_info_t *out, uint16_t max);

/** @brief Fetch one object's metadata by id. @return HSM_OK or error. */
uint16_t HSM_KeyStore_Get(uint32_t id, hsm_obj_info_t *out);

/** @brief Delete an object by id and persist. @return HSM_OK or error. */
uint16_t HSM_KeyStore_Delete(uint32_t id);

/**
 * @brief Decrypt an object's key material into @p out (caller buffer >= 64).
 *        For internal crypto use (sign/hmac/wrap); never sent to the host.
 * @return HSM_OK or error; *out_len set to the plaintext key length.
 */
uint16_t HSM_KeyStore_LoadKey(uint32_t id, uint8_t *out, uint16_t *out_len);

/**
 * @brief Increment an object's usage counter (RAM only; not persisted per-op
 *        to avoid flash wear — durable counters need wear-levelling, future).
 */
void HSM_KeyStore_BumpUsage(uint32_t id);

/** @brief AES-256-GCM encrypt with stored key @p id (needs HSM_CAP_ENCRYPT). */
uint16_t HSM_KeyStore_Encrypt(uint32_t id, const uint8_t nonce[12],
                              const uint8_t *aad, uint16_t aad_len,
                              const uint8_t *pt, uint16_t pt_len,
                              uint8_t *ct_out, uint8_t tag_out[16]);

/** @brief AES-256-GCM decrypt+verify with stored key @p id (needs HSM_CAP_DECRYPT). */
uint16_t HSM_KeyStore_Decrypt(uint32_t id, const uint8_t nonce[12],
                              const uint8_t *aad, uint16_t aad_len,
                              const uint8_t *ct, uint16_t ct_len,
                              const uint8_t tag[16], uint8_t *pt_out);

/**
 * @brief Wrap (export) object @p target_id under wrapping key @p wrap_id
 *        (AES-256 with HSM_CAP_WRAP). Target must be exportable.
 * @return HSM_OK; writes the wrap blob to @p out_blob and its length to @p out_len.
 */
uint16_t HSM_KeyStore_Wrap(uint32_t wrap_id, uint32_t target_id,
                           uint8_t *out_blob, uint16_t *out_len);

/**
 * @brief Unwrap (import) a wrap blob under wrapping key @p wrap_id (AES-256 with
 *        HSM_CAP_UNWRAP), creating a new object with the given attributes.
 */
uint16_t HSM_KeyStore_Unwrap(uint32_t wrap_id, const uint8_t *blob, uint16_t blob_len,
                             uint16_t caps, uint8_t exportable, uint8_t auth_domain,
                             const uint8_t *label, hsm_obj_info_t *out);

#endif /* OPENHSM_HSM_KEYSTORE_H */
