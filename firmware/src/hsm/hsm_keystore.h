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

#endif /* OPENHSM_HSM_KEYSTORE_H */
