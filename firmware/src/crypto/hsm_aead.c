/**
 * @file    hsm_aead.c
 * @brief   AES-256-GCM via the STM32 AES peripheral (HAL CRYP).
 *
 * Uses the documented ST idiom: DataType = byte (8-bit) with all buffers as
 * natural-order byte arrays, so inputs/outputs/tag match standard test vectors
 * directly. For GCM the init vector is nonce(12) || 0x00000002.
 */
#include "hsm_aead.h"
#include "stm32u5xx_hal.h"

#include <string.h>

/* Largest single AEAD payload we process (session inner message + slack). The
 * HW reads the final partial block as a whole 32-bit word, so the input must be
 * zero-padded to a 16-byte boundary: any non-zero bytes past the real length
 * corrupt the GCM tag. We bounce through these word-aligned, zero-padded
 * buffers to guarantee that, instead of trusting the caller's tail bytes. */
#define HSM_AEAD_MAX 544u
static __attribute__((aligned(4))) uint8_t bounce_in[HSM_AEAD_MAX];
static __attribute__((aligned(4))) uint8_t bounce_out[HSM_AEAD_MAX];

static size_t pad16(size_t n) { return (n + 15u) & ~(size_t)15u; }

/* The KEYR/IVR registers are loaded as raw 32-bit words (NOT affected by the
 * DataType byte-swap, which only applies to the DINR/DOUTR data path). So key
 * and IV must be packed as big-endian words; data/AAD/tag stay byte arrays. */
static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static int gcm_init(CRYP_HandleTypeDef *hcryp, uint32_t *kw, uint32_t *iv,
                    const uint8_t key[HSM_GCM_KEY_LEN],
                    const uint8_t nonce[HSM_GCM_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len)
{
    for (unsigned i = 0; i < 8; i++) {
        kw[i] = be32(key + 4u * i);
    }
    /* GCM init vector = 96-bit nonce (big-endian words) || counter 0x00000002. */
    iv[0] = be32(nonce + 0);
    iv[1] = be32(nonce + 4);
    iv[2] = be32(nonce + 8);
    iv[3] = 0x00000002u;

    memset(hcryp, 0, sizeof(*hcryp));
    hcryp->Instance            = AES;
    hcryp->Init.DataType       = CRYP_DATATYPE_8B;
    hcryp->Init.KeySize        = CRYP_KEYSIZE_256B;
    hcryp->Init.pKey           = kw;
    hcryp->Init.pInitVect      = iv;
    hcryp->Init.Algorithm      = CRYP_AES_GCM_GMAC;
    hcryp->Init.Header         = (uint32_t *)(void *)aad;
    hcryp->Init.HeaderSize     = (uint32_t)aad_len;
    hcryp->Init.DataWidthUnit  = CRYP_DATAWIDTHUNIT_BYTE;
    hcryp->Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_BYTE;
    return (HAL_CRYP_Init(hcryp) == HAL_OK) ? 0 : -1;
}

int HSM_AesGcmEncrypt(const uint8_t key[HSM_GCM_KEY_LEN],
                      const uint8_t nonce[HSM_GCM_NONCE_LEN],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *pt, size_t pt_len,
                      uint8_t *ct_out, uint8_t tag_out[HSM_GCM_TAG_LEN])
{
    CRYP_HandleTypeDef hcryp;
    uint32_t kw[8], iv[4], tag[4];
    int rc = -1;

    if (pt_len > HSM_AEAD_MAX) {
        return -1;
    }
    /* Zero-pad the input to a 16-byte boundary so the HW's whole-word read of
     * the final partial block sees zeros, not stale bytes. */
    size_t padded = pad16(pt_len);
    memset(bounce_in, 0, padded);
    memcpy(bounce_in, pt, pt_len);

    if (gcm_init(&hcryp, kw, iv, key, nonce, aad, aad_len) != 0) {
        return -1;
    }
    if (HAL_CRYP_Encrypt(&hcryp, (uint32_t *)(void *)bounce_in, (uint16_t)pt_len,
                         (uint32_t *)(void *)bounce_out, HAL_MAX_DELAY) == HAL_OK &&
        HAL_CRYPEx_AESGCM_GenerateAuthTAG(&hcryp, tag, HAL_MAX_DELAY) == HAL_OK) {
        memcpy(ct_out, bounce_out, pt_len);
        memcpy(tag_out, tag, HSM_GCM_TAG_LEN);
        rc = 0;
    }
    HAL_CRYP_DeInit(&hcryp);
    return rc;
}

int HSM_AesGcmDecrypt(const uint8_t key[HSM_GCM_KEY_LEN],
                      const uint8_t nonce[HSM_GCM_NONCE_LEN],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      const uint8_t tag[HSM_GCM_TAG_LEN],
                      uint8_t *pt_out)
{
    CRYP_HandleTypeDef hcryp;
    uint32_t kw[8], iv[4], calc_tag[4];
    int rc = -1;

    if (ct_len > HSM_AEAD_MAX) {
        return -1;
    }
    /* Zero-pad the ciphertext to a 16-byte boundary (see encrypt). */
    size_t padded = pad16(ct_len);
    memset(bounce_in, 0, padded);
    memcpy(bounce_in, ct, ct_len);

    if (gcm_init(&hcryp, kw, iv, key, nonce, aad, aad_len) != 0) {
        return -1;
    }
    if (HAL_CRYP_Decrypt(&hcryp, (uint32_t *)(void *)bounce_in, (uint16_t)ct_len,
                         (uint32_t *)(void *)bounce_out, HAL_MAX_DELAY) == HAL_OK &&
        HAL_CRYPEx_AESGCM_GenerateAuthTAG(&hcryp, calc_tag, HAL_MAX_DELAY) == HAL_OK) {
        memcpy(pt_out, bounce_out, ct_len);
        /* Constant-time tag compare. */
        const uint8_t *ct_tag = (const uint8_t *)calc_tag;
        uint8_t diff = 0;
        for (size_t i = 0; i < HSM_GCM_TAG_LEN; i++) {
            diff |= (uint8_t)(ct_tag[i] ^ tag[i]);
        }
        rc = (diff == 0) ? 0 : -1;
    }
    HAL_CRYP_DeInit(&hcryp);
    return rc;
}
