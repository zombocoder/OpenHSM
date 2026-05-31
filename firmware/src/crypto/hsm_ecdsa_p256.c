/**
 * @file    hsm_ecdsa_p256.c
 * @brief   NIST P-256 ECDSA on the STM32U5 PKA peripheral.
 */
#include "hsm_ecdsa_p256.h"
#include "hsm_rng.h"
#include "stm32u5xx_hal.h"

#include <string.h>

/* secp256r1 domain parameters, 32-byte big-endian. a is given as the reduced
 * positive residue p-3 with coefSign = 0 (a in [0,p)). */
static const uint8_t P256_P[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff };
static const uint8_t P256_A[32] = {  /* p - 3 */
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc };
static const uint8_t P256_B[32] = {
    0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
    0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b };
static const uint8_t P256_N[32] = {  /* group order */
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51 };
static const uint8_t P256_GX[32] = {
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96 };
static const uint8_t P256_GY[32] = {
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5 };

static PKA_HandleTypeDef hpka;
static int pka_ready;

static int pka_init(void)
{
    if (pka_ready) return 0;
    __HAL_RCC_PKA_CLK_ENABLE();
    hpka.Instance = PKA;
    if (HAL_PKA_Init(&hpka) != HAL_OK) return -1;
    pka_ready = 1;
    return 0;
}

/* big-endian compare: <0 if a<b, 0 if equal, >0 if a>b */
static int be_cmp(const uint8_t *a, const uint8_t *b, int n)
{
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i]) return (a[i] < b[i]) ? -1 : 1;
    }
    return 0;
}
static int be_is_zero(const uint8_t *a, int n)
{
    uint8_t x = 0;
    for (int i = 0; i < n; i++) x |= a[i];
    return x == 0;
}

int HSM_EcdsaP256_Public(const uint8_t priv[32], uint8_t pub[64])
{
    if (pka_init() != 0) return -1;
    PKA_ECCMulInTypeDef in = {0};
    in.scalarMulSize = 32; in.modulusSize = 32; in.coefSign = 0;
    in.coefA = P256_A; in.coefB = P256_B; in.modulus = P256_P;
    in.pointX = P256_GX; in.pointY = P256_GY; in.scalarMul = priv; in.primeOrder = P256_N;
    if (HAL_PKA_ECCMul(&hpka, &in, HAL_MAX_DELAY) != HAL_OK) return -1;
    PKA_ECCMulOutTypeDef out = { .ptX = pub, .ptY = pub + 32 };
    HAL_PKA_ECCMul_GetResult(&hpka, &out);
    return 0;
}

int HSM_EcdsaP256_Sign(const uint8_t priv[32], const uint8_t digest[32], uint8_t sig[64])
{
    if (pka_init() != 0) return -1;
    uint8_t k[32];
    int rc = -1;
    for (int tries = 0; tries < 32; tries++) {
        if (HSM_Rng_Fill(k, sizeof(k)) != 0) break;
        if (be_is_zero(k, 32) || be_cmp(k, P256_N, 32) >= 0) continue;  /* need 0 < k < n */

        PKA_ECDSASignInTypeDef in = {0};
        in.primeOrderSize = 32; in.modulusSize = 32; in.coefSign = 0;
        in.coef = P256_A; in.coefB = P256_B; in.modulus = P256_P;
        in.integer = k; in.basePointX = P256_GX; in.basePointY = P256_GY;
        in.hash = digest; in.privateKey = priv; in.primeOrder = P256_N;
        if (HAL_PKA_ECDSASign(&hpka, &in, HAL_MAX_DELAY) != HAL_OK) break;

        PKA_ECDSASignOutTypeDef out = { .RSign = sig, .SSign = sig + 32 };
        HAL_PKA_ECDSASign_GetResult(&hpka, &out, NULL);
        if (be_is_zero(sig, 32) || be_is_zero(sig + 32, 32)) continue;  /* r,s != 0 */
        rc = 0;
        break;
    }
    memset(k, 0, sizeof(k));
    return rc;
}

int HSM_EcdsaP256_Verify(const uint8_t pub[64], const uint8_t digest[32], const uint8_t sig[64])
{
    if (pka_init() != 0) return -1;
    PKA_ECDSAVerifInTypeDef in = {0};
    in.primeOrderSize = 32; in.modulusSize = 32; in.coefSign = 0;
    in.coef = P256_A; in.modulus = P256_P;
    in.basePointX = P256_GX; in.basePointY = P256_GY;
    in.pPubKeyCurvePtX = pub; in.pPubKeyCurvePtY = pub + 32;
    in.RSign = sig; in.SSign = sig + 32; in.hash = digest; in.primeOrder = P256_N;
    if (HAL_PKA_ECDSAVerif(&hpka, &in, HAL_MAX_DELAY) != HAL_OK) return -1;
    return HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) ? 0 : -1;
}
