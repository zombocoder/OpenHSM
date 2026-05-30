/**
 * @file    p11test.c
 * @brief   Minimal PKCS#11 test harness: dlopen the module and drive C_*.
 *
 * Avoids a dependency on OpenSC/pkcs11-tool during development.
 *   usage: p11test [path-to-module]   (default: ./libopenhsm_pkcs11.dylib)
 */
#define CRYPTOKI_COMPAT 1
#include "pkcs11.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static void print_padded(const char *label, const CK_UTF8CHAR *p, size_t n)
{
    int end = (int)n;
    while (end > 0 && p[end - 1] == ' ') end--;
    printf("%s\"%.*s\"\n", label, end, (const char *)p);
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "./libopenhsm_pkcs11.dylib";

    void *lib = dlopen(path, RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }

    CK_RV (*get_list)(CK_FUNCTION_LIST_PTR_PTR) = dlsym(lib, "C_GetFunctionList");
    if (!get_list) { fprintf(stderr, "no C_GetFunctionList\n"); return 1; }

    CK_FUNCTION_LIST_PTR fl = NULL;
    if (get_list(&fl) != CKR_OK || !fl) { fprintf(stderr, "C_GetFunctionList failed\n"); return 1; }

    CK_RV rv = fl->C_Initialize(NULL);
    if (rv != CKR_OK) { fprintf(stderr, "C_Initialize: 0x%lx\n", (unsigned long)rv); return 1; }
    printf("C_Initialize     OK\n");

    CK_INFO info;
    if (fl->C_GetInfo(&info) == CKR_OK) {
        print_padded("C_GetInfo        manufacturer=", info.manufacturerID, sizeof(info.manufacturerID));
        printf("                 cryptoki=%u.%u\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    }

    CK_SLOT_ID slots[4]; CK_ULONG nslots = 4;
    rv = fl->C_GetSlotList(CK_TRUE, slots, &nslots);
    printf("C_GetSlotList    rv=0x%lx slots=%lu\n", (unsigned long)rv, (unsigned long)nslots);

    for (CK_ULONG i = 0; i < nslots; i++) {
        CK_SLOT_INFO si;
        if (fl->C_GetSlotInfo(slots[i], &si) == CKR_OK) {
            print_padded("  slot desc      ", si.slotDescription, sizeof(si.slotDescription));
            printf("                 token_present=%s\n",
                   (si.flags & CKF_TOKEN_PRESENT) ? "yes" : "no");
        }
        CK_TOKEN_INFO ti;
        if (fl->C_GetTokenInfo(slots[i], &ti) == CKR_OK) {
            print_padded("  token label    ", ti.label, sizeof(ti.label));
            print_padded("  token model    ", ti.model, sizeof(ti.model));
            print_padded("  token serial   ", ti.serialNumber, sizeof(ti.serialNumber));
            printf("                 fw=%u.%u flags=0x%lx\n",
                   ti.firmwareVersion.major, ti.firmwareVersion.minor,
                   (unsigned long)ti.flags);
        }
    }

    CK_MECHANISM_TYPE mechs[16]; CK_ULONG nmech = 16;
    if (fl->C_GetMechanismList(slots[0], mechs, &nmech) == CKR_OK) {
        printf("C_GetMechanismList %lu mechanisms:", (unsigned long)nmech);
        for (CK_ULONG i = 0; i < nmech; i++) printf(" 0x%lx", (unsigned long)mechs[i]);
        printf("\n");
    }

    /* ---- Session + login + object enumeration ---- */
    CK_SESSION_HANDLE sess;
    rv = fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                           NULL, NULL, &sess);
    printf("C_OpenSession    rv=0x%lx handle=%lu\n", (unsigned long)rv, (unsigned long)sess);

    rv = fl->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"123456", 6);
    printf("C_Login          rv=0x%lx\n", (unsigned long)rv);

    rv = fl->C_FindObjectsInit(sess, NULL, 0);   /* match everything */
    printf("C_FindObjectsInit rv=0x%lx\n", (unsigned long)rv);

    CK_OBJECT_HANDLE objs[16]; CK_ULONG nobj = 0;
    rv = fl->C_FindObjects(sess, objs, 16, &nobj);
    printf("C_FindObjects    rv=0x%lx found=%lu\n", (unsigned long)rv, (unsigned long)nobj);

    for (CK_ULONG i = 0; i < nobj; i++) {
        CK_OBJECT_CLASS cls = 0; CK_KEY_TYPE kt = 0; CK_ULONG idv = 0;
        char label[33] = {0};
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,    &cls,   sizeof(cls) },
            { CKA_KEY_TYPE, &kt,    sizeof(kt)  },
            { CKA_ID,       &idv,   sizeof(idv) },
            { CKA_LABEL,    label,  sizeof(label) - 1 },
        };
        fl->C_GetAttributeValue(sess, objs[i], tmpl, 4);
        printf("  obj handle=%lu  class=%lu keytype=0x%lx id=%lu label=\"%s\"\n",
               (unsigned long)objs[i], (unsigned long)cls,
               (unsigned long)kt, (unsigned long)idv, label);
    }
    fl->C_FindObjectsFinal(sess);

    /* Find by label (as Vault would for its seal key). */
    CK_OBJECT_CLASS want_cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE bylabel[] = {
        { CKA_CLASS, &want_cls, sizeof(want_cls) },
        { CKA_LABEL, (void *)"openhsm-test-key", 16 },
    };
    fl->C_FindObjectsInit(sess, bylabel, 2);
    nobj = 0;
    fl->C_FindObjects(sess, objs, 16, &nobj);
    fl->C_FindObjectsFinal(sess);
    printf("Find by label \"openhsm-test-key\": %lu match%s\n",
           (unsigned long)nobj, nobj == 1 ? "" : "es");

    /* ---- Phase C: crypto ---- */

    /* C_GenerateRandom */
    unsigned char rnd[16] = {0};
    if (fl->C_GenerateRandom(sess, rnd, sizeof(rnd)) == CKR_OK) {
        printf("C_GenerateRandom 16 bytes: ");
        for (int i = 0; i < 16; i++) printf("%02x", rnd[i]);
        printf("\n");
    }

    /* helper: find first object with a given label */
    CK_OBJECT_HANDLE aes_key = 0, hmac_key = 0;
    {
        struct { const char *label; CK_OBJECT_HANDLE *out; } want[] = {
            { "openhsm-aead-key", &aes_key }, { "openhsm-mac-key", &hmac_key },
        };
        for (int w = 0; w < 2; w++) {
            CK_ATTRIBUTE t[] = { { CKA_LABEL, (void *)want[w].label, strlen(want[w].label) } };
            CK_OBJECT_HANDLE oh[4]; CK_ULONG n = 0;
            fl->C_FindObjectsInit(sess, t, 1);
            fl->C_FindObjects(sess, oh, 4, &n);
            fl->C_FindObjectsFinal(sess);
            if (n >= 1) *want[w].out = oh[0];
        }
    }

    /* AES-GCM encrypt/decrypt round-trip (Vault's seal primitive) */
    if (aes_key) {
        unsigned char iv[12]; for (int i = 0; i < 12; i++) iv[i] = (unsigned char)(0x20 + i);
        unsigned char aad[4] = { 1, 2, 3, 4 };
        CK_GCM_PARAMS gp = { iv, sizeof(iv), sizeof(iv) * 8, aad, sizeof(aad), 128 };
        CK_MECHANISM m = { CKM_AES_GCM, &gp, sizeof(gp) };
        const char *pt = "vault master key";
        unsigned char ct[64]; CK_ULONG ctlen = sizeof(ct);
        unsigned char back[64]; CK_ULONG backlen = sizeof(back);

        CK_RV e = fl->C_EncryptInit(sess, &m, aes_key);
        if (e == CKR_OK) e = fl->C_Encrypt(sess, (CK_BYTE_PTR)pt, strlen(pt), ct, &ctlen);
        CK_RV d = fl->C_DecryptInit(sess, &m, aes_key);
        if (d == CKR_OK) d = fl->C_Decrypt(sess, ct, ctlen, back, &backlen);
        int ok = (e == CKR_OK && d == CKR_OK && backlen == strlen(pt) &&
                  memcmp(back, pt, backlen) == 0);
        printf("AES-GCM enc(%lu)->ct(%lu)->dec(%lu) roundtrip [%s]\n",
               (unsigned long)strlen(pt), (unsigned long)ctlen,
               (unsigned long)backlen, ok ? "OK" : "FAIL");
    } else printf("AES-GCM: no aes key (run openhsm-ping first)\n");

    /* HMAC-SHA256 sign (Vault's seal HMAC) */
    if (hmac_key) {
        CK_MECHANISM m = { CKM_SHA256_HMAC, NULL, 0 };
        const char *msg = "integrity";
        unsigned char mac[32]; CK_ULONG maclen = sizeof(mac);
        CK_RV rv2 = fl->C_SignInit(sess, &m, hmac_key);
        if (rv2 == CKR_OK) rv2 = fl->C_Sign(sess, (CK_BYTE_PTR)msg, strlen(msg), mac, &maclen);
        printf("HMAC-SHA256 sign rv=0x%lx len=%lu mac=", (unsigned long)rv2, (unsigned long)maclen);
        for (int i = 0; i < 8 && i < (int)maclen; i++) printf("%02x", mac[i]);
        printf(".. [%s]\n", (rv2 == CKR_OK && maclen == 32) ? "OK" : "FAIL");
    } else printf("HMAC: no hmac key (run openhsm-ping first)\n");

    fl->C_Logout(sess);
    fl->C_CloseSession(sess);

    fl->C_Finalize(NULL);
    printf("C_Finalize       OK\n");
    dlclose(lib);
    return 0;
}
