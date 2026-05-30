/**
 * @file    p11provision.c
 * @brief   Provision OpenBao's seal + HMAC keys via the PKCS#11 module.
 *
 * OpenBao's (discontinued) builtin PKCS#11 seal does not auto-generate keys on
 * init even with generate_key=true; it expects them to pre-exist. This one-shot
 * tool creates them with the labels the seal config references.
 *
 *   usage: p11provision <module> [pin] [seal_label] [hmac_label]
 */
#define CRYPTOKI_COMPAT 1
#include "pkcs11.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *path  = argc > 1 ? argv[1] : "./libopenhsm_pkcs11.dylib";
    const char *pin   = argc > 2 ? argv[2] : "123456";
    const char *slbl  = argc > 3 ? argv[3] : "openbao-seal";
    const char *hlbl  = argc > 4 ? argv[4] : "openbao-hmac";

    void *lib = dlopen(path, RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    CK_RV (*get_list)(CK_FUNCTION_LIST_PTR_PTR) = dlsym(lib, "C_GetFunctionList");
    CK_FUNCTION_LIST_PTR fl = NULL;
    if (!get_list || get_list(&fl) != CKR_OK) { fprintf(stderr, "no function list\n"); return 1; }

    if (fl->C_Initialize(NULL) != CKR_OK) { fprintf(stderr, "C_Initialize failed\n"); return 1; }
    CK_SESSION_HANDLE s;
    if (fl->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &s) != CKR_OK) {
        fprintf(stderr, "C_OpenSession failed\n"); return 1; }
    CK_RV rv = fl->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));
    if (rv != CKR_OK) { fprintf(stderr, "C_Login rv=0x%lx\n", (unsigned long)rv); return 1; }

    CK_BBOOL yes = CK_TRUE;
    CK_ULONG len = 32;

    /* AES-256 seal key: ENCRYPT|DECRYPT */
    {
        CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL, 0 };
        CK_ATTRIBUTE t[] = {
            { CKA_LABEL, (void *)slbl, strlen(slbl) },
            { CKA_TOKEN, &yes, sizeof(yes) },
            { CKA_ENCRYPT, &yes, sizeof(yes) },
            { CKA_DECRYPT, &yes, sizeof(yes) },
            { CKA_VALUE_LEN, &len, sizeof(len) },
        };
        CK_OBJECT_HANDLE h;
        rv = fl->C_GenerateKey(s, &m, t, 5, &h);
        printf("seal  key \"%s\": rv=0x%lx handle=%lu\n", slbl, (unsigned long)rv, (unsigned long)h);
        if (rv != CKR_OK) return 1;
    }
    /* Generic-secret HMAC key: SIGN|VERIFY */
    {
        CK_MECHANISM m = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
        CK_ATTRIBUTE t[] = {
            { CKA_LABEL, (void *)hlbl, strlen(hlbl) },
            { CKA_TOKEN, &yes, sizeof(yes) },
            { CKA_SIGN, &yes, sizeof(yes) },
            { CKA_VERIFY, &yes, sizeof(yes) },
            { CKA_VALUE_LEN, &len, sizeof(len) },
        };
        CK_OBJECT_HANDLE h;
        rv = fl->C_GenerateKey(s, &m, t, 5, &h);
        printf("hmac  key \"%s\": rv=0x%lx handle=%lu\n", hlbl, (unsigned long)rv, (unsigned long)h);
        if (rv != CKR_OK) return 1;
    }

    fl->C_Logout(s);
    fl->C_CloseSession(s);
    fl->C_Finalize(NULL);
    dlclose(lib);
    printf("provisioned OK\n");
    return 0;
}
