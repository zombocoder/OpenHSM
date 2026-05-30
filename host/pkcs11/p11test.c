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

    fl->C_Finalize(NULL);
    printf("C_Finalize       OK\n");
    dlclose(lib);
    return 0;
}
