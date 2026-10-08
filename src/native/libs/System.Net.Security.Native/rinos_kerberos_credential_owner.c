/* SPDX-License-Identifier: MIT */
/*
 * RinOS target-side credential owner client.
 *
 * The keyring service is the owner of the encrypted FILE ccache/keytab
 * records.  This client asks it only for a generation-bound opaque handle;
 * it never calls GET_HANDLE and never copies ticket or key bytes into the
 * runtime process.  A Kerberos provider may retain the returned owner slot
 * and must release it through this table.
 */

#include "../../../../../../public-base/RinOS-SDK/include/rin/net/kerberos_credential_owner_abi.h"
#include "../../../../../../public-base/libs/rinruntime/include/rinruntime/rin_keyring_client.h"

#include <stddef.h>
#include <stdint.h>

#define RINOS_KERBEROS_OWNER_MAGIC UINT32_C(0x314f4b52)
#define RINOS_KERBEROS_OWNER_MAX_HANDLES UINT32_C(8)
#define RINOS_KERBEROS_OWNER_INITIALIZED UINT32_C(2)

typedef struct RinOsKerberosOwnerSlot {
    uint32_t magic;
    uint32_t kind;
    RinKeyringHandleV1 handle;
} RinOsKerberosOwnerSlot;

typedef struct RinOsKerberosOwnerContext {
    uint32_t magic;
    volatile uint32_t initialized;
    volatile uint32_t lock;
    uint32_t reserved;
    RinOsKerberosOwnerSlot slots[RINOS_KERBEROS_OWNER_MAX_HANDLES];
    RinKerberosCredentialOwnerV1 abi;
} RinOsKerberosOwnerContext;

static RinOsKerberosOwnerContext g_owner;

static void owner_zero(void* pointer, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    while (size-- != 0u) *bytes++ = 0u;
}

static int owner_lock(RinOsKerberosOwnerContext* context)
{
    return __atomic_exchange_n(&context->lock, 1u, __ATOMIC_ACQUIRE) == 0u;
}

static void owner_unlock(RinOsKerberosOwnerContext* context)
{
    __atomic_store_n(&context->lock, 0u, __ATOMIC_RELEASE);
}

static int owner_valid(const RinOsKerberosOwnerContext* context)
{
    return context != NULL && context->magic == RINOS_KERBEROS_OWNER_MAGIC &&
           context->initialized == RINOS_KERBEROS_OWNER_INITIALIZED &&
           context->abi.struct_size == sizeof(context->abi) &&
           context->abi.version == RIN_KERBEROS_CREDENTIAL_OWNER_ABI_VERSION &&
           context->abi.context == (void*)context;
}

static void owner_minor(uint32_t* minor_status, uint32_t value)
{
    if (minor_status != NULL) *minor_status = value;
}

static RinOsKerberosOwnerSlot* owner_find_free(
    RinOsKerberosOwnerContext* context)
{
    uint32_t index;
    for (index = 0u; index < RINOS_KERBEROS_OWNER_MAX_HANDLES; ++index) {
        if (context->slots[index].magic == 0u) return &context->slots[index];
    }
    return NULL;
}

static uint32_t owner_keyring_result(int result)
{
    if (result == RIN_KEYRING_LOCKED) return RIN_KERBEROS_CREDENTIAL_OWNER_EXPIRED;
    if (result == RIN_KEYRING_INVALID || result == RIN_KEYRING_DENIED)
        return RIN_KERBEROS_CREDENTIAL_OWNER_INVALID_SESSION;
    return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
}

static uint32_t owner_acquire(RinOsKerberosOwnerContext* context,
                              uint32_t* minor_status, void** output,
                              const char* scope, uint32_t kind)
{
    RinOsKerberosOwnerSlot* slot;
    int result;

    owner_minor(minor_status, 0u);
    if (output != NULL) *output = NULL;
    if (output == NULL || !owner_valid(context) || !owner_lock(context))
        return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    slot = owner_find_free(context);
    if (slot == NULL) {
        owner_unlock(context);
        return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    }
    result = rin_keyring_client_acquire_handle(scope, &slot->handle);
    if (result != RIN_KEYRING_OK) {
        owner_zero(&slot->handle, sizeof(slot->handle));
        owner_unlock(context);
        return owner_keyring_result(result);
    }
    slot->kind = kind;
    slot->magic = RINOS_KERBEROS_OWNER_MAGIC;
    *output = slot;
    owner_unlock(context);
    return RIN_KERBEROS_CREDENTIAL_OWNER_OK;
}

static uint32_t owner_acquire_session_initiator(
    void* context, uint32_t* minor_status, void* desired_name, void** output)
{
    static const char scope[] = "credential.kerberos.session";
    if (desired_name != NULL) {
        owner_minor(minor_status, 0u);
        if (output != NULL) *output = NULL;
        return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    }
    return owner_acquire((RinOsKerberosOwnerContext*)context, minor_status,
                         output, scope, 1u);
}

static uint32_t owner_acquire_acceptor_keytab(
    void* context, uint32_t* minor_status, void** output)
{
    static const char scope[] = "credential.kerberos.acceptor";
    return owner_acquire((RinOsKerberosOwnerContext*)context, minor_status,
                         output, scope, 2u);
}

static uint32_t owner_release_credential(void* context, uint32_t* minor_status,
                                         void** input)
{
    RinOsKerberosOwnerContext* owner = (RinOsKerberosOwnerContext*)context;
    uint32_t index;

    owner_minor(minor_status, 0u);
    if (input == NULL) return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    if (*input == NULL) return RIN_KERBEROS_CREDENTIAL_OWNER_OK;
    if (!owner_valid(owner) || !owner_lock(owner))
        return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    for (index = 0u; index < RINOS_KERBEROS_OWNER_MAX_HANDLES; ++index) {
        RinOsKerberosOwnerSlot* slot = &owner->slots[index];
        if (*input == slot && slot->magic == RINOS_KERBEROS_OWNER_MAGIC) {
            owner_zero(slot, sizeof(*slot));
            *input = NULL;
            owner_unlock(owner);
            return RIN_KERBEROS_CREDENTIAL_OWNER_OK;
        }
    }
    owner_unlock(owner);
    return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
}

static int owner_initialize(void)
{
    uint32_t expected = 0u;
    if (__atomic_compare_exchange_n(&g_owner.initialized, &expected, 1u, 0,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        owner_zero(&g_owner, sizeof(g_owner));
        g_owner.magic = RINOS_KERBEROS_OWNER_MAGIC;
        g_owner.abi.struct_size = sizeof(g_owner.abi);
        g_owner.abi.version = RIN_KERBEROS_CREDENTIAL_OWNER_ABI_VERSION;
        g_owner.abi.capability_mask =
            RIN_KERBEROS_CREDENTIAL_OWNER_KNOWN_CAPABILITIES;
        g_owner.abi.context = &g_owner;
        g_owner.abi.acquire_session_initiator = owner_acquire_session_initiator;
        g_owner.abi.acquire_acceptor_keytab = owner_acquire_acceptor_keytab;
        g_owner.abi.release_credential = owner_release_credential;
        __atomic_store_n(&g_owner.initialized,
                         RINOS_KERBEROS_OWNER_INITIALIZED, __ATOMIC_RELEASE);
        return 1;
    }
    return __atomic_load_n(&g_owner.initialized, __ATOMIC_ACQUIRE) ==
           RINOS_KERBEROS_OWNER_INITIALIZED;
}

const RinKerberosCredentialOwnerV1* rin_kerberos_credential_owner_get_v1(void)
{
    /* Capability discovery must not manufacture a credential, but it should
     * avoid advertising a dead keyring service as a usable owner. Actual
     * ccache/keytab presence remains checked by the acquire callback. */
    if (!owner_initialize() || rin_keyring_client_status() != RIN_KEYRING_OK)
        return NULL;
    return &g_owner.abi;
}
