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
#include "../../../../../../public-base/RinOS-SDK/include/rin/net/kerberos_operation_owner_abi.h"
#include "../../../../../../public-base/libs/rinruntime/include/rinruntime/rin_keyring_client.h"

#include <stddef.h>
#include <stdint.h>

#define RINOS_KERBEROS_OWNER_MAGIC UINT32_C(0x314f4b52)
#define RINOS_KERBEROS_OWNER_MAX_HANDLES UINT32_C(8)
#define RINOS_KERBEROS_OWNER_INITIALIZED UINT32_C(2)
#define RINOS_KERBEROS_OWNER_SLOT_BITS UINT32_C(3)
#define RINOS_KERBEROS_OWNER_SLOT_MASK \
    ((uintptr_t)((UINT32_C(1) << RINOS_KERBEROS_OWNER_SLOT_BITS) - 1u))

typedef struct RinOsKerberosOwnerSlot {
    uint32_t magic;
    uint32_t kind;
    uint32_t generation;
    uint32_t reserved;
    RinKeyringHandleV1 handle;
} RinOsKerberosOwnerSlot;

typedef struct RinOsKerberosOwnerContext {
    uint32_t magic;
    volatile uint32_t initialized;
    volatile uint32_t lock;
    uint32_t reserved;
    RinOsKerberosOwnerSlot slots[RINOS_KERBEROS_OWNER_MAX_HANDLES];
    RinKerberosCredentialOwnerV1 abi;
    RinKerberosOperationOwnerV1 operation_abi;
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
           context->abi.context == (void*)context &&
           context->operation_abi.struct_size ==
               sizeof(context->operation_abi) &&
           context->operation_abi.version ==
               RIN_KERBEROS_OPERATION_OWNER_ABI_VERSION &&
           context->operation_abi.context == (void*)context;
}

static void owner_minor(uint32_t* minor_status, uint32_t value)
{
    if (minor_status != NULL) *minor_status = value;
}

static void* owner_make_token(uint32_t index, uint32_t generation)
{
    const uintptr_t value =
        ((uintptr_t)generation << RINOS_KERBEROS_OWNER_SLOT_BITS) |
        (uintptr_t)(index + 1u);
    return (void*)value;
}

static int owner_decode_token(void* input, uint32_t* index,
                              uint32_t* generation)
{
    const uintptr_t value = (uintptr_t)input;
    const uintptr_t slot = value & RINOS_KERBEROS_OWNER_SLOT_MASK;
    const uintptr_t serial = value >> RINOS_KERBEROS_OWNER_SLOT_BITS;
    if (value == 0u || slot == 0u ||
        slot > RINOS_KERBEROS_OWNER_MAX_HANDLES || serial == 0u ||
        serial > UINT32_MAX || index == NULL || generation == NULL)
        return 0;
    *index = (uint32_t)(slot - 1u);
    *generation = (uint32_t)serial;
    return 1;
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
    uint32_t index;
    uint32_t generation;
    const uintptr_t max_generation = UINTPTR_MAX >> RINOS_KERBEROS_OWNER_SLOT_BITS;
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
    index = (uint32_t)(slot - context->slots);
    if (slot->generation >= UINT32_MAX ||
        (uintptr_t)(slot->generation + 1u) > max_generation) {
        owner_unlock(context);
        return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    }
    generation = slot->generation + 1u;
    result = rin_keyring_client_acquire_handle(scope, &slot->handle);
    if (result != RIN_KEYRING_OK) {
        owner_zero(&slot->handle, sizeof(slot->handle));
        slot->generation = generation;
        owner_unlock(context);
        return owner_keyring_result(result);
    }
    slot->generation = generation;
    slot->kind = kind;
    slot->magic = RINOS_KERBEROS_OWNER_MAGIC;
    /* This is a non-dereferenceable owner token.  Only this table may decode
     * it, which lets release reject a stale token after slot reuse. */
    *output = owner_make_token(index, generation);
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

static uint32_t owner_get_session_principal(
    void* context, uint32_t* minor_status, void* credential, uint8_t* output,
    uint32_t output_capacity, uint32_t* output_size, uint64_t* generation)
{
    RinOsKerberosOwnerContext* owner = (RinOsKerberosOwnerContext*)context;
    RinOsKerberosOwnerSlot* slot;
    uint32_t index;
    uint32_t token_generation;
    int result;

    owner_minor(minor_status, 0u);
    if (output_size != NULL) *output_size = 0u;
    if (generation != NULL) *generation = 0u;
    if (output == NULL || output_capacity == 0u ||
        output_capacity > RIN_KEYRING_MAX_SECRET_SIZE ||
        output_size == NULL ||
        generation == NULL || credential == NULL ||
        !owner_decode_token(credential, &index, &token_generation) ||
        !owner_valid(owner) || !owner_lock(owner))
        return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    owner_zero(output, output_capacity);
    slot = &owner->slots[index];
    if (slot->magic != RINOS_KERBEROS_OWNER_MAGIC || slot->kind != 1u ||
        slot->generation != token_generation) {
        owner_unlock(owner);
        return RIN_KERBEROS_CREDENTIAL_OWNER_INVALID_SESSION;
    }
    result = rin_keyring_client_kerberos_principal(
        &slot->handle, output, output_capacity, output_size, generation);
    if (result == RIN_KEYRING_OK && *generation != slot->handle.generation) {
        owner_zero(output, output_capacity);
        *output_size = 0u;
        *generation = 0u;
        result = RIN_KEYRING_CONFLICT;
    }
    owner_unlock(owner);
    if (result == RIN_KEYRING_OK)
        return RIN_KERBEROS_CREDENTIAL_OWNER_OK;
    owner_zero(output, output_capacity);
    *output_size = 0u;
    *generation = 0u;
    return owner_keyring_result(result);
}

static uint32_t owner_release_credential(void* context, uint32_t* minor_status,
                                         void** input)
{
    RinOsKerberosOwnerContext* owner = (RinOsKerberosOwnerContext*)context;
    uint32_t index;
    uint32_t generation;

    owner_minor(minor_status, 0u);
    if (input == NULL) return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    if (*input == NULL) return RIN_KERBEROS_CREDENTIAL_OWNER_OK;
    if (!owner_decode_token(*input, &index, &generation) ||
        !owner_valid(owner) || !owner_lock(owner))
        return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    {
        RinOsKerberosOwnerSlot* slot = &owner->slots[index];
        if (slot->magic == RINOS_KERBEROS_OWNER_MAGIC &&
            slot->generation == generation) {
            const int result = rin_keyring_client_remove_handle(&slot->handle);
            if (result != RIN_KEYRING_OK) {
                owner_unlock(owner);
                return owner_keyring_result(result);
            }
            const uint32_t preserved_generation = slot->generation;
            owner_zero(slot, sizeof(*slot));
            slot->generation = preserved_generation;
            *input = NULL;
            owner_unlock(owner);
            return RIN_KERBEROS_CREDENTIAL_OWNER_OK;
        }
    }
    owner_unlock(owner);
    return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
}

static uint32_t owner_operation(
    void* context, uint32_t* minor_status, void* credential,
    const RinKerberosOperationRequestV1* request,
    const uint8_t* context_token, uint32_t context_token_size,
    const uint8_t* input, uint32_t input_size, uint8_t* output,
    uint32_t output_capacity, uint32_t* output_size,
    uint8_t* next_context_token, uint32_t next_context_capacity,
    uint32_t* next_context_token_size, uint64_t* generation,
    uint32_t* provider_result, uint32_t* return_flags)
{
    RinOsKerberosOwnerContext* owner = (RinOsKerberosOwnerContext*)context;
    RinOsKerberosOwnerSlot* slot;
    uint32_t index;
    uint32_t token_generation;
    int result;

    owner_minor(minor_status, 0u);
    if (output_size != NULL) *output_size = 0u;
    if (next_context_token_size != NULL) *next_context_token_size = 0u;
    if (generation != NULL) *generation = 0u;
    if (provider_result != NULL) *provider_result = 0u;
    if (return_flags != NULL) *return_flags = 0u;
    if (output != NULL && output_capacity != 0u)
        owner_zero(output, output_capacity);
    if (next_context_token != NULL && next_context_capacity != 0u)
        owner_zero(next_context_token, next_context_capacity);
    if (credential == NULL || request == NULL || output_size == NULL ||
        next_context_token_size == NULL || generation == NULL ||
        provider_result == NULL || return_flags == NULL ||
        request->struct_size != sizeof(*request) ||
        request->version != RIN_KERBEROS_OPERATION_ABI_VERSION ||
        !owner_decode_token(credential, &index, &token_generation) ||
        !owner_valid(owner) || !owner_lock(owner))
        return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    slot = &owner->slots[index];
    if (slot->magic != RINOS_KERBEROS_OWNER_MAGIC ||
        slot->generation != token_generation ||
        slot->kind != request->credential_kind) {
        owner_unlock(owner);
        return RIN_KERBEROS_CREDENTIAL_OWNER_INVALID_SESSION;
    }
    result = rin_keyring_client_kerberos_operation(
        &slot->handle, request, context_token, context_token_size, input,
        input_size, output, output_capacity, output_size, next_context_token,
        next_context_capacity, next_context_token_size, generation,
        provider_result, return_flags);
    /* A successful IPC response must still belong to the exact generation
     * acquired for this slot.  DELETE_SEC_CONTEXT is a destruction
     * acknowledgement and deliberately returns generation zero; every other
     * operation publishes a generation-bound context/output response. */
    if (result == RIN_KEYRING_OK &&
        request->operation != RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT &&
        *generation != slot->handle.generation) {
        if (output != NULL && output_capacity != 0u)
            owner_zero(output, output_capacity);
        if (next_context_token != NULL && next_context_capacity != 0u)
            owner_zero(next_context_token, next_context_capacity);
        *output_size = 0u;
        *next_context_token_size = 0u;
        *generation = 0u;
        *provider_result = 0u;
        *return_flags = 0u;
        result = RIN_KEYRING_CONFLICT;
    }
    owner_unlock(owner);
    if (result == RIN_KEYRING_OK)
        return RIN_KERBEROS_CREDENTIAL_OWNER_OK;
    return owner_keyring_result(result);
}

static int owner_initialize(void)
{
    uint32_t expected = 0u;
    if (__atomic_compare_exchange_n(&g_owner.initialized, &expected, 1u, 0,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        /* g_owner has static storage and is zero-initialized by the loader.
         * Do not scrub the whole context after publishing 1: that would
         * restore initialized=0 and let another thread enter this one-time
         * initializer concurrently.  Slot scrubbing remains explicit in the
         * acquire/release paths. */
        g_owner.magic = RINOS_KERBEROS_OWNER_MAGIC;
        g_owner.abi.struct_size = sizeof(g_owner.abi);
        g_owner.abi.version = RIN_KERBEROS_CREDENTIAL_OWNER_ABI_VERSION;
        g_owner.abi.capability_mask =
            RIN_KERBEROS_CREDENTIAL_OWNER_KNOWN_CAPABILITIES;
        g_owner.abi.context = &g_owner;
        g_owner.abi.acquire_session_initiator = owner_acquire_session_initiator;
        g_owner.abi.acquire_acceptor_keytab = owner_acquire_acceptor_keytab;
        g_owner.abi.release_credential = owner_release_credential;
        g_owner.abi.get_session_principal = owner_get_session_principal;
        g_owner.operation_abi.struct_size = sizeof(g_owner.operation_abi);
        g_owner.operation_abi.version =
            RIN_KERBEROS_OPERATION_OWNER_ABI_VERSION;
        g_owner.operation_abi.context = &g_owner;
        g_owner.operation_abi.operation = owner_operation;
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

const RinKerberosOperationOwnerV1*
rin_kerberos_operation_owner_get_v1(void)
{
    if (!owner_initialize() || rin_keyring_client_status() != RIN_KEYRING_OK)
        return NULL;
    return &g_owner.operation_abi;
}
