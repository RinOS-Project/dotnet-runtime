// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS Kerberos transport provider.
 *
 * This file is intentionally a transport boundary, not a replacement for
 * RFC 4120/4121.  The authenticated keyring owner receives the only access to
 * raw ccache/keytab bytes.  This provider sends bounded GSS inputs to the owner,
 * carries back opaque context/output tokens, and refuses to manufacture a
 * credential or a successful token when the service-side RFC implementation
 * is absent. The linked service path now covers initiator AP-REQ/AP-REP and
 * bounded RFC 4121 per-message operations.  SPNEGO mechListMIC is verified
 * and generated through the same established-context GSS VerifyMIC/GetMIC
 * owner operations. RFC 4178 request-mic is honored only when the selected
 * mechanism reports per-message integrity through the owner ABI; the provider
 * never invents a MIC or upgrades a context without that capability.
 */

#include "pal_gssapi.h"
#include "../../../../../../public-base/RinOS-SDK/include/rin/net/auth_provider_abi.h"
#include "../../../../../../public-base/RinOS-SDK/include/rin/net/kerberos_credential_owner_abi.h"
#include "../../../../../../public-base/RinOS-SDK/include/rin/net/kerberos_operation_owner_abi.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RINOS_KERBEROS_NAME_MAGIC UINT32_C(0x314e4b52)
#define RINOS_KERBEROS_CREDENTIAL_MAGIC UINT32_C(0x31434b52)
#define RINOS_KERBEROS_CONTEXT_MAGIC UINT32_C(0x31584252)
#define RINOS_KERBEROS_MAX_PRINCIPAL_SIZE UINT32_C(4096)
#define RINOS_KERBEROS_GSS_FLAG_SEALED UINT8_C(0x02)
#define RINOS_KERBEROS_CONTEXT_NEGOTIATING UINT32_C(1)
#define RINOS_KERBEROS_CONTEXT_ESTABLISHED UINT32_C(2)
#define RINOS_KERBEROS_MAX_MECH_LIST_SIZE UINT32_C(4096)
#if defined(RINOS_KERBEROS_OWNER_LINKED)
extern const RinKerberosCredentialOwnerV1*
rin_kerberos_credential_owner_get_v1(void);
extern const RinKerberosOperationOwnerV1*
rin_kerberos_operation_owner_get_v1(void);
#else
#if defined(__GNUC__) || defined(__clang__)
#define RINOS_KERBEROS_WEAK __attribute__((weak))
#else
#define RINOS_KERBEROS_WEAK
#endif
extern const RinKerberosCredentialOwnerV1*
rin_kerberos_credential_owner_get_v1(void) RINOS_KERBEROS_WEAK;
extern const RinKerberosOperationOwnerV1*
rin_kerberos_operation_owner_get_v1(void) RINOS_KERBEROS_WEAK;
#endif

#if defined(RINOS_KERBEROS_RFC_PROVIDER_LINKED)
typedef struct RinOsKerberosProviderName {
    uint32_t magic;
    uint32_t size;
    uint8_t bytes[RIN_KERBEROS_PROVIDER_MAX_TARGET_NAME_SIZE];
    struct RinOsKerberosProviderName* next;
} RinOsKerberosProviderName;

typedef struct RinOsKerberosProviderCredential {
    uint32_t magic;
    uint32_t kind;
    void* owner_credential;
    /* A refresh can obtain a replacement handle and then fail to release it
     * after the old handle has expired.  Keep that owner object reachable so
     * the next provider release can retry cleanup instead of leaking an
     * opaque session capability.  It is never used for Kerberos operations. */
    void* pending_release_credential;
    const RinKerberosCredentialOwnerV1* owner;
    uint32_t active_contexts;
} RinOsKerberosProviderCredential;

typedef struct RinOsKerberosProviderContext {
    uint32_t magic;
    uint32_t kind;
    uint64_t generation;
    uint32_t token_size;
    uint32_t state;
    uint32_t spnego;
    uint32_t spnego_response_seen;
    uint32_t spnego_mic_required;
    uint32_t spnego_mic_sent;
    void* owner_credential;
    const RinKerberosOperationOwnerV1* owner;
    struct RinOsKerberosProviderCredential* credential;
    uint32_t credential_ref_held;
    uint32_t mech_list_size;
    uint8_t mech_list[RINOS_KERBEROS_MAX_MECH_LIST_SIZE];
    uint8_t token[RIN_KERBEROS_OPERATION_MAX_CONTEXT_TOKEN_SIZE];
} RinOsKerberosProviderContext;

static uint32_t provider_verify_mic(
    void* context, uint32_t* minor_status, void* security_context,
    uint8_t* input, int32_t input_length, uint8_t* token, int32_t token_length);
static uint32_t provider_verify_mic_bytes(
    void* context, uint32_t* minor_status, void* security_context,
    const uint8_t* input, int32_t input_length, const uint8_t* token,
    int32_t token_length);
static uint32_t provider_get_mic(
    void* context, uint32_t* minor_status, void* security_context,
    uint8_t* input, int32_t input_length, RinAuthProviderBufferV1* output);

static void provider_zero(void* pointer, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    while (size-- != 0u) *bytes++ = 0u;
}

/* GSS release receives the public buffer length from managed/native code.
 * That length is metadata, not an allocation authority.  A provider-owned
 * header is not sufficient for this boundary: a hostile or stale pointer
 * could make a header-at-buffer-minus-one read fault before its magic is
 * checked.  Keep exact live allocations in a process-local ownership list so
 * invalid and repeated releases are harmless no-ops. */
typedef struct RinOsKerberosProviderBuffer {
    struct RinOsKerberosProviderBuffer* next;
    size_t capacity;
    uint8_t data[];
} RinOsKerberosProviderBuffer;

static volatile unsigned int g_provider_buffer_lock;
static RinOsKerberosProviderBuffer* g_provider_buffers;

/* Names are provider-owned opaque handles too.  Do not inspect a caller-
 * supplied pointer before establishing that it is one of our live
 * allocations: a stale or foreign GSS name must fail closed without turning
 * release/validation into an arbitrary memory read. */
static volatile unsigned int g_provider_name_lock;
static RinOsKerberosProviderName* g_provider_names;

static void provider_name_lock(void)
{
    while (__atomic_exchange_n(
               &g_provider_name_lock, 1u, __ATOMIC_ACQUIRE) != 0u) {
    }
}

static void provider_name_unlock(void)
{
    __atomic_store_n(&g_provider_name_lock, 0u, __ATOMIC_RELEASE);
}

static void provider_name_register(RinOsKerberosProviderName* name)
{
    provider_name_lock();
    name->next = g_provider_names;
    g_provider_names = name;
    provider_name_unlock();
}

static int provider_name_snapshot(
    const void* pointer, uint8_t* bytes, uint32_t* size_out)
{
    RinOsKerberosProviderName* current;
    uint32_t size;
    if (pointer == NULL || size_out == NULL) return 0;
    provider_name_lock();
    current = g_provider_names;
    while (current != NULL && current != pointer)
        current = current->next;
    if (current == NULL || current->magic != RINOS_KERBEROS_NAME_MAGIC ||
        current->size == 0u ||
        current->size > RIN_KERBEROS_PROVIDER_MAX_TARGET_NAME_SIZE) {
        provider_name_unlock();
        return 0;
    }
    size = current->size;
    if (bytes != NULL) memcpy(bytes, current->bytes, size);
    provider_name_unlock();
    *size_out = size;
    return 1;
}

/* Remove a name and return its owner only after unlinking it while holding
 * the registry lock.  Callers may then scrub/free it without exposing a
 * pointer that another provider operation can still discover. */
static RinOsKerberosProviderName* provider_name_take(const void* pointer)
{
    RinOsKerberosProviderName* previous = NULL;
    RinOsKerberosProviderName* current;
    if (pointer == NULL) return NULL;
    provider_name_lock();
    current = g_provider_names;
    while (current != NULL && current != pointer) {
        previous = current;
        current = current->next;
    }
    if (current == NULL || current->magic != RINOS_KERBEROS_NAME_MAGIC ||
        current->size == 0u ||
        current->size > RIN_KERBEROS_PROVIDER_MAX_TARGET_NAME_SIZE) {
        provider_name_unlock();
        return NULL;
    }
    if (previous == NULL)
        g_provider_names = current->next;
    else
        previous->next = current->next;
    current->next = NULL;
    provider_name_unlock();
    return current;
}

static void provider_buffer_lock(void)
{
    while (__atomic_exchange_n(
               &g_provider_buffer_lock, 1u, __ATOMIC_ACQUIRE) != 0u) {
    }
}

static void provider_buffer_unlock(void)
{
    __atomic_store_n(&g_provider_buffer_lock, 0u, __ATOMIC_RELEASE);
}

static uint8_t* provider_buffer_alloc(size_t capacity)
{
    RinOsKerberosProviderBuffer* buffer;
    if (capacity > SIZE_MAX - sizeof(*buffer)) return NULL;
    buffer = (RinOsKerberosProviderBuffer*)calloc(
        1u, sizeof(*buffer) + capacity);
    if (buffer == NULL) return NULL;
    buffer->capacity = capacity;
    provider_buffer_lock();
    buffer->next = g_provider_buffers;
    g_provider_buffers = buffer;
    provider_buffer_unlock();
    return buffer->data;
}

static void provider_buffer_dispose(void* buffer)
{
    RinOsKerberosProviderBuffer* previous = NULL;
    RinOsKerberosProviderBuffer* current;
    if (buffer == NULL) return;

    provider_buffer_lock();
    current = g_provider_buffers;
    while (current != NULL && current->data != (uint8_t*)buffer) {
        previous = current;
        current = current->next;
    }
    if (current == NULL) {
        provider_buffer_unlock();
        return;
    }
    if (previous == NULL)
        g_provider_buffers = current->next;
    else
        previous->next = current->next;
    provider_buffer_unlock();

    provider_zero(current->data, current->capacity);
    current->capacity = 0u;
    current->next = NULL;
    free(current);
}

static uint32_t provider_unavailable(uint32_t* minor_status)
{
    if (minor_status != NULL) *minor_status = 0u;
    return RIN_AUTH_PROVIDER_UNAVAILABLE;
}

static uint32_t provider_status_from_owner(uint32_t status,
                                           uint32_t* minor_status)
{
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_OK) {
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_OK;
    }
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_CONTEXT_EXPIRED) {
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_CONTEXT_EXPIRED;
    }
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_BAD_BINDINGS) {
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_BAD_BINDINGS;
    }
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_BAD_SIGNATURE) {
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_BAD_SIGNATURE;
    }
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_INVALID_SESSION) {
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_DEFECTIVE_CREDENTIAL;
    }
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_EXPIRED) {
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_CREDENTIALS_EXPIRED;
    }
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_NO_CREDENTIAL) {
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_NO_CREDENTIAL;
    }
    return provider_unavailable(minor_status);
}

static uint32_t provider_defective_token(uint32_t* minor_status)
{
    if (minor_status != NULL) *minor_status = 0u;
    return RIN_AUTH_PROVIDER_DEFECTIVE_TOKEN;
}

/* The service owns the full RFC 4120/4121 decoder.  The runtime-side check is
 * intentionally only a bounded GSS framing check: it rejects truncated or
 * malformed wrappers before IPC, while leaving token semantics, KRB-ERROR,
 * and integrity failures to the product provider. */
static int provider_der_value_bounds(const uint8_t* input, uint32_t size,
                                     uint32_t* header_size,
                                     uint32_t* value_size)
{
    uint8_t length_byte;
    uint32_t length_octets;
    uint32_t value = 0u;

    if (input == NULL || header_size == NULL || value_size == NULL ||
        size < 2u)
        return 0;
    length_byte = input[1];
    if (length_byte < 0x80u) {
        *header_size = 2u;
        *value_size = length_byte;
        return *value_size <= size - *header_size;
    }
    length_octets = (uint32_t)(length_byte & 0x7fu);
    if (length_octets == 0u || length_octets > 4u ||
        length_octets > size - 2u)
        return 0;
    if (input[2] == 0u) return 0;
    for (uint32_t index = 0u; index < length_octets; ++index)
        value = (value << 8u) | input[2u + index];
    if (value < 0x80u || value > size - 2u - length_octets)
        return 0;
    *header_size = 2u + length_octets;
    *value_size = value;
    return 1;
}

static int provider_gss_token_payload(const uint8_t* token,
                                      uint32_t token_size,
                                      const uint8_t** payload_out,
                                      uint32_t* payload_size_out)
{
    static const uint8_t kerberos_oid[] = {
        0x2au, 0x86u, 0x48u, 0x86u, 0xf7u,
        0x12u, 0x01u, 0x02u, 0x02u,
    };
    uint32_t outer_header;
    uint32_t outer_size;
    uint32_t oid_header;
    uint32_t oid_size;
    uint32_t offset;

    if (payload_out == NULL || payload_size_out == NULL || token == NULL ||
        token_size < 2u || token[0] != 0x60u ||
        !provider_der_value_bounds(token, token_size, &outer_header,
                                   &outer_size) ||
        outer_header > token_size ||
        outer_size != token_size - outer_header)
        return 0;
    offset = outer_header;
    if (offset >= token_size || token[offset] != 0x06u ||
        !provider_der_value_bounds(token + offset, token_size - offset,
                                   &oid_header, &oid_size) ||
        oid_size != sizeof(kerberos_oid) ||
        oid_header + oid_size > token_size - offset ||
        memcmp(token + offset + oid_header, kerberos_oid,
               sizeof(kerberos_oid)) != 0)
        return 0;
    offset += oid_header + oid_size;
    if (token_size - offset < 2u) return 0;
    *payload_out = token + offset;
    *payload_size_out = token_size - offset;
    return 1;
}

static int provider_gss_token_has_framing(const uint8_t* token,
                                          uint32_t token_size)
{
    const uint8_t* payload = NULL;
    uint32_t payload_size = 0u;
    return provider_gss_token_payload(token, token_size, &payload,
                                      &payload_size);
}

typedef struct ProviderDerCursorV1 {
    const uint8_t* bytes;
    uint32_t size;
    uint32_t offset;
} ProviderDerCursorV1;

static int provider_der_read_tlv(ProviderDerCursorV1* cursor,
                                 uint8_t expected_tag,
                                 const uint8_t** value_out,
                                 uint32_t* value_size_out)
{
    uint32_t header_size;
    uint32_t value_size;

    if (cursor == NULL || value_out == NULL || value_size_out == NULL ||
        cursor->bytes == NULL || cursor->offset > cursor->size ||
        cursor->offset == cursor->size ||
        cursor->bytes[cursor->offset] != expected_tag ||
        !provider_der_value_bounds(cursor->bytes + cursor->offset,
                                   cursor->size - cursor->offset,
                                   &header_size, &value_size))
        return 0;
    *value_out = cursor->bytes + cursor->offset + header_size;
    *value_size_out = value_size;
    cursor->offset += header_size + value_size;
    return 1;
}

static int provider_der_read_integer(ProviderDerCursorV1* cursor,
                                     uint32_t* value_out)
{
    const uint8_t* bytes;
    uint32_t size;
    uint32_t value = 0u;
    uint32_t index;

    if (value_out == NULL || !provider_der_read_tlv(
            cursor, 0x02u, &bytes, &size) || size == 0u || size > 5u ||
        (size == 5u && (bytes[0] != 0u || (bytes[1] & 0x80u) == 0u)) ||
        /* All callers of this helper consume non-negative KRB-ERROR
         * fields (pvno, msg-type, times, and error-code).  Keep the
         * signed ASN.1 INTEGER representation from being reinterpreted as
         * uint32_t.  The one-octet case must be checked explicitly before
         * the value loop; otherwise 0xff would bypass the old size==1
         * fast path and become the positive value 255. */
        (bytes[0] & 0x80u) != 0u ||
        (size > 1u && size < 5u && bytes[0] == 0u &&
         (bytes[1] & 0x80u) == 0u))
        return 0;
    for (index = size == 5u ? 1u : 0u; index < size; ++index)
        value = (value << 8u) | bytes[index];
    *value_out = value;
    return 1;
}

static int provider_der_read_wrapped_integer(ProviderDerCursorV1* cursor,
                                             uint8_t wrapper_tag,
                                             uint32_t* value_out)
{
    const uint8_t* bytes;
    uint32_t size;
    ProviderDerCursorV1 nested;

    if (!provider_der_read_tlv(cursor, wrapper_tag, &bytes, &size)) return 0;
    nested.bytes = bytes;
    nested.size = size;
    nested.offset = 0u;
    return provider_der_read_integer(&nested, value_out) &&
           nested.offset == nested.size;
}

static int provider_der_read_wrapped_value(ProviderDerCursorV1* cursor,
                                           uint8_t wrapper_tag,
                                           uint8_t inner_tag,
                                           const uint8_t** value_out,
                                           uint32_t* value_size_out)
{
    const uint8_t* bytes;
    uint32_t size;
    ProviderDerCursorV1 nested;

    if (!provider_der_read_tlv(cursor, wrapper_tag, &bytes, &size)) return 0;
    nested.bytes = bytes;
    nested.size = size;
    nested.offset = 0u;
    return provider_der_read_tlv(&nested, inner_tag, value_out,
                                 value_size_out) &&
           nested.offset == nested.size;
}

static int provider_der_read_oid(ProviderDerCursorV1* cursor,
                                 const uint8_t* expected,
                                 uint32_t expected_size)
{
    const uint8_t* value;
    uint32_t value_size;

    return expected != NULL &&
           provider_der_read_tlv(cursor, 0x06u, &value, &value_size) &&
           value_size == expected_size &&
           memcmp(value, expected, expected_size) == 0;
}

static int provider_der_read_wrapped_octet(
    ProviderDerCursorV1* cursor, uint8_t wrapper_tag,
    const uint8_t** value_out, uint32_t* value_size_out)
{
    return provider_der_read_wrapped_value(cursor, wrapper_tag, 0x04u,
                                           value_out, value_size_out);
}

static int provider_der_read_wrapped_bit_string(
    ProviderDerCursorV1* cursor, uint8_t wrapper_tag)
{
    const uint8_t* value;
    uint32_t value_size;
    uint8_t unused_bits;

    if (!provider_der_read_wrapped_value(cursor, wrapper_tag, 0x03u,
                                         &value, &value_size) ||
        value_size == 0u)
        return 0;
    unused_bits = value[0];
    if (unused_bits > 7u || (value_size == 1u && unused_bits != 0u))
        return 0;
    if (unused_bits != 0u &&
        (value[value_size - 1u] & ((UINT8_C(1) << unused_bits) - 1u)) != 0u)
        return 0;
    return 1;
}

static int provider_der_read_wrapped_enumerated(
    ProviderDerCursorV1* cursor, uint8_t wrapper_tag, uint32_t* value_out)
{
    const uint8_t* value;
    uint32_t value_size;
    uint32_t number = 0u;
    uint32_t index;

    if (value_out == NULL ||
        !provider_der_read_wrapped_value(cursor, wrapper_tag, 0x0au,
                                         &value, &value_size) ||
        value_size == 0u || value_size > 4u ||
        (value[0] & 0x80u) != 0u ||
        (value_size > 1u && value[0] == 0u &&
         (value[1] & 0x80u) == 0u))
        return 0;
    for (index = 0u; index < value_size; ++index)
        number = (number << 8u) | value[index];
    *value_out = number;
    return 1;
}

typedef struct ProviderSpnegoInputV1 {
    const uint8_t* mechanism_token;
    uint32_t mechanism_token_size;
    const uint8_t* mech_list;
    uint32_t mech_list_size;
    const uint8_t* mechanism_mic;
    uint32_t mechanism_mic_size;
    uint32_t is_initial;
    uint32_t has_mechanism_token;
    uint32_t has_mechanism_mic;
    uint32_t neg_state;
    uint32_t has_neg_state;
    uint32_t rejected;
} ProviderSpnegoInputV1;

static const uint8_t g_provider_spnego_oid[] = {
    0x2bu, 0x06u, 0x01u, 0x05u, 0x05u, 0x02u,
};

static const uint8_t g_provider_kerberos_oid[] = {
    0x2au, 0x86u, 0x48u, 0x86u, 0xf7u,
    0x12u, 0x01u, 0x02u, 0x02u,
};

static const uint8_t g_provider_kerberos_mech_list[] = {
    0x30u, 0x0bu, 0x06u, 0x09u, 0x2au, 0x86u, 0x48u, 0x86u,
    0xf7u, 0x12u, 0x01u, 0x02u, 0x02u,
};

/* Return values: 0 malformed, 1 usable Kerberos token, 2 valid SPNEGO with
 * no supported Kerberos mechanism, 3 valid peer reject. */
static int provider_spnego_parse_init(const uint8_t* bytes, uint32_t size,
                                      ProviderSpnegoInputV1* output)
{
    const uint8_t* sequence_bytes;
    const uint8_t* mechanism_bytes;
    const uint8_t* list_bytes;
    const uint8_t* token_bytes;
    uint32_t sequence_size;
    uint32_t mechanism_size;
    uint32_t list_size;
    uint32_t token_size;
    ProviderDerCursorV1 outer = {bytes, size, 0u};
    ProviderDerCursorV1 sequence;
    ProviderDerCursorV1 mechanism;
    ProviderDerCursorV1 list;
    uint32_t list_tlv_start;
    uint8_t last_tag = 0xa0u;
    int has_kerberos = 0;

    if (output == NULL ||
        !provider_der_read_tlv(&outer, 0x30u, &sequence_bytes,
                               &sequence_size) || outer.offset != outer.size)
        return 0;
    sequence.bytes = sequence_bytes;
    sequence.size = sequence_size;
    sequence.offset = 0u;
    if (!provider_der_read_tlv(&sequence, 0xa0u, &mechanism_bytes,
                               &mechanism_size) || sequence.offset > sequence.size)
        return 0;
    mechanism.bytes = mechanism_bytes;
    mechanism.size = mechanism_size;
    mechanism.offset = 0u;
    list_tlv_start = mechanism.offset;
    if (!provider_der_read_tlv(&mechanism, 0x30u, &list_bytes, &list_size) ||
        mechanism.offset != mechanism.size)
        return 0;
    list.bytes = list_bytes;
    list.size = list_size;
    list.offset = 0u;
    while (list.offset < list.size) {
        const uint8_t* oid;
        uint32_t oid_size;
        if (!provider_der_read_tlv(&list, 0x06u, &oid, &oid_size))
            return 0;
        if (oid_size == sizeof(g_provider_kerberos_oid) &&
            memcmp(oid, g_provider_kerberos_oid,
                   sizeof(g_provider_kerberos_oid)) == 0)
            has_kerberos = 1;
    }
    if (!has_kerberos)
        return 2;

    memset(output, 0, sizeof(*output));
    output->is_initial = 1u;
    if (mechanism.offset < list_tlv_start ||
        mechanism.offset - list_tlv_start > RINOS_KERBEROS_MAX_MECH_LIST_SIZE)
        return 0;
    output->mech_list = mechanism.bytes + list_tlv_start;
    output->mech_list_size = mechanism.offset - list_tlv_start;
    while (sequence.offset < sequence.size) {
        const uint8_t tag = sequence.bytes[sequence.offset];
        if (tag <= last_tag)
            return 0;
        last_tag = tag;
        if (tag == 0xa1u) {
            /* reqFlags is ContextFlags, not an arbitrary context value. */
            if (!provider_der_read_wrapped_bit_string(&sequence, 0xa1u))
                return 0;
        } else if (tag == 0xa2u) {
            if (output->has_mechanism_token ||
                !provider_der_read_wrapped_octet(
                    &sequence, 0xa2u, &token_bytes, &token_size))
                return 0;
            output->mechanism_token = token_bytes;
            output->mechanism_token_size = token_size;
            output->has_mechanism_token = 1u;
        } else if (tag == 0xa3u) {
            /* RFC 4178 Section 5 authenticates the DER encoding of the
             * MechTypeList value, not the surrounding [0] wrapper.  Keep the
             * MIC until the mechanism context is established and verify it
             * through the existing GSS VerifyMIC owner operation. */
            if (output->has_mechanism_mic)
                return 0;
            if (!provider_der_read_wrapped_octet(&sequence, 0xa3u,
                                                 &token_bytes, &token_size) ||
                token_size != 28u || token_bytes[0] != 0x04u ||
                token_bytes[1] != 0x04u)
                return 0;
            output->mechanism_mic = token_bytes;
            output->mechanism_mic_size = token_size;
            output->has_mechanism_mic = 1u;
        } else {
            return 0;
        }
    }
    return 1;
}

static int provider_spnego_parse_response(const uint8_t* bytes, uint32_t size,
                                          ProviderSpnegoInputV1* output)
{
    const uint8_t* sequence_bytes;
    const uint8_t* token_bytes;
    uint32_t sequence_size;
    uint32_t token_size;
    uint32_t state = 0u;
    int have_state = 0;
    int have_mechanism = 0;
    uint8_t last_tag = 0x9fu;
    ProviderDerCursorV1 outer = {bytes, size, 0u};
    ProviderDerCursorV1 sequence;

    if (output == NULL ||
        !provider_der_read_tlv(&outer, 0x30u, &sequence_bytes,
                               &sequence_size) || outer.offset != outer.size)
        return 0;
    sequence.bytes = sequence_bytes;
    sequence.size = sequence_size;
    sequence.offset = 0u;
    memset(output, 0, sizeof(*output));
    while (sequence.offset < sequence.size) {
        const uint8_t tag = sequence.bytes[sequence.offset];
        if (tag <= last_tag)
            return 0;
        last_tag = tag;
        if (tag == 0xa0u) {
            if (have_state ||
                !provider_der_read_wrapped_enumerated(&sequence, 0xa0u,
                                                      &state) ||
                state > 3u)
                return 0;
            output->neg_state = state;
            output->has_neg_state = 1u;
            have_state = 1;
        } else if (tag == 0xa1u) {
            if (have_mechanism || !provider_der_read_wrapped_value(
                    &sequence, 0xa1u, 0x06u, &token_bytes, &token_size))
                return 0;
            if (token_size != sizeof(g_provider_kerberos_oid) ||
                memcmp(token_bytes, g_provider_kerberos_oid,
                       sizeof(g_provider_kerberos_oid)) != 0)
                return 2;
            have_mechanism = 1;
        } else if (tag == 0xa2u) {
            if (output->has_mechanism_token ||
                !provider_der_read_wrapped_octet(
                    &sequence, 0xa2u, &token_bytes, &token_size))
                return 0;
            output->mechanism_token = token_bytes;
            output->mechanism_token_size = token_size;
            output->has_mechanism_token = 1u;
        } else if (tag == 0xa3u) {
            /* See the NegTokenInit path above: retain the field and verify it
             * against the initial MechTypeList after context establishment. */
            if (output->has_mechanism_mic)
                return 0;
            if (!provider_der_read_wrapped_octet(&sequence, 0xa3u,
                                                 &token_bytes, &token_size) ||
                token_size != 28u || token_bytes[0] != 0x04u ||
                token_bytes[1] != 0x04u)
                return 0;
            output->mechanism_mic = token_bytes;
            output->mechanism_mic_size = token_size;
            output->has_mechanism_mic = 1u;
        } else {
            return 0;
        }
    }
    output->rejected = have_state && state == 2u;
    if (output->rejected)
        return 3;
    return 1;
}

static int provider_spnego_mech_list_starts_with_kerberos(
    const RinOsKerberosProviderContext* context)
{
    const uint8_t* list_bytes;
    const uint8_t* oid_bytes;
    uint32_t list_size;
    uint32_t oid_size;
    ProviderDerCursorV1 cursor;
    if (context == NULL || context->mech_list_size == 0u)
        return 0;
    cursor.bytes = context->mech_list;
    cursor.size = context->mech_list_size;
    cursor.offset = 0u;
    if (!provider_der_read_tlv(&cursor, 0x30u, &list_bytes, &list_size) ||
        cursor.offset != cursor.size)
        return 0;
    cursor.bytes = list_bytes;
    cursor.size = list_size;
    cursor.offset = 0u;
    if (!provider_der_read_tlv(&cursor, 0x06u, &oid_bytes, &oid_size))
        return 0;
    return oid_size == sizeof(g_provider_kerberos_oid) &&
           memcmp(oid_bytes, g_provider_kerberos_oid,
                  sizeof(g_provider_kerberos_oid)) == 0;
}

static int provider_spnego_mic_is_valid(const uint8_t* token,
                                        uint32_t token_size)
{
    return token != NULL && token_size == 28u && token[0] == 0x04u &&
           token[1] == 0x04u;
}

static int provider_spnego_store_mech_list(
    RinOsKerberosProviderContext* context,
    const ProviderSpnegoInputV1* input)
{
    if (context == NULL || input == NULL || input->mech_list == NULL ||
        input->mech_list_size == 0u ||
        input->mech_list_size > RINOS_KERBEROS_MAX_MECH_LIST_SIZE)
        return 0;
    provider_zero(context->mech_list, sizeof(context->mech_list));
    memcpy(context->mech_list, input->mech_list, input->mech_list_size);
    context->mech_list_size = input->mech_list_size;
    return 1;
}

static int provider_spnego_store_default_mech_list(
    RinOsKerberosProviderContext* context)
{
    if (context == NULL)
        return 0;
    provider_zero(context->mech_list, sizeof(context->mech_list));
    memcpy(context->mech_list, g_provider_kerberos_mech_list,
           sizeof(g_provider_kerberos_mech_list));
    context->mech_list_size = sizeof(g_provider_kerberos_mech_list);
    return 1;
}

static int provider_spnego_unwrap(const uint8_t* input, uint32_t input_size,
                                  ProviderSpnegoInputV1* output)
{
    const uint8_t* application_bytes;
    const uint8_t* negotiation_bytes;
    uint32_t application_size;
    uint32_t negotiation_size;
    ProviderDerCursorV1 outer = {input, input_size, 0u};
    ProviderDerCursorV1 application;

    if (output == NULL || input == NULL || input_size == 0u)
        return 0;
    memset(output, 0, sizeof(*output));
    if (input[0] == 0x60u) {
        if (!provider_der_read_tlv(&outer, 0x60u, &application_bytes,
                                   &application_size) || outer.offset != outer.size)
            return 0;
        application.bytes = application_bytes;
        application.size = application_size;
        application.offset = 0u;
        if (!provider_der_read_oid(&application, g_provider_spnego_oid,
                                   sizeof(g_provider_spnego_oid)) ||
            !provider_der_read_tlv(&application, 0xa0u, &negotiation_bytes,
                                   &negotiation_size) ||
            application.offset != application.size)
            return 0;
        return provider_spnego_parse_init(negotiation_bytes,
                                          negotiation_size, output);
    }
    if (input[0] == 0xa0u) {
        if (!provider_der_read_tlv(&outer, 0xa0u, &negotiation_bytes,
                                   &negotiation_size) || outer.offset != outer.size)
            return 0;
        return provider_spnego_parse_init(negotiation_bytes,
                                          negotiation_size, output);
    }
    if (input[0] == 0xa1u) {
        if (!provider_der_read_tlv(&outer, 0xa1u, &negotiation_bytes,
                                   &negotiation_size) || outer.offset != outer.size)
            return 0;
        return provider_spnego_parse_response(negotiation_bytes,
                                              negotiation_size, output);
    }
    return 0;
}

static uint32_t provider_der_length_size(uint32_t value)
{
    if (value < 0x80u) return 1u;
    if (value <= 0xffu) return 2u;
    if (value <= 0xffffu) return 3u;
    if (value <= 0xffffffu) return 4u;
    return 5u;
}

static uint64_t provider_der_tlv_size(uint32_t value_size)
{
    return UINT64_C(1) + provider_der_length_size(value_size) + value_size;
}

static int provider_der_write_header(uint8_t* output, uint32_t capacity,
                                     uint32_t* offset, uint8_t tag,
                                     uint32_t value_size)
{
    uint32_t length_size;
    uint32_t index;
    uint32_t value = value_size;
    if (output == NULL || offset == NULL || *offset > capacity)
        return 0;
    length_size = provider_der_length_size(value_size);
    if (capacity - *offset < 1u + length_size) return 0;
    output[(*offset)++] = tag;
    if (length_size == 1u) {
        output[(*offset)++] = (uint8_t)value_size;
        return 1;
    }
    output[(*offset)++] = (uint8_t)(0x80u | (length_size - 1u));
    for (index = length_size - 1u; index != 0u; --index)
        output[(*offset)++] = (uint8_t)(value >> ((index - 1u) * 8u));
    return 1;
}

static int provider_spnego_wrap_init(const uint8_t* token, uint32_t token_size,
                                     const uint8_t* mic, uint32_t mic_size,
                                     uint8_t** output, uint32_t* output_size)
{
    const uint32_t oid_tlv_size =
        (uint32_t)provider_der_tlv_size(sizeof(g_provider_kerberos_oid));
    const uint32_t spnego_oid_tlv_size =
        (uint32_t)provider_der_tlv_size(sizeof(g_provider_spnego_oid));
    const uint32_t mechanism_list_content = oid_tlv_size;
    const uint32_t mechanism_list_tlv =
        (uint32_t)provider_der_tlv_size(mechanism_list_content);
    const uint32_t mechanism_field =
        (uint32_t)provider_der_tlv_size(mechanism_list_tlv);
    const uint32_t token_tlv = token_size != 0u
        ? (uint32_t)provider_der_tlv_size(token_size) : 0u;
    const uint32_t token_field = token_tlv != 0u
        ? (uint32_t)provider_der_tlv_size(token_tlv) : 0u;
    const uint32_t mic_tlv = mic_size != 0u
        ? (uint32_t)provider_der_tlv_size(mic_size) : 0u;
    const uint32_t mic_field = mic_tlv != 0u
        ? (uint32_t)provider_der_tlv_size(mic_tlv) : 0u;
    const uint64_t init_sequence_content64 =
        (uint64_t)mechanism_field + token_field + mic_field;
    const uint64_t init_sequence_tlv64 =
        provider_der_tlv_size((uint32_t)init_sequence_content64);
    const uint64_t negotiation_field64 =
        provider_der_tlv_size((uint32_t)init_sequence_tlv64);
    const uint64_t application_content64 =
        spnego_oid_tlv_size + negotiation_field64;
    const uint64_t total64 =
        provider_der_tlv_size((uint32_t)application_content64);
    uint8_t* bytes;
    uint32_t total;
    uint32_t offset = 0u;

    (void)token;
    if (output == NULL || output_size == NULL ||
        token_size > RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE ||
        (token_size != 0u && token == NULL) ||
        (!provider_spnego_mic_is_valid(mic, mic_size) && mic_size != 0u) ||
        init_sequence_content64 > UINT32_MAX || init_sequence_tlv64 > UINT32_MAX ||
        negotiation_field64 > UINT32_MAX || application_content64 > UINT32_MAX ||
        total64 > RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE)
        return 0;
    total = (uint32_t)total64;
    bytes = provider_buffer_alloc(total);
    if (bytes == NULL) return 0;
    if (!provider_der_write_header(bytes, total, &offset, 0x60u,
                                   (uint32_t)application_content64) ||
        !provider_der_write_header(bytes, total, &offset, 0x06u,
                                   sizeof(g_provider_spnego_oid))) {
        provider_buffer_dispose(bytes);
        return 0;
    }
    memcpy(bytes + offset, g_provider_spnego_oid,
           sizeof(g_provider_spnego_oid));
    offset += sizeof(g_provider_spnego_oid);
    if (!provider_der_write_header(bytes, total, &offset, 0xa0u,
                                   (uint32_t)init_sequence_tlv64) ||
        !provider_der_write_header(bytes, total, &offset, 0x30u,
                                   (uint32_t)init_sequence_content64) ||
        !provider_der_write_header(bytes, total, &offset, 0xa0u,
                                   mechanism_list_tlv) ||
        !provider_der_write_header(bytes, total, &offset, 0x30u,
                                   mechanism_list_content) ||
        !provider_der_write_header(bytes, total, &offset, 0x06u,
                                   sizeof(g_provider_kerberos_oid))) {
        provider_zero(bytes, total);
        provider_buffer_dispose(bytes);
        return 0;
    }
    memcpy(bytes + offset, g_provider_kerberos_oid,
           sizeof(g_provider_kerberos_oid));
    offset += sizeof(g_provider_kerberos_oid);
    if (token_tlv != 0u) {
        if (!provider_der_write_header(bytes, total, &offset, 0xa2u,
                                       token_tlv) ||
            !provider_der_write_header(bytes, total, &offset, 0x04u,
                                       token_size)) {
            provider_zero(bytes, total);
            provider_buffer_dispose(bytes);
            return 0;
        }
        memcpy(bytes + offset, token, token_size);
        offset += token_size;
    }
    if (mic_tlv != 0u) {
        if (!provider_der_write_header(bytes, total, &offset, 0xa3u,
                                       mic_tlv) ||
            !provider_der_write_header(bytes, total, &offset, 0x04u,
                                       mic_size)) {
            provider_zero(bytes, total);
            provider_buffer_dispose(bytes);
            return 0;
        }
        memcpy(bytes + offset, mic, mic_size);
        offset += mic_size;
    }
    if (offset != total) {
        provider_zero(bytes, total);
        provider_buffer_dispose(bytes);
        return 0;
    }
    *output = bytes;
    *output_size = total;
    return 1;
}

static int provider_spnego_wrap_response(
    const uint8_t* token, uint32_t token_size, uint32_t status,
    uint32_t initiator, uint32_t include_mechanism, uint32_t neg_state,
    const uint8_t* mic, uint32_t mic_size,
    uint8_t** output, uint32_t* output_size)
{
    const uint32_t token_tlv = token_size != 0u
        ? (uint32_t)provider_der_tlv_size(token_size) : 0u;
    const uint32_t token_field = token_tlv != 0u
        ? (uint32_t)provider_der_tlv_size(token_tlv) : 0u;
    const uint32_t mechanism_tlv =
        (uint32_t)provider_der_tlv_size(sizeof(g_provider_kerberos_oid));
    const uint32_t mechanism_field = include_mechanism
        ? (uint32_t)provider_der_tlv_size(mechanism_tlv) : 0u;
    const uint32_t mic_tlv = mic_size != 0u
        ? (uint32_t)provider_der_tlv_size(mic_size) : 0u;
    const uint32_t mic_field = mic_tlv != 0u
        ? (uint32_t)provider_der_tlv_size(mic_tlv) : 0u;
    const uint32_t state_field = initiator ? 0u :
        (uint32_t)provider_der_tlv_size(3u);
    const uint64_t sequence_content64 =
        (uint64_t)state_field + mechanism_field + token_field + mic_field;
    const uint64_t sequence_tlv64 =
        provider_der_tlv_size((uint32_t)sequence_content64);
    const uint64_t total64 = provider_der_tlv_size((uint32_t)sequence_tlv64);
    uint8_t* bytes;
    uint32_t total;
    uint32_t offset = 0u;
    uint32_t state = neg_state != UINT32_MAX
        ? neg_state : (status == RIN_AUTH_PROVIDER_OK ? 0u : 1u);

    if (output == NULL || output_size == NULL ||
        token_size > RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE ||
        (token_size != 0u && token == NULL) ||
        (!provider_spnego_mic_is_valid(mic, mic_size) && mic_size != 0u) ||
        state > 3u ||
        sequence_content64 > UINT32_MAX || sequence_tlv64 > UINT32_MAX ||
        total64 > RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE)
        return 0;
    total = (uint32_t)total64;
    bytes = provider_buffer_alloc(total);
    if (bytes == NULL) return 0;
    if (!provider_der_write_header(bytes, total, &offset, 0xa1u,
                                   (uint32_t)sequence_tlv64) ||
        !provider_der_write_header(bytes, total, &offset, 0x30u,
                                   (uint32_t)sequence_content64)) {
        provider_buffer_dispose(bytes);
        return 0;
    }
    if (!initiator &&
        (!provider_der_write_header(bytes, total, &offset, 0xa0u, 3u) ||
         !provider_der_write_header(bytes, total, &offset, 0x0au, 1u))) {
        provider_zero(bytes, total);
        provider_buffer_dispose(bytes);
        return 0;
    }
    if (!initiator) bytes[offset++] = (uint8_t)state;
    if (include_mechanism &&
        (!provider_der_write_header(bytes, total, &offset, 0xa1u,
                                    mechanism_tlv) ||
         !provider_der_write_header(bytes, total, &offset, 0x06u,
                                    sizeof(g_provider_kerberos_oid)))) {
        provider_zero(bytes, total);
        provider_buffer_dispose(bytes);
        return 0;
    }
    if (include_mechanism) {
        memcpy(bytes + offset, g_provider_kerberos_oid,
               sizeof(g_provider_kerberos_oid));
        offset += sizeof(g_provider_kerberos_oid);
    }
    if (token_tlv != 0u &&
        (!provider_der_write_header(bytes, total, &offset, 0xa2u,
                                    token_tlv) ||
         !provider_der_write_header(bytes, total, &offset, 0x04u,
                                    token_size))) {
        provider_zero(bytes, total);
        provider_buffer_dispose(bytes);
        return 0;
    }
    if (token_tlv != 0u) {
        memcpy(bytes + offset, token, token_size);
        offset += token_size;
    }
    if (mic_tlv != 0u) {
        if (!provider_der_write_header(bytes, total, &offset, 0xa3u,
                                       mic_tlv) ||
            !provider_der_write_header(bytes, total, &offset, 0x04u,
                                       mic_size)) {
            provider_zero(bytes, total);
            provider_buffer_dispose(bytes);
            return 0;
        }
        memcpy(bytes + offset, mic, mic_size);
        offset += mic_size;
    }
    if (offset != total) {
        provider_zero(bytes, total);
        provider_buffer_dispose(bytes);
        return 0;
    }
    *output = bytes;
    *output_size = total;
    return 1;
}

static int provider_spnego_replace_output(RinAuthProviderBufferV1* output,
                                           uint32_t status,
                                           uint32_t initial_message,
                                           uint32_t initiator,
                                           uint32_t include_mechanism,
                                           uint32_t neg_state,
                                           const uint8_t* mic,
                                           uint32_t mic_size)
{
    uint8_t* old_bytes;
    uint64_t old_size;
    uint8_t* wrapped = NULL;
    uint32_t wrapped_size = 0u;
    int ok;

    if (output == NULL || output->length > RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE ||
        (output->length != 0u && output->data == NULL))
        return 0;
    old_bytes = output->data;
    old_size = output->length;
    ok = initial_message
        ? provider_spnego_wrap_init(old_bytes, (uint32_t)old_size,
                                    mic, mic_size, &wrapped, &wrapped_size)
        : provider_spnego_wrap_response(
            old_bytes, (uint32_t)old_size, status, initiator,
            include_mechanism, neg_state, mic, mic_size,
            &wrapped, &wrapped_size);
    if (!ok) {
        if (old_bytes != NULL) {
            provider_zero(old_bytes, (size_t)old_size);
            provider_buffer_dispose(old_bytes);
        }
        output->data = NULL;
        output->length = 0u;
        return 0;
    }
    if (old_bytes != NULL) {
        provider_zero(old_bytes, (size_t)old_size);
        provider_buffer_dispose(old_bytes);
    }
    output->data = wrapped;
    output->length = wrapped_size;
    return 1;
}

static int provider_der_integer32_valid(const uint8_t* bytes, uint32_t size)
{
    if (bytes == NULL || size == 0u || size > 5u) return 0;
    if (size == 1u) return 1;
    if (size == 5u)
        return bytes[0] == 0u && (bytes[1] & 0x80u) != 0u;
    if (bytes[0] == 0u && (bytes[1] & 0x80u) == 0u) return 0;
    if (bytes[0] == 0xffu && (bytes[1] & 0x80u) != 0u) return 0;
    return 1;
}

static int provider_kerberos_principal_name_valid(const uint8_t* bytes,
                                                  uint32_t size)
{
    const uint8_t* field_bytes;
    const uint8_t* components_bytes;
    uint32_t field_size;
    uint32_t components_size;
    uint32_t component_count = 0u;
    ProviderDerCursorV1 principal = {bytes, size, 0u};
    ProviderDerCursorV1 integer;
    ProviderDerCursorV1 components;

    if (bytes == NULL ||
        !provider_der_read_tlv(&principal, 0xa0u, &field_bytes,
                               &field_size) ||
        principal.offset == principal.size)
        return 0;
    integer.bytes = field_bytes;
    integer.size = field_size;
    integer.offset = 0u;
    if (!provider_der_read_tlv(&integer, 0x02u, &field_bytes, &field_size) ||
        integer.offset != integer.size ||
        !provider_der_integer32_valid(field_bytes, field_size) ||
        !provider_der_read_wrapped_value(&principal, 0xa1u, 0x30u,
                                         &components_bytes,
                                         &components_size) ||
        principal.offset != principal.size)
        return 0;

    components.bytes = components_bytes;
    components.size = components_size;
    components.offset = 0u;
    while (components.offset < components.size) {
        if (!provider_der_read_tlv(&components, 0x1bu, &field_bytes,
                                   &field_size))
            return 0;
        if (field_size == 0u) return 0;
        ++component_count;
    }
    /* RFC 4120 PrincipalName carries a non-empty name-string.  An empty
     * sequence is not a usable service/client principal and must not turn a
     * malformed peer KRB-ERROR into a preserved protocol status. */
    return component_count != 0u;
}

static int provider_kerberos_time_valid(const uint8_t* bytes,
                                        uint32_t size)
{
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;
    static const uint8_t month_days[] = {
        31u, 28u, 31u, 30u, 31u, 30u,
        31u, 31u, 30u, 31u, 30u, 31u,
    };
    uint32_t max_day;
    uint32_t index;
    if (bytes == NULL || size != 15u || bytes[14] != (uint8_t)'Z')
        return 0;
    for (index = 0u; index < 14u; ++index) {
        if (bytes[index] < (uint8_t)'0' || bytes[index] > (uint8_t)'9')
            return 0;
    }
    year = (uint32_t)(bytes[0] - (uint8_t)'0') * 1000u +
           (uint32_t)(bytes[1] - (uint8_t)'0') * 100u +
           (uint32_t)(bytes[2] - (uint8_t)'0') * 10u +
           (uint32_t)(bytes[3] - (uint8_t)'0');
    month = (uint32_t)(bytes[4] - (uint8_t)'0') * 10u +
            (uint32_t)(bytes[5] - (uint8_t)'0');
    day = (uint32_t)(bytes[6] - (uint8_t)'0') * 10u +
          (uint32_t)(bytes[7] - (uint8_t)'0');
    hour = (uint32_t)(bytes[8] - (uint8_t)'0') * 10u +
           (uint32_t)(bytes[9] - (uint8_t)'0');
    minute = (uint32_t)(bytes[10] - (uint8_t)'0') * 10u +
             (uint32_t)(bytes[11] - (uint8_t)'0');
    second = (uint32_t)(bytes[12] - (uint8_t)'0') * 10u +
             (uint32_t)(bytes[13] - (uint8_t)'0');
    if (month == 0u || month > 12u || day == 0u ||
        hour > 23u || minute > 59u || second > 60u)
        return 0;
    max_day = month_days[month - 1u];
    if (month == 2u && (year % 4u == 0u) &&
        ((year % 100u) != 0u || (year % 400u) == 0u))
        ++max_day;
    return day <= max_day;
}

static int provider_kerberos_error_der(const uint8_t* bytes, uint32_t size,
                                       uint32_t* error_code_out)
{
    const uint8_t* app_bytes;
    const uint8_t* time_bytes;
    uint32_t app_size;
    uint32_t time_size;
    uint32_t value;
    uint32_t previous_optional_tag = 0u;
    ProviderDerCursorV1 token = {bytes, size, 0u};
    ProviderDerCursorV1 sequence;

    if (error_code_out == NULL ||
        !provider_der_read_tlv(&token, 0x7eu, &app_bytes, &app_size) ||
        token.offset != token.size)
        return 0;
    /* KRB-ERROR uses the APPLICATION 30 IMPLICIT tag for its SEQUENCE;
     * the sequence contents follow the 0x7e tag directly. */
    sequence.bytes = app_bytes;
    sequence.size = app_size;
    sequence.offset = 0u;
    if (!provider_der_read_wrapped_integer(&sequence, 0xa0u, &value) ||
        value != 5u ||
        !provider_der_read_wrapped_integer(&sequence, 0xa1u, &value) ||
        value != 30u)
        return 0;

    if (sequence.offset < sequence.size &&
        sequence.bytes[sequence.offset] == 0xa2u) {
        if (!provider_der_read_wrapped_value(&sequence, 0xa2u, 0x18u,
                                             &time_bytes, &time_size) ||
            !provider_kerberos_time_valid(time_bytes, time_size))
            return 0;
    }
    if (sequence.offset < sequence.size &&
        sequence.bytes[sequence.offset] == 0xa3u) {
        if (!provider_der_read_wrapped_integer(&sequence, 0xa3u, &value) ||
            value >= 1000000u)
            return 0;
    }
    if (!provider_der_read_wrapped_value(&sequence, 0xa4u, 0x18u,
                                         &time_bytes, &time_size) ||
        !provider_kerberos_time_valid(time_bytes, time_size) ||
        !provider_der_read_wrapped_integer(&sequence, 0xa5u, &value) ||
        value >= 1000000u ||
        !provider_der_read_wrapped_integer(&sequence, 0xa6u, &value) ||
        value == 0u || value > UINT32_C(0x7fffffff))
        return 0;
    *error_code_out = value;

    /* Validate the remaining optional KRB-ERROR fields in ASN.1 order. They
     * are advisory only; no peer-supplied name, text, or data drives policy. */
    while (sequence.offset < sequence.size) {
        const uint8_t tag = sequence.bytes[sequence.offset];
        uint8_t inner_tag;
        const uint8_t* ignored_bytes;
        uint32_t ignored_size;
        if (tag < 0xa7u || tag > 0xacu || tag <= previous_optional_tag)
            return 0;
        previous_optional_tag = tag;
        switch (tag) {
        case 0xa7u: case 0xa9u: case 0xabu: inner_tag = 0x1bu; break;
        case 0xa8u: case 0xaau: inner_tag = 0x30u; break;
        case 0xacu: inner_tag = 0x04u; break;
        default: return 0;
        }
        if (!provider_der_read_wrapped_value(&sequence, tag, inner_tag,
                                             &ignored_bytes, &ignored_size))
            return 0;
        if ((tag == 0xa8u || tag == 0xaau) &&
            !provider_kerberos_principal_name_valid(ignored_bytes,
                                                     ignored_size))
            return 0;
        /* RFC 4120 makes crealm, cname, realm, sname, e-text, and e-data
         * optional.  Validate identity fields when a peer supplies them, but
         * do not require a service identity in order to surface the KDC error
         * code.  An explicitly supplied empty realm is still malformed. */
        if (tag == 0xa7u || tag == 0xa9u) {
            if (ignored_size == 0u) return 0;
        }
        (void)ignored_bytes;
        (void)ignored_size;
    }
    return 1;
}

/* Returns 1 for a valid KRB-ERROR token, 0 for a different TOK_ID, and -1
 * for malformed GSS/KRB-ERROR framing. */
static int provider_gss_krb_error(const uint8_t* token, uint32_t token_size,
                                  uint32_t* error_code_out)
{
    const uint8_t* payload;
    uint32_t payload_size;
    if (error_code_out == NULL ||
        !provider_gss_token_payload(token, token_size, &payload,
                                    &payload_size))
        return -1;
    /* Keep this parser total even if the GSS framing helper is changed later:
     * TOK_ID is a two-octet field, and a truncated mechanism payload is a
     * defective token rather than a different token kind. */
    if (payload_size < 2u) return -1;
    if (payload[0] != 0x03u || payload[1] != 0x00u) return 0;
    return provider_kerberos_error_der(payload + 2u, payload_size - 2u,
                                       error_code_out) ? 1 : -1;
}

static int provider_sec_context_token(
    const uint8_t* input, uint32_t input_size,
    const uint8_t** token_out, uint32_t* token_size_out)
{
    RinKerberosProviderSecContextInputV1 header = {0};
    uint32_t offset;

    if (input == NULL || token_out == NULL || token_size_out == NULL ||
        input_size < sizeof(header))
        return 0;
    memcpy(&header, input, sizeof(header));
    if (header.struct_size != sizeof(header) ||
        header.version != RIN_KERBEROS_PROVIDER_INPUT_ABI_VERSION ||
        header.kind != RIN_KERBEROS_PROVIDER_INPUT_SEC_CONTEXT ||
        header.reserved != 0u ||
        header.target_name_size > RIN_KERBEROS_PROVIDER_MAX_TARGET_NAME_SIZE ||
        header.channel_binding_size >
            RIN_KERBEROS_PROVIDER_MAX_CHANNEL_BINDING_SIZE ||
        header.token_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE)
        return 0;
    offset = (uint32_t)sizeof(header);
    if (header.target_name_size > input_size - offset)
        return 0;
    offset += header.target_name_size;
    if (header.channel_binding_size > input_size - offset)
        return 0;
    offset += header.channel_binding_size;
    if (header.token_size > input_size - offset ||
        offset + header.token_size != input_size)
        return 0;
    *token_out = input + offset;
    *token_size_out = header.token_size;
    return 1;
}

static int provider_message_pair(
    const uint8_t* input, uint32_t input_size,
    const uint8_t** message_out, uint32_t* message_size_out,
    const uint8_t** token_out, uint32_t* token_size_out)
{
    RinKerberosProviderMessagePairInputV1 header;
    uint32_t offset;

    if (input == NULL || message_out == NULL || message_size_out == NULL ||
        token_out == NULL || token_size_out == NULL ||
        input_size < sizeof(header))
        return 0;
    memcpy(&header, input, sizeof(header));
    if (header.struct_size != sizeof(header) ||
        header.version != RIN_KERBEROS_PROVIDER_INPUT_ABI_VERSION ||
        header.kind != RIN_KERBEROS_PROVIDER_INPUT_MESSAGE_PAIR ||
        (header.flags & ~RIN_KERBEROS_OPERATION_FLAG_ENCRYPT) != 0u ||
        header.first_size > input_size - sizeof(header))
        return 0;
    offset = (uint32_t)sizeof(header);
    if (header.second_size > input_size - offset - header.first_size ||
        offset + header.first_size + header.second_size != input_size)
        return 0;
    *message_out = input + offset;
    *message_size_out = header.first_size;
    *token_out = input + offset + header.first_size;
    *token_size_out = header.second_size;
    return 1;
}

static int provider_name_valid(const RinOsKerberosProviderName* name)
{
    uint32_t size = 0u;
    return provider_name_snapshot(name, NULL, &size);
}

/* RinOS does not have a caller-selected credential namespace.  A named
 * initiator credential is therefore permitted only when its provider-owned
 * principal is exactly the authenticated session principal returned by the
 * same owner handle.  This keeps GSS_C_NO_NAME (DefaultCredentials) and a
 * named acquisition on one real session credential path; it never turns a
 * requested name into a username, password, token, or fabricated handle. */
static uint32_t provider_validate_named_session_credential(
    const RinKerberosCredentialOwnerV1* owner, void* owner_credential,
    const RinOsKerberosProviderName* desired_name, uint32_t* minor_status)
{
    uint8_t principal[RINOS_KERBEROS_MAX_PRINCIPAL_SIZE] = {0};
    uint32_t principal_size = 0u;
    uint64_t generation = 0u;
    uint32_t owner_minor = 0u;
    uint32_t status = RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
    uint8_t desired_principal[RINOS_KERBEROS_MAX_PRINCIPAL_SIZE] = {0};
    uint32_t desired_principal_size = 0u;
    int matches = 0;

    if (minor_status != NULL) *minor_status = 0u;
    if (owner == NULL || owner_credential == NULL ||
        !provider_name_snapshot(desired_name, desired_principal,
                                &desired_principal_size) ||
        owner->get_session_principal == NULL)
        return RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;

    status = owner->get_session_principal(
        owner->context, &owner_minor, owner_credential, principal,
        sizeof(principal), &principal_size, &generation);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK || owner_minor != 0u ||
        principal_size == 0u ||
        principal_size > RINOS_KERBEROS_MAX_PRINCIPAL_SIZE || generation == 0u) {
        if (status == RIN_KERBEROS_CREDENTIAL_OWNER_OK)
            status = RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE;
        goto cleanup;
    }

    matches = principal_size == desired_principal_size &&
              memcmp(principal, desired_principal, principal_size) == 0;
    status = matches ? RIN_KERBEROS_CREDENTIAL_OWNER_OK
                     : RIN_KERBEROS_CREDENTIAL_OWNER_NO_CREDENTIAL;

cleanup:
    provider_zero(principal, sizeof(principal));
    provider_zero(desired_principal, sizeof(desired_principal));
    if (minor_status != NULL) *minor_status = owner_minor;
    return status;
}

static int provider_operation_valid(uint16_t operation)
{
    switch (operation) {
        case RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT:
        case RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT:
        case RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT:
        case RIN_KERBEROS_OPERATION_WRAP:
        case RIN_KERBEROS_OPERATION_UNWRAP:
        case RIN_KERBEROS_OPERATION_GET_MIC:
        case RIN_KERBEROS_OPERATION_VERIFY_MIC:
        case RIN_KERBEROS_OPERATION_GET_PEER_PRINCIPAL:
            return 1;
        default:
            return 0;
    }
}

static int provider_credential_valid(
    const RinOsKerberosProviderCredential* credential, uint32_t kind)
{
    return credential != NULL &&
           credential->magic == RINOS_KERBEROS_CREDENTIAL_MAGIC &&
           credential->kind == kind && credential->owner != NULL &&
           credential->owner_credential != NULL &&
           credential->owner->release_credential != NULL;
}

static int provider_credential_releaseable(
    const RinOsKerberosProviderCredential* credential, uint32_t kind)
{
    return credential != NULL &&
           credential->magic == RINOS_KERBEROS_CREDENTIAL_MAGIC &&
           credential->kind == kind && credential->owner != NULL &&
           credential->owner->release_credential != NULL;
}

static int provider_context_valid(
    const RinOsKerberosProviderContext* context)
{
    return context != NULL && context->magic == RINOS_KERBEROS_CONTEXT_MAGIC &&
           (context->kind == RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR ||
            context->kind == RIN_KERBEROS_OPERATION_CREDENTIAL_ACCEPTOR) &&
           context->owner != NULL && context->owner_credential != NULL &&
           context->credential != NULL &&
           context->credential->magic == RINOS_KERBEROS_CREDENTIAL_MAGIC &&
           context->credential->kind == context->kind &&
           context->credential->owner != NULL &&
           context->credential->owner->release_credential != NULL &&
           context->credential->owner_credential == context->owner_credential &&
           context->credential_ref_held <= 1u &&
           (context->credential_ref_held == 0u ||
            context->credential->active_contexts != 0u) &&
           context->owner->operation != NULL &&
           (context->state == RINOS_KERBEROS_CONTEXT_NEGOTIATING ||
            context->state == RINOS_KERBEROS_CONTEXT_ESTABLISHED) &&
           context->token_size <= RIN_KERBEROS_OPERATION_MAX_CONTEXT_TOKEN_SIZE;
}

/* Keep the opaque owner credential alive while a provider context can still
 * call into it.  The initial context is not published until its first owner
 * operation succeeds, so failed setup paths do not consume a reference. */
static int provider_context_retain(
    RinOsKerberosProviderCredential* credential,
    RinOsKerberosProviderContext* context)
{
    if (credential == NULL || context == NULL ||
        context->credential != credential || context->credential_ref_held != 0u ||
        credential->active_contexts == UINT32_MAX)
        return 0;
    ++credential->active_contexts;
    context->credential_ref_held = 1u;
    return 1;
}

static void provider_context_release(
    RinOsKerberosProviderContext* context)
{
    if (context == NULL || context->credential_ref_held == 0u)
        return;
    if (context->credential != NULL &&
        context->credential->active_contexts != 0u)
        --context->credential->active_contexts;
    context->credential_ref_held = 0u;
}

static int provider_credential_owner_valid(
    const RinKerberosCredentialOwnerV1* owner)
{
    const uint32_t capabilities =
        owner != NULL ? owner->capability_mask : 0u;
    if (owner == NULL || owner->struct_size < sizeof(*owner) ||
        owner->version != RIN_KERBEROS_CREDENTIAL_OWNER_ABI_VERSION ||
        owner->reserved0 != 0u || owner->reserved1 != 0u ||
        (capabilities & RIN_KERBEROS_CREDENTIAL_OWNER_KNOWN_CAPABILITIES) ==
            0u ||
        (capabilities & ~RIN_KERBEROS_CREDENTIAL_OWNER_KNOWN_CAPABILITIES) !=
            0u || owner->release_credential == NULL)
        return 0;

    /* The two credential roles are independent.  A session may have an
     * initiator ccache without a service keytab, or a service may expose only
     * its acceptor keytab.  Rejecting such an owner here would hide a valid
     * role before the role-specific acquisition callback can return the
     * correct NO_CREDENTIAL result. */
    if ((capabilities & RIN_KERBEROS_CREDENTIAL_OWNER_CAP_SESSION_INITIATOR) !=
            0u &&
        (owner->acquire_session_initiator == NULL ||
         owner->get_session_principal == NULL))
        return 0;
    if ((capabilities & RIN_KERBEROS_CREDENTIAL_OWNER_CAP_ACCEPTOR_KEYTAB) !=
            0u &&
        owner->acquire_acceptor_keytab == NULL)
        return 0;
    return 1;
}

static int provider_operation_owner_valid(
    const RinKerberosOperationOwnerV1* owner)
{
    return owner != NULL &&
           owner->struct_size >= sizeof(*owner) &&
           owner->version == RIN_KERBEROS_OPERATION_OWNER_ABI_VERSION &&
           owner->reserved0 == 0u && owner->operation != NULL;
}

static const RinKerberosCredentialOwnerV1* provider_credential_owner(void)
{
    const RinKerberosCredentialOwnerV1* owner;
#if !defined(RINOS_KERBEROS_OWNER_LINKED)
    if (rin_kerberos_credential_owner_get_v1 == NULL) return NULL;
#endif
    owner = rin_kerberos_credential_owner_get_v1();
    return provider_credential_owner_valid(owner) ? owner : NULL;
}

static const RinKerberosOperationOwnerV1* provider_operation_owner(void)
{
    const RinKerberosOperationOwnerV1* owner;
#if !defined(RINOS_KERBEROS_OWNER_LINKED)
    if (rin_kerberos_operation_owner_get_v1 == NULL) return NULL;
#endif
    owner = rin_kerberos_operation_owner_get_v1();
    return provider_operation_owner_valid(owner) ? owner : NULL;
}

static uint32_t provider_alloc_name(uint32_t* minor_status, char* input,
                                    uint32_t input_length, void** output)
{
    RinOsKerberosProviderName* name;
    if (output == NULL || input_length == 0u ||
        input_length > RIN_KERBEROS_PROVIDER_MAX_TARGET_NAME_SIZE ||
        input == NULL) {
        if (output != NULL) *output = NULL;
        return provider_unavailable(minor_status);
    }
    name = (RinOsKerberosProviderName*)calloc(1u, sizeof(*name));
    if (name == NULL) return provider_unavailable(minor_status);
    name->magic = RINOS_KERBEROS_NAME_MAGIC;
    name->size = input_length;
    memcpy(name->bytes, input, input_length);
    provider_name_register(name);
    *output = name;
    if (minor_status != NULL) *minor_status = 0u;
    return RIN_AUTH_PROVIDER_OK;
}

static uint32_t provider_import_user_name(
    void* context, uint32_t* minor_status, char* input,
    uint32_t input_length, void** output)
{
    (void)context;
    return provider_alloc_name(minor_status, input, input_length, output);
}

static uint32_t provider_import_principal_name(
    void* context, uint32_t* minor_status, char* input,
    uint32_t input_length, void** output)
{
    (void)context;
    return provider_alloc_name(minor_status, input, input_length, output);
}

static uint32_t provider_release_name(void* context, uint32_t* minor_status,
                                      void** input)
{
    RinOsKerberosProviderName* name;
    (void)context;
    if (input == NULL || *input == NULL)
        return provider_unavailable(minor_status);
    name = provider_name_take(*input);
    if (name == NULL) {
        *input = NULL;
        return provider_unavailable(minor_status);
    }
    provider_zero(name, sizeof(*name));
    free(name);
    *input = NULL;
    if (minor_status != NULL) *minor_status = 0u;
    return RIN_AUTH_PROVIDER_OK;
}

static void provider_initialize_credential(
    RinOsKerberosProviderCredential* credential,
    const RinKerberosCredentialOwnerV1* owner, uint32_t kind,
    void* owner_credential)
{
    credential->magic = RINOS_KERBEROS_CREDENTIAL_MAGIC;
    credential->kind = kind;
    credential->owner_credential = owner_credential;
    credential->pending_release_credential = NULL;
    credential->owner = owner;
    credential->active_contexts = 0u;
}

/* Cleanup for a replacement obtained during a failed refresh.  The pending
 * handle is deliberately not usable for operations; this helper only
 * retries the same owner release until the owner consumes it. */
static uint32_t provider_release_pending_credential(
    RinOsKerberosProviderCredential* credential, uint32_t* minor_status)
{
    uint32_t status;
    if (credential == NULL || credential->pending_release_credential == NULL)
        return RIN_AUTH_PROVIDER_OK;
    status = credential->owner->release_credential(
        credential->owner->context, minor_status,
        &credential->pending_release_credential);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK)
        return provider_status_from_owner(status, minor_status);
    if (credential->pending_release_credential != NULL)
        return provider_unavailable(minor_status);
    return RIN_AUTH_PROVIDER_OK;
}

static uint32_t provider_acquire_acceptor_cred(
    void* context, uint32_t* minor_status, void** output)
{
    const RinKerberosCredentialOwnerV1* owner = provider_credential_owner();
    RinOsKerberosProviderCredential* credential;
    void* owner_credential = NULL;
    uint32_t status;
    (void)context;
    if (output == NULL) return provider_unavailable(minor_status);
    *output = NULL;
    if (owner == NULL ||
        (owner->capability_mask &
             RIN_KERBEROS_CREDENTIAL_OWNER_CAP_ACCEPTOR_KEYTAB) == 0u ||
        owner->acquire_acceptor_keytab == NULL)
        return provider_unavailable(minor_status);
    credential = (RinOsKerberosProviderCredential*)calloc(
        1u, sizeof(*credential));
    if (credential == NULL) return provider_unavailable(minor_status);
    status = owner->acquire_acceptor_keytab(
        owner->context, minor_status, &owner_credential);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK) {
        if (owner_credential != NULL) {
            provider_initialize_credential(
                credential, owner,
                RIN_KERBEROS_OPERATION_CREDENTIAL_ACCEPTOR,
                owner_credential);
            *output = credential;
        } else {
            provider_zero(credential, sizeof(*credential));
            free(credential);
        }
        return provider_status_from_owner(status, minor_status);
    }
    if (owner_credential == NULL) {
        provider_zero(credential, sizeof(*credential));
        free(credential);
        return provider_unavailable(minor_status);
    }
    provider_initialize_credential(
        credential, owner, RIN_KERBEROS_OPERATION_CREDENTIAL_ACCEPTOR,
        owner_credential);
    *output = credential;
    if (minor_status != NULL) *minor_status = 0u;
    return RIN_AUTH_PROVIDER_OK;
}

static uint32_t provider_initiate_cred_spnego(
    void* context, uint32_t* minor_status, void* desired_name, void** output)
{
    const RinKerberosCredentialOwnerV1* owner = provider_credential_owner();
    RinOsKerberosProviderCredential* credential;
    void* owner_credential = NULL;
    uint32_t status;
    uint32_t named_status;
    uint32_t cleanup_minor = 0u;
    (void)context;
    if (output == NULL) return provider_unavailable(minor_status);
    *output = NULL;
    if (owner == NULL ||
        (owner->capability_mask &
             RIN_KERBEROS_CREDENTIAL_OWNER_CAP_SESSION_INITIATOR) == 0u ||
        owner->acquire_session_initiator == NULL)
        return provider_unavailable(minor_status);
    credential = (RinOsKerberosProviderCredential*)calloc(
        1u, sizeof(*credential));
    if (credential == NULL) return provider_unavailable(minor_status);
    status = owner->acquire_session_initiator(
        owner->context, minor_status, NULL, &owner_credential);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK) {
        if (owner_credential != NULL) {
            provider_initialize_credential(
                credential, owner,
                RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR,
                owner_credential);
            *output = credential;
        } else {
            provider_zero(credential, sizeof(*credential));
            free(credential);
        }
        return provider_status_from_owner(status, minor_status);
    }
    if (owner_credential == NULL) {
        provider_zero(credential, sizeof(*credential));
        free(credential);
        return provider_unavailable(minor_status);
    }

    if (desired_name != NULL) {
        /* Acquire the real session handle first, then authorize a named
         * request against its bounded non-secret principal.  The owner is
         * still the authority for the ccache and generation. */
        named_status = provider_validate_named_session_credential(
            owner, owner_credential,
            (const RinOsKerberosProviderName*)desired_name, minor_status);
        if (named_status != RIN_KERBEROS_CREDENTIAL_OWNER_OK) {
            uint32_t release_status = owner->release_credential(
                owner->context, &cleanup_minor, &owner_credential);
            if (owner_credential != NULL) {
                provider_initialize_credential(
                    credential, owner,
                    RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR,
                    owner_credential);
                *output = credential;
                if (release_status == RIN_KERBEROS_CREDENTIAL_OWNER_OK)
                    return provider_unavailable(minor_status);
                return provider_status_from_owner(release_status,
                                                  &cleanup_minor);
            } else {
                provider_zero(credential, sizeof(*credential));
                free(credential);
            }
            if (release_status != RIN_KERBEROS_CREDENTIAL_OWNER_OK)
                return provider_status_from_owner(release_status,
                                                  &cleanup_minor);
            return provider_status_from_owner(named_status, minor_status);
        }
    }

    provider_initialize_credential(
        credential, owner, RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR,
        owner_credential);
    *output = credential;
    if (minor_status != NULL) *minor_status = 0u;
    return RIN_AUTH_PROVIDER_OK;
}

static uint32_t provider_release_cred(void* context, uint32_t* minor_status,
                                      void** input)
{
    RinOsKerberosProviderCredential* credential;
    uint32_t pending_status;
    uint32_t status;
    (void)context;
    if (input == NULL || *input == NULL)
        return provider_unavailable(minor_status);
    credential = (RinOsKerberosProviderCredential*)*input;
    if (!provider_credential_releaseable(credential, credential->kind)) {
        *input = NULL;
        return provider_unavailable(minor_status);
    }
    /* A live context retains the opaque owner handle.  Releasing it here
     * would leave the context's later operation/delete path with a dangling
     * handle, so fail closed and leave the caller's credential retryable. */
    if (credential->active_contexts != 0u)
        return provider_unavailable(minor_status);
    pending_status = provider_release_pending_credential(credential, minor_status);
    /* A release failure remains visible even when the owner consumed the
     * opaque handle before reporting the error.  The handle is then no
     * longer retryable, but the provider must not erase the failure by
     * releasing the primary credential and returning success. */
    if (pending_status != RIN_AUTH_PROVIDER_OK)
        return pending_status;
    if (credential->owner_credential != NULL) {
        status = credential->owner->release_credential(
            credential->owner->context, minor_status,
            &credential->owner_credential);
        if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK) {
            /* An owner may report failure after consuming its opaque handle
             * (for example, the service removed the keyring record but lost
             * the final acknowledgement).  In that case the wrapper is no
             * longer retryable; retain it only while the owner still exposes
             * a handle. */
            if (credential->owner_credential == NULL) {
                provider_zero(credential, sizeof(*credential));
                free(credential);
                *input = NULL;
            }
            return provider_status_from_owner(status, minor_status);
        }
        if (credential->owner_credential != NULL)
            return provider_status_from_owner(
                RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE,
                minor_status);
    }
    provider_zero(credential, sizeof(*credential));
    free(credential);
    *input = NULL;
    return pending_status != RIN_AUTH_PROVIDER_OK
               ? pending_status
               : provider_status_from_owner(
                     RIN_KERBEROS_CREDENTIAL_OWNER_OK, minor_status);
}

static uint32_t provider_build_sec_context_input(
    uint32_t mechanism, uint32_t requested_flags,
    const RinOsKerberosProviderName* target_name, const void* channel_binding,
    uint32_t channel_binding_size, const uint8_t* token, uint32_t token_size,
    uint8_t** output, uint32_t* output_size)
{
    RinKerberosProviderSecContextInputV1 header = {0};
    uint8_t target_name_bytes[RIN_KERBEROS_PROVIDER_MAX_TARGET_NAME_SIZE] = {0};
    uint32_t target_name_size = 0u;
    uint32_t total;
    uint8_t* bytes;
    if (output == NULL || output_size == NULL ||
        (target_name != NULL && !provider_name_snapshot(
            target_name, target_name_bytes, &target_name_size)) ||
        /* The upstream GSS namespace is wider than the RinOS operation
         * contract.  Do not let a caller request delegation, identity, or
         * another mode whose session policy/owner lifecycle is not present;
         * advertising only the known bit names would turn an unsupported
         * request into a provider-side success path. */
        (requested_flags &
         ~RIN_KERBEROS_OPERATION_SUPPORTED_CONTEXT_FLAGS) != 0u ||
        channel_binding_size > RIN_KERBEROS_PROVIDER_MAX_CHANNEL_BINDING_SIZE ||
        (channel_binding_size != 0u && channel_binding == NULL) ||
        token_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE ||
        (token_size != 0u && token == NULL))
        return 0u;
    total = (uint32_t)sizeof(header);
    if (target_name_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE - total ||
        channel_binding_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE - total ||
        token_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE - total)
        return 0u;
    total += target_name_size;
    if (channel_binding_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE - total)
        return 0u;
    total += channel_binding_size;
    if (token_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE - total)
        return 0u;
    total += token_size;
    bytes = (uint8_t*)calloc(1u, total);
    if (bytes == NULL) return 0u;
    header.struct_size = sizeof(header);
    header.version = RIN_KERBEROS_PROVIDER_INPUT_ABI_VERSION;
    header.kind = RIN_KERBEROS_PROVIDER_INPUT_SEC_CONTEXT;
    header.mechanism = mechanism;
    header.requested_flags = requested_flags;
    header.target_name_size = target_name_size;
    header.channel_binding_size = channel_binding_size;
    header.token_size = token_size;
    memcpy(bytes, &header, sizeof(header));
    total = (uint32_t)sizeof(header);
    if (target_name_size != 0u) {
        memcpy(bytes + total, target_name_bytes, target_name_size);
        total += target_name_size;
    }
    if (channel_binding_size != 0u) {
        memcpy(bytes + total, channel_binding, channel_binding_size);
        total += channel_binding_size;
    }
    if (token_size != 0u) {
        memcpy(bytes + total, token, token_size);
        total += token_size;
    }
    *output = bytes;
    *output_size = total;
    return 1u;
}

static uint32_t provider_operation(
    RinOsKerberosProviderCredential* credential,
    RinOsKerberosProviderContext* provider_context,
    RinKerberosOperationRequestV1* request, const uint8_t* input,
    uint32_t input_size, RinAuthProviderBufferV1* output,
    uint32_t update_context, uint32_t* return_flags,
    uint32_t* minor_status)
{
    const RinKerberosOperationOwnerV1* owner;
    uint8_t* operation_output = NULL;
    uint8_t next_context[RIN_KERBEROS_OPERATION_MAX_CONTEXT_TOKEN_SIZE];
    uint32_t operation_output_size = 0u;
    uint32_t next_context_size = 0u;
    uint64_t operation_generation = 0u;
    uint32_t provider_result = 0u;
    uint32_t operation_return_flags = 0u;
    uint32_t allowed_return_flags = 0u;
    uint32_t owner_minor_status = 0u;
    uint32_t status;
    const uint8_t* first_input = NULL;
    const uint8_t* second_input = NULL;
    uint32_t first_input_size = 0u;
    uint32_t second_input_size = 0u;

    memset(next_context, 0, sizeof(next_context));
    if (return_flags != NULL) *return_flags = 0u;
    if (minor_status != NULL) *minor_status = 0u;
    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    if (request == NULL ||
        !provider_credential_valid(credential, request->credential_kind) ||
        request->struct_size != sizeof(*request) ||
        request->version != RIN_KERBEROS_OPERATION_ABI_VERSION ||
        !provider_operation_valid(request->operation) ||
        request->input_size != input_size ||
        request->context_token_size >
            RIN_KERBEROS_OPERATION_MAX_CONTEXT_TOKEN_SIZE ||
        request->output_capacity >
            RIN_KERBEROS_OPERATION_MAX_OUTPUT_SIZE ||
        (request->flags & ~RIN_KERBEROS_OPERATION_KNOWN_FLAGS) != 0u ||
        ((request->operation != RIN_KERBEROS_OPERATION_WRAP &&
          request->operation != RIN_KERBEROS_OPERATION_UNWRAP) &&
         request->flags != 0u) ||
        input_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE ||
        (input_size != 0u && input == NULL))
        return RIN_AUTH_PROVIDER_UNAVAILABLE;
    owner = provider_context != NULL ? provider_context->owner
                                      : provider_operation_owner();
    if (owner == NULL || owner->operation == NULL)
        return RIN_AUTH_PROVIDER_UNAVAILABLE;
    if (provider_context != NULL) {
        if (!provider_context_valid(provider_context) ||
            provider_context->owner != owner ||
            provider_context->owner_credential !=
                credential->owner_credential ||
            provider_context->kind != request->credential_kind)
            return RIN_AUTH_PROVIDER_UNAVAILABLE;
        if ((request->operation == RIN_KERBEROS_OPERATION_WRAP ||
             request->operation == RIN_KERBEROS_OPERATION_UNWRAP ||
             request->operation == RIN_KERBEROS_OPERATION_GET_MIC ||
             request->operation == RIN_KERBEROS_OPERATION_VERIFY_MIC) &&
            provider_context->state != RINOS_KERBEROS_CONTEXT_ESTABLISHED)
            return RIN_AUTH_PROVIDER_UNAVAILABLE;
        request->context_token_size = provider_context->token_size;
    }
    if (request->operation == RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT ||
        request->operation == RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT) {
        int continuation = provider_context != NULL &&
                           provider_context->token_size != 0u;
        if (!provider_sec_context_token(input, input_size, &first_input,
                                        &first_input_size))
            return RIN_AUTH_PROVIDER_UNAVAILABLE;
        /* The initial initiator call legitimately has no input token. Every
         * accept call and every continuation call must carry a bounded GSS
         * wrapper; malformed framing is an RFC 2743 defective token. */
        if ((request->operation == RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT ||
             continuation) &&
            (first_input_size == 0u ||
             !provider_gss_token_has_framing(first_input, first_input_size))) {
            return provider_defective_token(NULL);
        }
    } else if (request->operation == RIN_KERBEROS_OPERATION_UNWRAP ||
               request->operation == RIN_KERBEROS_OPERATION_VERIFY_MIC) {
        if (!provider_message_pair(input, input_size, &first_input,
                                   &first_input_size, &second_input,
                                   &second_input_size))
            return RIN_AUTH_PROVIDER_UNAVAILABLE;
        /* These are only syntax checks.  A token with a valid header but a
         * bad checksum remains a provider/service integrity failure and is
         * never relabeled as defective framing here. */
        if (request->operation == RIN_KERBEROS_OPERATION_UNWRAP &&
            (first_input_size < 16u || first_input[0] != 0x05u ||
             first_input[1] != 0x04u))
            return provider_defective_token(NULL);
        if (request->operation == RIN_KERBEROS_OPERATION_VERIFY_MIC &&
            (second_input_size != 28u || second_input[0] != 0x04u ||
             second_input[1] != 0x04u))
            return provider_defective_token(NULL);
    }
    if (request->output_capacity != 0u) {
        /* Operation output is published through the provider buffer ABI on
         * success.  Use the same owned-capacity allocation as every other
         * public buffer so error cleanup and release cannot interpret a raw
         * calloc pointer as a provider allocation header. */
        operation_output = provider_buffer_alloc(request->output_capacity);
        if (operation_output == NULL) return RIN_AUTH_PROVIDER_UNAVAILABLE;
    }
    status = owner->operation(
        owner->context, &owner_minor_status, credential->owner_credential,
        request,
        provider_context != NULL ? provider_context->token : NULL,
        provider_context != NULL ? provider_context->token_size : 0u, input,
        input_size, operation_output, request->output_capacity,
        &operation_output_size, next_context, sizeof(next_context),
        &next_context_size, &operation_generation, &provider_result,
        &operation_return_flags);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK) {
        if (operation_output != NULL) {
            provider_zero(operation_output, request->output_capacity);
            provider_buffer_dispose(operation_output);
        }
        provider_zero(next_context, sizeof(next_context));
        /* Preserve the owner-defined GSS-relevant failure classification.
         * The owner is the authority for ticket/context lifetime and channel
         * bindings; collapsing these values to UNAVAILABLE would hide a
         * real protocol result from the PAL. */
        return provider_status_from_owner(status, minor_status);
    }
    /* DELETE_SEC_CONTEXT is the one operation whose successful response does
     * not publish a live context generation.  The owner ABI deliberately
     * returns generation zero after it has discarded the remote context;
     * every other operation must remain generation-bound.  Treating delete
     * like an ordinary context operation leaves the local handle retryable
     * forever against the real keyring owner. */
    if (owner_minor_status != 0u ||
        provider_result > RIN_KERBEROS_OPERATION_RESULT_ERROR ||
        (request->operation != RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT &&
         operation_generation == 0u) ||
        operation_output_size > request->output_capacity ||
        next_context_size > sizeof(next_context) ||
        (operation_output_size != 0u && output == NULL) ||
        (!update_context && next_context_size != 0u) ||
        (update_context && provider_context == NULL) ||
        (provider_result == RIN_KERBEROS_OPERATION_RESULT_CONTINUE_NEEDED &&
         request->operation != RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT &&
         request->operation != RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT) ||
        ((request->operation == RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT &&
          (provider_result == RIN_KERBEROS_OPERATION_RESULT_COMPLETE ||
           provider_result == RIN_KERBEROS_OPERATION_RESULT_CONTINUE_NEEDED)) &&
         next_context_size == 0u) ||
        (request->operation == RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT &&
         provider_result == RIN_KERBEROS_OPERATION_RESULT_COMPLETE &&
         next_context_size == 0u) ||
        (provider_result == RIN_KERBEROS_OPERATION_RESULT_ERROR &&
         ((request->operation != RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT &&
           request->operation != RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT) ||
          operation_output_size == 0u || next_context_size != 0u ||
          (operation_return_flags &
           ~RIN_KERBEROS_OPERATION_RETURN_FLAG_EXTENDED_ERROR) != 0u)) ||
        (request->operation == RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT &&
         (operation_generation != 0u || operation_output_size != 0u ||
          next_context_size != 0u || operation_return_flags != 0u)) ||
         /* The keyring response generation is the credential-record
          * generation for every non-delete operation.  Once a context has
          * published a generation, accepting a response from another
          * generation would mix an old opaque context token with a refreshed
          * session credential.  DELETE is intentionally generation-zero and
          * is validated by the separate branch above. */
         (request->operation != RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT &&
          provider_context != NULL && provider_context->generation != 0u &&
          operation_generation != provider_context->generation) ||
        (operation_return_flags &
         ~RIN_KERBEROS_OPERATION_KNOWN_RETURN_FLAGS) != 0u) {
        if (operation_output != NULL) {
            provider_zero(operation_output, request->output_capacity);
            provider_buffer_dispose(operation_output);
        }
        provider_zero(next_context, sizeof(next_context));
        return RIN_AUTH_PROVIDER_UNAVAILABLE;
    }
    /* The wider GSS flag namespace is not the same as the flags this RinOS
     * provider can safely carry.  In particular, delegation/identity/anon
     * need a session policy and owner lifecycle that are not part of the
     * current operation ABI.  Reject an owner which advertises them instead
     * of exposing a capability that the managed PAL cannot honor.  The
     * extended-error bit is meaningful only on a KRB-ERROR response. */
    if (request->operation == RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT ||
        request->operation == RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT) {
        allowed_return_flags = RIN_KERBEROS_OPERATION_SUPPORTED_CONTEXT_FLAGS;
        if (provider_result == RIN_KERBEROS_OPERATION_RESULT_ERROR)
            allowed_return_flags |=
                RIN_KERBEROS_OPERATION_RETURN_FLAG_EXTENDED_ERROR;
    }
    if ((operation_return_flags & ~allowed_return_flags) != 0u) {
        if (operation_output != NULL) {
            provider_zero(operation_output, request->output_capacity);
            provider_buffer_dispose(operation_output);
        }
        provider_zero(next_context, sizeof(next_context));
        return RIN_AUTH_PROVIDER_UNAVAILABLE;
    }
    if (provider_result == RIN_KERBEROS_OPERATION_RESULT_ERROR) {
        uint32_t error_code = 0u;
        if (provider_gss_krb_error(operation_output, operation_output_size,
                                   &error_code) != 1) {
            if (operation_output != NULL) {
                provider_zero(operation_output, request->output_capacity);
                provider_buffer_dispose(operation_output);
            }
            provider_zero(next_context, sizeof(next_context));
            return provider_unavailable(minor_status);
        }
        if (minor_status != NULL)
            *minor_status = RIN_KERBEROS_OPERATION_MINOR_PROTOCOL_ERROR |
                            error_code;
    }
    if (provider_context != NULL &&
        provider_result != RIN_KERBEROS_OPERATION_RESULT_ERROR &&
        (request->operation == RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT ||
         request->operation == RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT)) {
        /* A failed continuation may still leave the owner-side context live.
         * Do not replace its generation/token with the empty error response:
         * the PAL must be able to delete the previous opaque context after a
         * KRB-ERROR, and a caller may retry the same continuation.  Message
         * protection and identity operations have no next context token; they
         * must retain the token that authenticated the current context. */
        if (request->operation != RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT &&
            provider_context->generation != 0u &&
            provider_context->generation != operation_generation) {
            if (operation_output != NULL) {
                provider_zero(operation_output, request->output_capacity);
                provider_buffer_dispose(operation_output);
            }
            provider_zero(next_context, sizeof(next_context));
            return RIN_AUTH_PROVIDER_UNAVAILABLE;
        }
        provider_context->generation = operation_generation;
        provider_context->token_size = next_context_size;
        provider_zero(provider_context->token, sizeof(provider_context->token));
        if (next_context_size != 0u)
            memcpy(provider_context->token, next_context, next_context_size);
        if (request->operation == RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT ||
            request->operation == RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT) {
            provider_context->state =
                provider_result == RIN_KERBEROS_OPERATION_RESULT_COMPLETE
                    ? RINOS_KERBEROS_CONTEXT_ESTABLISHED
                    : RINOS_KERBEROS_CONTEXT_NEGOTIATING;
        }
    }
    if (output != NULL && operation_output_size != 0u) {
        output->data = operation_output;
        output->length = operation_output_size;
    } else if (operation_output != NULL) {
        provider_zero(operation_output, request->output_capacity);
        provider_buffer_dispose(operation_output);
    }
    if (return_flags != NULL) *return_flags = operation_return_flags;
    provider_zero(next_context, sizeof(next_context));
    if (provider_result == RIN_KERBEROS_OPERATION_RESULT_ERROR)
        return RIN_AUTH_PROVIDER_KRB_ERROR;
    return provider_result == RIN_KERBEROS_OPERATION_RESULT_CONTINUE_NEEDED
               ? RIN_AUTH_PROVIDER_CONTINUE_NEEDED
               : RIN_AUTH_PROVIDER_OK;
}

/* Reacquire the current authenticated live-session handle after the owner
 * reports that the old generation has expired.  This is deliberately a
 * generation refresh of an opaque keyring record, not a KDC login, TGT
 * renewal, or locally manufactured credential.  The owner remains the only
 * authority allowed to select the session credential. */
static uint32_t provider_refresh_initiator_credential(
    RinOsKerberosProviderCredential* credential,
    RinOsKerberosProviderContext* provider_context, uint32_t* minor_status)
{
    const RinKerberosCredentialOwnerV1* owner;
    void* replacement = NULL;
    void* old_credential;
    uint32_t status;
    uint32_t cleanup_minor = 0u;
    uint32_t replacement_minor = 0u;
    uint32_t replacement_principal_size = 0u;
    uint32_t current_principal_size = 0u;
    uint64_t current_generation = 0u;
    uint64_t replacement_generation = 0u;
    int replacement_identity_matches = 0;
    uint8_t current_principal[RINOS_KERBEROS_MAX_PRINCIPAL_SIZE] = {0};
    uint8_t replacement_principal[RINOS_KERBEROS_MAX_PRINCIPAL_SIZE] = {0};

    if (minor_status != NULL) *minor_status = 0u;
    if (credential == NULL || provider_context == NULL ||
        !provider_credential_valid(
            credential, RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR) ||
        !provider_context_valid(provider_context) ||
        provider_context->kind !=
            RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR ||
        provider_context->owner_credential != credential->owner_credential)
        return provider_unavailable(minor_status);
    owner = credential->owner;
    if (owner == NULL || owner->acquire_session_initiator == NULL ||
        owner->release_credential == NULL)
        return provider_unavailable(minor_status);

    status = provider_release_pending_credential(credential, &cleanup_minor);
    /* Do not continue a refresh after a failed pending-handle cleanup.  A
     * provider-owned opaque capability may have been consumed even when the
     * owner reports an error, so treating a NULL pending slot as success
     * would allow a stale refresh path to proceed. */
    if (status != RIN_AUTH_PROVIDER_OK)
        return status;

    /* Capture the generation of the handle that actually produced the
     * expiry.  The first initial operation can fail before the operation
     * response publishes a generation, so provider_context->generation alone
     * is not sufficient for the comparison below. */
    status = owner->get_session_principal(
        owner->context, &replacement_minor, credential->owner_credential,
        current_principal, sizeof(current_principal),
        &current_principal_size, &current_generation);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK ||
        replacement_minor != 0u || current_principal_size == 0u ||
        current_principal_size > sizeof(current_principal) ||
        current_generation == 0u ||
        (provider_context->generation != 0u &&
         provider_context->generation != current_generation)) {
        provider_zero(current_principal, sizeof(current_principal));
        provider_zero(replacement_principal, sizeof(replacement_principal));
        return status == RIN_KERBEROS_CREDENTIAL_OWNER_OK
                   ? provider_unavailable(minor_status)
                   : provider_status_from_owner(status, minor_status);
    }

    status = owner->acquire_session_initiator(
        owner->context, minor_status, NULL, &replacement);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK || replacement == NULL) {
        /* A failed acquire may still return an owner handle.  Do not leak or
         * adopt it, and preserve the acquire failure as the visible result. */
        if (replacement != NULL) {
            (void)owner->release_credential(
                owner->context, &cleanup_minor, &replacement);
            if (replacement != NULL)
                credential->pending_release_credential = replacement;
        }
        provider_zero(current_principal, sizeof(current_principal));
        provider_zero(replacement_principal, sizeof(replacement_principal));
        return status == RIN_KERBEROS_CREDENTIAL_OWNER_OK
                   ? provider_unavailable(minor_status)
                   : provider_status_from_owner(status, minor_status);
    }

    /* Re-acquisition is not a refresh by itself.  The owner may legally
     * return a new opaque capability for the same still-expired ccache
     * generation; accepting that capability would make a stale session
     * credential look like a successful ticket refresh.  Query only the
     * bounded non-secret principal metadata and require both an exact
     * principal match and a newer generation before replacing the old handle.
     * The principal bytes never leave this function and are scrubbed before
     * any branch returns. */
    status = owner->get_session_principal(
        owner->context, &replacement_minor, replacement,
        replacement_principal, sizeof(replacement_principal),
        &replacement_principal_size, &replacement_generation);
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_OK &&
        replacement_minor == 0u && replacement_principal_size != 0u &&
        replacement_principal_size <= sizeof(replacement_principal) &&
        replacement_generation != 0u) {
        replacement_identity_matches =
            replacement_principal_size == current_principal_size &&
            memcmp(replacement_principal, current_principal,
                   current_principal_size) == 0;
    }
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK ||
        replacement_minor != 0u || replacement_principal_size == 0u ||
        replacement_principal_size > sizeof(replacement_principal) ||
        replacement_generation == 0u ||
        replacement_generation == current_generation ||
        !replacement_identity_matches) {
        const uint32_t release_status = owner->release_credential(
            owner->context, &cleanup_minor, &replacement);
        if (replacement != NULL)
            credential->pending_release_credential = replacement;
        provider_zero(current_principal, sizeof(current_principal));
        provider_zero(replacement_principal, sizeof(replacement_principal));
        if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK)
            return provider_status_from_owner(status, minor_status);
        if (release_status != RIN_KERBEROS_CREDENTIAL_OWNER_OK ||
            replacement != NULL)
            return provider_unavailable(minor_status);
        if (!replacement_identity_matches)
            return provider_unavailable(minor_status);
        /* The authenticated owner still exposes the old generation.  Do not
         * replay the initial token against it; surface the real expiry. */
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_CREDENTIALS_EXPIRED;
    }

    old_credential = credential->owner_credential;
    provider_zero(current_principal, sizeof(current_principal));
    provider_zero(replacement_principal, sizeof(replacement_principal));
    status = owner->release_credential(
        owner->context, minor_status, &old_credential);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK ||
        old_credential != NULL) {
        /* Keep the old handle when the owner can still expose it.  If the
         * owner consumed it while reporting failure, invalidate both wrapper
         * objects rather than leaving a stale context reachable. */
        (void)owner->release_credential(
            owner->context, &cleanup_minor, &replacement);
        if (replacement != NULL)
            credential->pending_release_credential = replacement;
        if (old_credential == NULL) {
            credential->owner_credential = NULL;
            provider_context->owner_credential = NULL;
        }
        return status != RIN_KERBEROS_CREDENTIAL_OWNER_OK
                   ? provider_status_from_owner(status, minor_status)
                   : provider_unavailable(minor_status);
    }

    credential->owner_credential = replacement;
    provider_context->owner_credential = replacement;
    provider_context->generation = replacement_generation;
    if (minor_status != NULL) *minor_status = 0u;
    return RIN_AUTH_PROVIDER_OK;
}

static uint32_t provider_init_sec_context(
    void* context, uint32_t* minor_status, void* claimant_cred,
    void** security_context, uint32_t package_type, void* target_name,
    uint32_t requested_flags, uint8_t* input, uint32_t input_length,
    RinAuthProviderBufferV1* output, uint32_t* return_flags,
    int32_t* ntlm_used)
{
    RinOsKerberosProviderCredential* credential =
        (RinOsKerberosProviderCredential*)claimant_cred;
    RinOsKerberosProviderName* name =
        (RinOsKerberosProviderName*)target_name;
    RinOsKerberosProviderContext* provider_context;
    RinOsKerberosProviderContext* existing_context;
    uint8_t* operation_input = NULL;
    uint32_t operation_input_size = 0u;
    RinKerberosOperationRequestV1 request = {0};
    uint32_t status;
    uint32_t mechanism;
    int created_context = 0;
    uint32_t received_error_code = 0u;
    int received_error;
    ProviderSpnegoInputV1 spnego_input = {0};
    const uint8_t* mechanism_input = input;
    uint32_t mechanism_input_length = input_length;
    int spnego_mode = 0;
    int spnego_parse_status;
    int spnego_final_ack = 0;
    RinAuthProviderBufferV1 mic_output = {0};
    int generate_spnego_mic = 0;
    (void)context;
    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    if (return_flags != NULL) *return_flags = 0u;
    if (ntlm_used != NULL) *ntlm_used = 0;
    if (security_context == NULL || output == NULL || return_flags == NULL ||
        ntlm_used == NULL || !provider_name_valid(name) ||
        (package_type != PAL_GSS_NEGOTIATE &&
         package_type != PAL_GSS_KERBEROS) ||
        !provider_credential_valid(credential,
                                   RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR))
        return provider_unavailable(minor_status);
    if (input_length != 0u && package_type != PAL_GSS_NEGOTIATE) {
        received_error = provider_gss_krb_error(
            input, input_length, &received_error_code);
        if (received_error < 0) return provider_defective_token(minor_status);
        if (received_error > 0) {
            if (minor_status != NULL)
                *minor_status = RIN_KERBEROS_OPERATION_MINOR_PROTOCOL_ERROR |
                                received_error_code;
            return RIN_AUTH_PROVIDER_KRB_ERROR;
        }
    }
    existing_context = (RinOsKerberosProviderContext*)*security_context;
    if (existing_context != NULL) {
        if (!provider_context_valid(existing_context) ||
            existing_context->kind !=
                RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR ||
            existing_context->owner_credential != credential->owner_credential)
            return provider_unavailable(minor_status);
        provider_context = existing_context;
        spnego_mode = provider_context->spnego != 0u;
    } else {
        *security_context = NULL;
        provider_context = (RinOsKerberosProviderContext*)calloc(
            1u, sizeof(*provider_context));
        if (provider_context == NULL)
            return provider_unavailable(minor_status);
        provider_context->magic = RINOS_KERBEROS_CONTEXT_MAGIC;
        provider_context->kind = RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR;
        provider_context->state = RINOS_KERBEROS_CONTEXT_NEGOTIATING;
        provider_context->owner_credential = credential->owner_credential;
        provider_context->owner = provider_operation_owner();
        provider_context->credential = credential;
        provider_context->spnego = package_type == PAL_GSS_NEGOTIATE;
        spnego_mode = provider_context->spnego != 0u;
        if (spnego_mode && !provider_spnego_store_default_mech_list(
                               provider_context)) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
            return provider_unavailable(minor_status);
        }
        created_context = 1;
    }
    if (spnego_mode && input_length != 0u) {
        spnego_parse_status = provider_spnego_unwrap(
            input, input_length, &spnego_input);
        if (spnego_parse_status != 1) {
            if (created_context) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
            }
            return spnego_parse_status == 0
                ? provider_defective_token(minor_status)
                : provider_unavailable(minor_status);
        }
        if (!spnego_input.has_mechanism_token) {
            /* After the initiator has returned its MIC, RFC 4178 permits the
             * target to finish with NegTokenResp.negState=accept-completed
             * and no responseToken.  It carries no new mechanism input and
             * must not be forwarded to the Kerberos owner as an empty GSS
             * continuation. */
            if (created_context || !provider_context->spnego_mic_required ||
                !provider_context->spnego_mic_sent ||
                spnego_input.has_mechanism_mic ||
                (spnego_input.has_neg_state &&
                 spnego_input.neg_state != 0u)) {
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_defective_token(minor_status);
            }
            provider_context->spnego_mic_required = 0u;
            provider_context->spnego_mic_sent = 0u;
            spnego_final_ack = 1;
        } else {
            if (spnego_input.has_neg_state && spnego_input.neg_state == 3u &&
                provider_context->spnego_response_seen) {
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_defective_token(minor_status);
            }
            if (spnego_input.has_neg_state && spnego_input.neg_state == 3u &&
                !spnego_input.has_mechanism_mic) {
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_defective_token(minor_status);
            }
            provider_context->spnego_response_seen = 1u;
            if (spnego_input.has_neg_state && spnego_input.neg_state == 3u)
                provider_context->spnego_mic_required = 1u;
            if (spnego_input.mech_list_size != 0u &&
                !provider_spnego_store_mech_list(provider_context,
                                                 &spnego_input)) {
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_defective_token(minor_status);
            }
            mechanism_input = spnego_input.mechanism_token;
            mechanism_input_length = spnego_input.mechanism_token_size;
        }
        if (spnego_final_ack) {
            if (created_context &&
                !provider_context_retain(credential, provider_context)) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
                return provider_unavailable(minor_status);
            }
            *security_context = provider_context;
            if (minor_status != NULL) *minor_status = 0u;
            return RIN_AUTH_PROVIDER_OK;
        }
    }
    /* PackageType.Negotiate selects the SPNEGO envelope, while the only
     * mechanism this provider can execute is the authenticated Kerberos
     * operation owner.  Do not claim NTLM or silently treat SPNEGO bytes as
     * Kerberos bytes. */
    mechanism = package_type == PAL_GSS_NEGOTIATE
                    ? PAL_GSS_KERBEROS
                    : package_type;
    if (provider_context->owner == NULL ||
        !provider_build_sec_context_input(
            mechanism, requested_flags, name, NULL, 0u, mechanism_input,
            mechanism_input_length, &operation_input, &operation_input_size)) {
        if (operation_input != NULL) {
            provider_zero(operation_input, operation_input_size);
            free(operation_input);
        }
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return provider_unavailable(minor_status);
    }
    request.struct_size = sizeof(request);
    request.version = RIN_KERBEROS_OPERATION_ABI_VERSION;
    request.operation = RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT;
    request.credential_kind = RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR;
    request.input_size = operation_input_size;
    request.output_capacity = RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE;
    status = provider_operation(credential, provider_context, &request,
                                operation_input, operation_input_size, output,
                                1u, return_flags, minor_status);
    if (status == RIN_AUTH_PROVIDER_CREDENTIALS_EXPIRED &&
        provider_context->state == RINOS_KERBEROS_CONTEXT_NEGOTIATING &&
        provider_context->token_size == 0u && mechanism_input_length == 0u &&
        provider_refresh_initiator_credential(
            credential, provider_context, minor_status) ==
            RIN_AUTH_PROVIDER_OK) {
        /* Retry exactly one empty-input initial leg with the newly acquired
         * live-session generation.  Continuations are never replayed. */
        if (operation_input != NULL) {
            provider_zero(operation_input, operation_input_size);
            free(operation_input);
            operation_input = NULL;
            operation_input_size = 0u;
        }
        if (!provider_build_sec_context_input(
                mechanism, requested_flags, name, NULL, 0u,
                mechanism_input, mechanism_input_length, &operation_input,
                &operation_input_size)) {
            status = provider_unavailable(minor_status);
        } else {
            request.input_size = operation_input_size;
            status = provider_operation(
                credential, provider_context, &request, operation_input,
                operation_input_size, output, 1u, return_flags, minor_status);
        }
    }
    if (operation_input != NULL) {
        provider_zero(operation_input, operation_input_size);
        free(operation_input);
    }
    if (spnego_mode && spnego_input.has_mechanism_mic) {
        uint32_t mic_status;
        if (status != RIN_AUTH_PROVIDER_OK ||
            provider_context->mech_list_size == 0u) {
            mic_status = provider_unavailable(minor_status);
        } else {
            mic_status = provider_verify_mic_bytes(
                context, minor_status, provider_context,
                provider_context->mech_list,
                (int32_t)provider_context->mech_list_size,
                spnego_input.mechanism_mic,
                (int32_t)spnego_input.mechanism_mic_size);
        }
        if (mic_status != RIN_AUTH_PROVIDER_OK) {
            if (output->data != NULL) {
                provider_zero(output->data, (size_t)output->length);
                provider_buffer_dispose(output->data);
                output->data = NULL;
                output->length = 0u;
            }
            if (created_context) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
            }
            return mic_status;
        }
    }
    if (spnego_mode && spnego_input.has_neg_state &&
        spnego_input.neg_state == 3u && status == RIN_AUTH_PROVIDER_OK &&
        ((*return_flags & RIN_KERBEROS_OPERATION_RETURN_FLAG_INTEGRITY) != 0u)) {
        if (provider_context->mech_list_size == 0u ||
            provider_get_mic(context, minor_status, provider_context,
                             provider_context->mech_list,
                             (int32_t)provider_context->mech_list_size,
                             &mic_output) != RIN_AUTH_PROVIDER_OK ||
            !provider_spnego_mic_is_valid(mic_output.data,
                                          (uint32_t)mic_output.length)) {
            if (mic_output.data != NULL) {
                provider_zero(mic_output.data, (size_t)mic_output.length);
                provider_buffer_dispose(mic_output.data);
            }
            if (output->data != NULL) {
                provider_zero(output->data, (size_t)output->length);
                provider_buffer_dispose(output->data);
                output->data = NULL;
                output->length = 0u;
            }
            if (created_context) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
            }
            return provider_unavailable(minor_status);
        }
        generate_spnego_mic = 1;
    }
    if (spnego_mode &&
        (status == RIN_AUTH_PROVIDER_OK ||
         status == RIN_AUTH_PROVIDER_CONTINUE_NEEDED ||
         status == RIN_AUTH_PROVIDER_KRB_ERROR) &&
        !provider_spnego_replace_output(
            output, status, created_context ? 1u : 0u, 1u, 0u,
            UINT32_MAX,
            generate_spnego_mic ? (const uint8_t*)mic_output.data : NULL,
            generate_spnego_mic ? (uint32_t)mic_output.length : 0u)) {
        if (mic_output.data != NULL) {
            provider_zero(mic_output.data, (size_t)mic_output.length);
            provider_buffer_dispose(mic_output.data);
        }
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return provider_unavailable(minor_status);
    }
    if (generate_spnego_mic)
        provider_context->spnego_mic_sent = 1u;
    if (mic_output.data != NULL) {
        provider_zero(mic_output.data, (size_t)mic_output.length);
        provider_buffer_dispose(mic_output.data);
    }
    if (status != RIN_AUTH_PROVIDER_OK &&
        status != RIN_AUTH_PROVIDER_CONTINUE_NEEDED) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        /* Keep an already-published context live for the PAL cleanup path on
         * a mechanism error.  The owner operation above deliberately kept
         * its previous generation/token rather than accepting the empty error
         * response as a new context state. */
        return status;
    }
    if (created_context &&
        !provider_context_retain(credential, provider_context)) {
        provider_zero(provider_context, sizeof(*provider_context));
        free(provider_context);
        *security_context = NULL;
        return provider_unavailable(minor_status);
    }
    *security_context = provider_context;
    if (minor_status != NULL) *minor_status = 0u;
    return status;
}

static uint32_t provider_init_sec_context_ex(
    void* context, uint32_t* minor_status, void* claimant_cred,
    void** security_context, uint32_t package_type, void* channel_binding,
    int32_t channel_binding_size, void* target_name, uint32_t requested_flags,
    uint8_t* input, uint32_t input_length, RinAuthProviderBufferV1* output,
    uint32_t* return_flags, int32_t* ntlm_used)
{
    RinOsKerberosProviderCredential* credential =
        (RinOsKerberosProviderCredential*)claimant_cred;
    RinOsKerberosProviderName* name =
        (RinOsKerberosProviderName*)target_name;
    RinOsKerberosProviderContext* provider_context;
    RinOsKerberosProviderContext* existing_context;
    uint8_t* operation_input = NULL;
    uint32_t operation_input_size = 0u;
    RinKerberosOperationRequestV1 request = {0};
    uint32_t status;
    uint32_t mechanism;
    int created_context = 0;
    uint32_t received_error_code = 0u;
    int received_error;
    ProviderSpnegoInputV1 spnego_input = {0};
    const uint8_t* mechanism_input = input;
    uint32_t mechanism_input_length = input_length;
    int spnego_mode = 0;
    int spnego_parse_status;
    int spnego_final_ack = 0;
    RinAuthProviderBufferV1 mic_output = {0};
    int generate_spnego_mic = 0;
    (void)context;
    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    if (return_flags != NULL) *return_flags = 0u;
    if (ntlm_used != NULL) *ntlm_used = 0;
    if (security_context == NULL || output == NULL || return_flags == NULL ||
        ntlm_used == NULL || channel_binding_size < 0 ||
        !provider_name_valid(name) ||
        (package_type != PAL_GSS_NEGOTIATE &&
         package_type != PAL_GSS_KERBEROS) ||
        !provider_credential_valid(credential,
                                   RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR))
        return provider_unavailable(minor_status);
    if (input_length != 0u && package_type != PAL_GSS_NEGOTIATE) {
        received_error = provider_gss_krb_error(
            input, input_length, &received_error_code);
        if (received_error < 0) return provider_defective_token(minor_status);
        if (received_error > 0) {
            if (minor_status != NULL)
                *minor_status = RIN_KERBEROS_OPERATION_MINOR_PROTOCOL_ERROR |
                                received_error_code;
            return RIN_AUTH_PROVIDER_KRB_ERROR;
        }
    }
    existing_context = (RinOsKerberosProviderContext*)*security_context;
    if (existing_context != NULL) {
        if (!provider_context_valid(existing_context) ||
            existing_context->kind !=
                RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR ||
            existing_context->owner_credential != credential->owner_credential)
            return provider_unavailable(minor_status);
        provider_context = existing_context;
        spnego_mode = provider_context->spnego != 0u;
    } else {
        *security_context = NULL;
        provider_context = (RinOsKerberosProviderContext*)calloc(
            1u, sizeof(*provider_context));
        if (provider_context == NULL)
            return provider_unavailable(minor_status);
        provider_context->magic = RINOS_KERBEROS_CONTEXT_MAGIC;
        provider_context->kind = RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR;
        provider_context->state = RINOS_KERBEROS_CONTEXT_NEGOTIATING;
        provider_context->owner_credential = credential->owner_credential;
        provider_context->owner = provider_operation_owner();
        provider_context->credential = credential;
        provider_context->spnego = package_type == PAL_GSS_NEGOTIATE;
        spnego_mode = provider_context->spnego != 0u;
        if (spnego_mode && !provider_spnego_store_default_mech_list(
                               provider_context)) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
            return provider_unavailable(minor_status);
        }
        created_context = 1;
    }
    if (spnego_mode && input_length != 0u) {
        spnego_parse_status = provider_spnego_unwrap(
            input, input_length, &spnego_input);
        if (spnego_parse_status != 1) {
            if (created_context) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
            }
            return spnego_parse_status == 0
                ? provider_defective_token(minor_status)
                : provider_unavailable(minor_status);
        }
        if (!spnego_input.has_mechanism_token) {
            if (created_context || !provider_context->spnego_mic_required ||
                !provider_context->spnego_mic_sent ||
                spnego_input.has_mechanism_mic ||
                (spnego_input.has_neg_state &&
                 spnego_input.neg_state != 0u)) {
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_defective_token(minor_status);
            }
            provider_context->spnego_mic_required = 0u;
            provider_context->spnego_mic_sent = 0u;
            spnego_final_ack = 1;
        } else {
            if (spnego_input.has_neg_state && spnego_input.neg_state == 3u &&
                provider_context->spnego_response_seen) {
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_defective_token(minor_status);
            }
            if (spnego_input.has_neg_state && spnego_input.neg_state == 3u &&
                !spnego_input.has_mechanism_mic) {
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_defective_token(minor_status);
            }
            provider_context->spnego_response_seen = 1u;
            if (spnego_input.has_neg_state && spnego_input.neg_state == 3u)
                provider_context->spnego_mic_required = 1u;
            if (spnego_input.mech_list_size != 0u &&
                !provider_spnego_store_mech_list(provider_context,
                                                 &spnego_input)) {
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_defective_token(minor_status);
            }
            mechanism_input = spnego_input.mechanism_token;
            mechanism_input_length = spnego_input.mechanism_token_size;
        }
        if (spnego_final_ack) {
            if (created_context &&
                !provider_context_retain(credential, provider_context)) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
                return provider_unavailable(minor_status);
            }
            *security_context = provider_context;
            if (minor_status != NULL) *minor_status = 0u;
            return RIN_AUTH_PROVIDER_OK;
        }
    }
    mechanism = package_type == PAL_GSS_NEGOTIATE
                    ? PAL_GSS_KERBEROS
                    : package_type;
    if (provider_context->owner == NULL ||
        !provider_build_sec_context_input(
            mechanism, requested_flags, name, channel_binding,
            (uint32_t)channel_binding_size, mechanism_input,
            mechanism_input_length,
            &operation_input, &operation_input_size)) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return provider_unavailable(minor_status);
    }
    request.struct_size = sizeof(request);
    request.version = RIN_KERBEROS_OPERATION_ABI_VERSION;
    request.operation = RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT;
    request.credential_kind = RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR;
    request.input_size = operation_input_size;
    request.output_capacity = RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE;
    status = provider_operation(credential, provider_context, &request,
                                operation_input, operation_input_size, output,
                                1u, return_flags, minor_status);
    if (status == RIN_AUTH_PROVIDER_CREDENTIALS_EXPIRED &&
        provider_context->state == RINOS_KERBEROS_CONTEXT_NEGOTIATING &&
        provider_context->token_size == 0u && mechanism_input_length == 0u &&
        provider_refresh_initiator_credential(
            credential, provider_context, minor_status) ==
            RIN_AUTH_PROVIDER_OK) {
        /* Channel binding does not change the retry rule: only an empty
         * initial leg may be replayed, and it must be rebuilt with the same
         * caller-supplied binding after the authenticated session owner
         * returns a replacement opaque handle.  Never replay a continuation
         * or manufacture a credential from the binding bytes. */
        if (operation_input != NULL) {
            provider_zero(operation_input, operation_input_size);
            free(operation_input);
            operation_input = NULL;
            operation_input_size = 0u;
        }
        if (!provider_build_sec_context_input(
                mechanism, requested_flags, name, channel_binding,
                (uint32_t)channel_binding_size, mechanism_input,
                mechanism_input_length, &operation_input,
                &operation_input_size)) {
            status = provider_unavailable(minor_status);
        } else {
            request.input_size = operation_input_size;
            status = provider_operation(
                credential, provider_context, &request, operation_input,
                operation_input_size, output, 1u, return_flags,
                minor_status);
        }
    }
    provider_zero(operation_input, operation_input_size);
    free(operation_input);
    if (spnego_mode && spnego_input.has_mechanism_mic) {
        uint32_t mic_status;
        if (status != RIN_AUTH_PROVIDER_OK ||
            provider_context->mech_list_size == 0u) {
            mic_status = provider_unavailable(minor_status);
        } else {
            mic_status = provider_verify_mic_bytes(
                context, minor_status, provider_context,
                provider_context->mech_list,
                (int32_t)provider_context->mech_list_size,
                spnego_input.mechanism_mic,
                (int32_t)spnego_input.mechanism_mic_size);
        }
        if (mic_status != RIN_AUTH_PROVIDER_OK) {
            if (output->data != NULL) {
                provider_zero(output->data, (size_t)output->length);
                provider_buffer_dispose(output->data);
                output->data = NULL;
                output->length = 0u;
            }
            if (created_context) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
            }
            return mic_status;
        }
    }
    if (spnego_mode && spnego_input.has_neg_state &&
        spnego_input.neg_state == 3u && status == RIN_AUTH_PROVIDER_OK &&
        ((*return_flags & RIN_KERBEROS_OPERATION_RETURN_FLAG_INTEGRITY) != 0u)) {
        if (provider_context->mech_list_size == 0u ||
            provider_get_mic(context, minor_status, provider_context,
                             provider_context->mech_list,
                             (int32_t)provider_context->mech_list_size,
                             &mic_output) != RIN_AUTH_PROVIDER_OK ||
            !provider_spnego_mic_is_valid(mic_output.data,
                                          (uint32_t)mic_output.length)) {
            if (mic_output.data != NULL) {
                provider_zero(mic_output.data, (size_t)mic_output.length);
                provider_buffer_dispose(mic_output.data);
            }
            if (output->data != NULL) {
                provider_zero(output->data, (size_t)output->length);
                provider_buffer_dispose(output->data);
                output->data = NULL;
                output->length = 0u;
            }
            if (created_context) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
            }
            return provider_unavailable(minor_status);
        }
        generate_spnego_mic = 1;
    }
    if (spnego_mode &&
        (status == RIN_AUTH_PROVIDER_OK ||
         status == RIN_AUTH_PROVIDER_CONTINUE_NEEDED ||
         status == RIN_AUTH_PROVIDER_KRB_ERROR) &&
        !provider_spnego_replace_output(
            output, status, created_context ? 1u : 0u, 1u, 0u,
            UINT32_MAX,
            generate_spnego_mic ? (const uint8_t*)mic_output.data : NULL,
            generate_spnego_mic ? (uint32_t)mic_output.length : 0u)) {
        if (mic_output.data != NULL) {
            provider_zero(mic_output.data, (size_t)mic_output.length);
            provider_buffer_dispose(mic_output.data);
        }
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return provider_unavailable(minor_status);
    }
    if (generate_spnego_mic)
        provider_context->spnego_mic_sent = 1u;
    if (mic_output.data != NULL) {
        provider_zero(mic_output.data, (size_t)mic_output.length);
        provider_buffer_dispose(mic_output.data);
    }
    if (status != RIN_AUTH_PROVIDER_OK &&
        status != RIN_AUTH_PROVIDER_CONTINUE_NEEDED) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        /* Preserve an existing owner context on a mechanism error so the
         * PAL can issue DELETE_SEC_CONTEXT with the prior opaque token. */
        return status;
    }
    if (created_context &&
        !provider_context_retain(credential, provider_context)) {
        provider_zero(provider_context, sizeof(*provider_context));
        free(provider_context);
        *security_context = NULL;
        return provider_unavailable(minor_status);
    }
    *security_context = provider_context;
    if (minor_status != NULL) *minor_status = 0u;
    return status;
}

static uint32_t provider_accept_sec_context(
    void* context, uint32_t* minor_status, void* acceptor_cred,
    void** security_context, void* channel_binding, int32_t channel_binding_size,
    uint8_t* input, uint32_t input_length, RinAuthProviderBufferV1* output,
    uint32_t* return_flags, int32_t* ntlm_used)
{
    RinOsKerberosProviderCredential* credential =
        (RinOsKerberosProviderCredential*)acceptor_cred;
    RinOsKerberosProviderContext* provider_context;
    RinOsKerberosProviderContext* existing_context;
    uint8_t* operation_input = NULL;
    uint32_t operation_input_size = 0u;
    RinKerberosOperationRequestV1 request = {0};
    uint32_t status;
    int created_context = 0;
    ProviderSpnegoInputV1 spnego_input = {0};
    const uint8_t* mechanism_input = input;
    uint32_t mechanism_input_length = input_length;
    int spnego_mode = 0;
    int spnego_parse_status = 0;
    int spnego_mic_only = 0;
    RinAuthProviderBufferV1 mic_output = {0};
    uint32_t spnego_neg_state = UINT32_MAX;
    int generate_spnego_mic = 0;
    (void)context;
    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    if (return_flags != NULL) *return_flags = 0u;
    if (ntlm_used != NULL) *ntlm_used = 0;
    if (security_context == NULL || output == NULL || return_flags == NULL ||
        ntlm_used == NULL || channel_binding_size < 0 ||
        (input_length != 0u && input == NULL) ||
        !provider_credential_valid(credential,
                                   RIN_KERBEROS_OPERATION_CREDENTIAL_ACCEPTOR))
        return provider_unavailable(minor_status);
    existing_context = (RinOsKerberosProviderContext*)*security_context;
    if (existing_context != NULL) {
        if (!provider_context_valid(existing_context) ||
            existing_context->kind !=
                RIN_KERBEROS_OPERATION_CREDENTIAL_ACCEPTOR ||
            existing_context->owner_credential != credential->owner_credential)
            return provider_unavailable(minor_status);
        provider_context = existing_context;
        spnego_mode = provider_context->spnego != 0u;
    } else {
        *security_context = NULL;
        provider_context = (RinOsKerberosProviderContext*)calloc(
            1u, sizeof(*provider_context));
        if (provider_context == NULL)
            return provider_unavailable(minor_status);
        provider_context->magic = RINOS_KERBEROS_CONTEXT_MAGIC;
        provider_context->kind = RIN_KERBEROS_OPERATION_CREDENTIAL_ACCEPTOR;
        provider_context->state = RINOS_KERBEROS_CONTEXT_NEGOTIATING;
        provider_context->owner_credential = credential->owner_credential;
        provider_context->owner = provider_operation_owner();
        provider_context->credential = credential;
        created_context = 1;
    }
    if (spnego_mode ||
        (input_length != 0u &&
         (input[0] == 0x60u || input[0] == 0xa0u || input[0] == 0xa1u))) {
        spnego_parse_status = provider_spnego_unwrap(
            input, input_length, &spnego_input);
        if (spnego_parse_status == 1) {
            spnego_mode = 1;
            if (spnego_input.has_mechanism_token) {
                mechanism_input = spnego_input.mechanism_token;
                mechanism_input_length = spnego_input.mechanism_token_size;
            } else if (!created_context &&
                       provider_context->spnego_mic_required &&
                       spnego_input.has_mechanism_mic) {
                /* The initiator's final SPNEGO leg may contain only
                 * mechListMIC.  Verify it against the retained initial
                 * MechTypeList without passing an empty GSS continuation to
                 * the Kerberos owner. */
                spnego_mic_only = 1;
                mechanism_input = NULL;
                mechanism_input_length = 0u;
            } else {
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_defective_token(minor_status);
            }
        } else if (spnego_mode || input[0] == 0xa0u || input[0] == 0xa1u ||
                   !provider_gss_token_has_framing(input, input_length)) {
            if (created_context) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
            }
            return spnego_parse_status == 2 || spnego_parse_status == 3
                ? provider_unavailable(minor_status)
                : provider_defective_token(minor_status);
        }
    }
    provider_context->spnego = spnego_mode ? 1u : 0u;
    if (spnego_mode && spnego_input.mech_list_size != 0u &&
        !provider_spnego_store_mech_list(provider_context,
                                         &spnego_input)) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return provider_defective_token(minor_status);
    }
    if (spnego_mode && !created_context &&
        provider_context->spnego_mic_required &&
        !spnego_input.has_mechanism_mic) {
        return provider_defective_token(minor_status);
    }
    if (spnego_mic_only) {
        uint32_t mic_status;
        if (provider_context->mech_list_size == 0u) {
            return provider_unavailable(minor_status);
        }
        mic_status = provider_verify_mic_bytes(
            context, minor_status, provider_context,
            provider_context->mech_list,
            (int32_t)provider_context->mech_list_size,
            spnego_input.mechanism_mic,
            (int32_t)spnego_input.mechanism_mic_size);
        if (mic_status != RIN_AUTH_PROVIDER_OK)
            return mic_status;
        provider_context->spnego_mic_required = 0u;
        spnego_neg_state = 0u;
        status = RIN_AUTH_PROVIDER_OK;
        goto spnego_accept_output;
    }
    if (provider_context->owner == NULL ||
        !provider_build_sec_context_input(
            PAL_GSS_KERBEROS, 0u, NULL, channel_binding,
            (uint32_t)channel_binding_size, mechanism_input,
            mechanism_input_length,
            &operation_input, &operation_input_size)) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return provider_unavailable(minor_status);
    }
    request.struct_size = sizeof(request);
    request.version = RIN_KERBEROS_OPERATION_ABI_VERSION;
    request.operation = RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT;
    request.credential_kind = RIN_KERBEROS_OPERATION_CREDENTIAL_ACCEPTOR;
    request.input_size = operation_input_size;
    request.output_capacity = RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE;
    status = provider_operation(credential, provider_context, &request,
                                operation_input, operation_input_size, output,
                                1u, return_flags, minor_status);
    provider_zero(operation_input, operation_input_size);
    free(operation_input);
    if (spnego_mode && spnego_input.has_mechanism_mic) {
        uint32_t mic_status;
        if (status != RIN_AUTH_PROVIDER_OK ||
            provider_context->mech_list_size == 0u) {
            mic_status = provider_unavailable(minor_status);
        } else {
            mic_status = provider_verify_mic_bytes(
                context, minor_status, provider_context,
                provider_context->mech_list,
                (int32_t)provider_context->mech_list_size,
                spnego_input.mechanism_mic,
                (int32_t)spnego_input.mechanism_mic_size);
        }
        if (mic_status != RIN_AUTH_PROVIDER_OK) {
            if (output->data != NULL) {
                provider_zero(output->data, (size_t)output->length);
                provider_buffer_dispose(output->data);
                output->data = NULL;
                output->length = 0u;
            }
            if (created_context) {
                provider_zero(provider_context, sizeof(*provider_context));
                free(provider_context);
                *security_context = NULL;
            }
            return mic_status;
        }
    }
    if (spnego_mode && spnego_input.has_mechanism_mic &&
        provider_context->spnego_mic_required)
        provider_context->spnego_mic_required = 0u;
    if (spnego_mode && created_context &&
        (status == RIN_AUTH_PROVIDER_OK ||
         status == RIN_AUTH_PROVIDER_CONTINUE_NEEDED) &&
        ((*return_flags & RIN_KERBEROS_OPERATION_RETURN_FLAG_INTEGRITY) != 0u) &&
        !provider_spnego_mech_list_starts_with_kerberos(provider_context)) {
        spnego_neg_state = 3u;
        provider_context->spnego_mic_required = 1u;
        if (status == RIN_AUTH_PROVIDER_OK) {
            if (provider_context->mech_list_size == 0u ||
                provider_get_mic(context, minor_status, provider_context,
                                 provider_context->mech_list,
                                 (int32_t)provider_context->mech_list_size,
                                 &mic_output) != RIN_AUTH_PROVIDER_OK ||
                !provider_spnego_mic_is_valid(mic_output.data,
                                              (uint32_t)mic_output.length)) {
                if (mic_output.data != NULL) {
                    provider_zero(mic_output.data, (size_t)mic_output.length);
                    provider_buffer_dispose(mic_output.data);
                }
                if (output->data != NULL) {
                    provider_zero(output->data, (size_t)output->length);
                    provider_buffer_dispose(output->data);
                    output->data = NULL;
                    output->length = 0u;
                }
                if (created_context) {
                    provider_zero(provider_context, sizeof(*provider_context));
                    free(provider_context);
                    *security_context = NULL;
                }
                return provider_unavailable(minor_status);
            }
            generate_spnego_mic = 1;
        }
    }
spnego_accept_output:
    if (spnego_mode &&
        (status == RIN_AUTH_PROVIDER_OK ||
         status == RIN_AUTH_PROVIDER_CONTINUE_NEEDED ||
         status == RIN_AUTH_PROVIDER_KRB_ERROR) &&
        !provider_spnego_replace_output(
            output, status, created_context ? 0u : 0u, 0u,
            created_context ? 1u : 0u, spnego_neg_state,
            generate_spnego_mic ? (const uint8_t*)mic_output.data : NULL,
            generate_spnego_mic ? (uint32_t)mic_output.length : 0u)) {
        if (mic_output.data != NULL) {
            provider_zero(mic_output.data, (size_t)mic_output.length);
            provider_buffer_dispose(mic_output.data);
        }
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return provider_unavailable(minor_status);
    }
    if (mic_output.data != NULL) {
        provider_zero(mic_output.data, (size_t)mic_output.length);
        provider_buffer_dispose(mic_output.data);
    }
    if (status != RIN_AUTH_PROVIDER_OK &&
        status != RIN_AUTH_PROVIDER_CONTINUE_NEEDED) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return status;
    }
    if (created_context &&
        !provider_context_retain(credential, provider_context)) {
        provider_zero(provider_context, sizeof(*provider_context));
        free(provider_context);
        *security_context = NULL;
        return provider_unavailable(minor_status);
    }
    *security_context = provider_context;
    if (minor_status != NULL) *minor_status = 0u;
    return status;
}

static uint32_t provider_delete_sec_context(
    void* context, uint32_t* minor_status, void** security_context)
{
    RinOsKerberosProviderContext* provider_context;
    RinOsKerberosProviderCredential* credential;
    RinKerberosOperationRequestV1 request = {0};
    uint32_t status;
    (void)context;
    if (security_context == NULL || *security_context == NULL)
        return provider_unavailable(minor_status);
    provider_context = (RinOsKerberosProviderContext*)*security_context;
    if (!provider_context_valid(provider_context)) {
        *security_context = NULL;
        return provider_unavailable(minor_status);
    }
    credential = provider_context->credential;
    request.struct_size = sizeof(request);
    request.version = RIN_KERBEROS_OPERATION_ABI_VERSION;
    request.operation = RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT;
    request.credential_kind = provider_context->kind;
    request.context_token_size = provider_context->token_size;
    request.output_capacity = 0u;
    status = provider_operation(credential, provider_context, &request, NULL,
                                0u, NULL, 0u, NULL, minor_status);
    if (status != RIN_AUTH_PROVIDER_OK) {
        /* The keyring operation owner removes an expired context slot before
         * returning CONTEXT_EXPIRED.  There is therefore no remote context
         * left for a later DELETE_SEC_CONTEXT retry.  Release the local
         * lifetime reference at this terminal boundary; retaining it would
         * keep the credential wrapper permanently unreleasable after ticket
         * expiry.  Other failures remain retryable because their remote
         * context ownership is not established to have ended. */
        if (status == RIN_AUTH_PROVIDER_CONTEXT_EXPIRED) {
            provider_context_release(provider_context);
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        /* The owner still owns the remote context when cleanup fails.  Keep
         * the local handle alive so the caller can retry after a transient
         * transport failure; successful cleanup below is the commit point. */
        if (minor_status != NULL) *minor_status = 0u;
        return status;
    }
    provider_context_release(provider_context);
    provider_zero(provider_context, sizeof(*provider_context));
    free(provider_context);
    *security_context = NULL;
    if (minor_status != NULL) *minor_status = 0u;
    return status;
}

static uint32_t provider_message_operation(
    uint16_t operation, uint32_t* minor_status, void* security_context,
    int32_t* encrypt, uint8_t* input, int32_t input_length,
    RinAuthProviderBufferV1* output)
{
    RinOsKerberosProviderContext* provider_context =
        (RinOsKerberosProviderContext*)security_context;
    RinOsKerberosProviderCredential credential = {0};
    RinKerberosProviderMessagePairInputV1 header = {0};
    RinKerberosOperationRequestV1 request = {0};
    uint8_t* envelope;
    uint32_t total;
    uint32_t operation_flags =
        operation == RIN_KERBEROS_OPERATION_WRAP && encrypt != NULL &&
                *encrypt != 0
            ? RIN_KERBEROS_OPERATION_FLAG_ENCRYPT
            : 0u;
    uint32_t status;
    if (!provider_context_valid(provider_context) ||
        provider_context->state != RINOS_KERBEROS_CONTEXT_ESTABLISHED ||
        output == NULL ||
        input_length < 0 ||
        (input_length != 0 && input == NULL) ||
        (uint32_t)input_length > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE -
            sizeof(header))
        return provider_unavailable(minor_status);
    total = (uint32_t)sizeof(header) + (uint32_t)input_length;
    envelope = (uint8_t*)calloc(1u, total);
    if (envelope == NULL) return provider_unavailable(minor_status);
    header.struct_size = sizeof(header);
    header.version = RIN_KERBEROS_PROVIDER_INPUT_ABI_VERSION;
    header.kind = RIN_KERBEROS_PROVIDER_INPUT_MESSAGE_PAIR;
    header.first_size = (uint32_t)input_length;
    header.second_size = 0u;
    header.flags = operation_flags;
    memcpy(envelope, &header, sizeof(header));
    if (input_length != 0)
        memcpy(envelope + sizeof(header), input, (size_t)input_length);
    credential.magic = RINOS_KERBEROS_CREDENTIAL_MAGIC;
    credential.kind = provider_context->kind;
    credential.owner_credential = provider_context->owner_credential;
    /* A published context retains the credential owner for its lifetime.
     * Do not rediscover it here: a transient capability-probe outage must not
     * turn an already-authenticated context into an unusable one. */
    credential.owner = provider_context->credential->owner;
    request.struct_size = sizeof(request);
    request.version = RIN_KERBEROS_OPERATION_ABI_VERSION;
    request.operation = operation;
    request.credential_kind = provider_context->kind;
    request.flags = operation_flags;
    request.input_size = total;
    request.output_capacity = RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE;
    status = provider_operation(&credential, provider_context, &request,
                                envelope, total, output, 1u, NULL,
                                minor_status);
    provider_zero(envelope, total);
    free(envelope);
    if (status == RIN_AUTH_PROVIDER_OK && encrypt != NULL) {
        if (operation == RIN_KERBEROS_OPERATION_WRAP)
            *encrypt = operation_flags != 0u;
        else if (operation == RIN_KERBEROS_OPERATION_UNWRAP &&
                 input_length >= 3 && input != NULL)
            *encrypt = (input[2] & RINOS_KERBEROS_GSS_FLAG_SEALED) != 0u;
    }
    if ((status == RIN_AUTH_PROVIDER_OK ||
         status == RIN_AUTH_PROVIDER_CONTINUE_NEEDED) &&
        minor_status != NULL)
        *minor_status = 0u;
    return status;
}

static uint32_t provider_wrap(
    void* context, uint32_t* minor_status, void* security_context,
    int32_t* encrypt, uint8_t* input, int32_t input_length,
    RinAuthProviderBufferV1* output)
{
    (void)context;
    return provider_message_operation(RIN_KERBEROS_OPERATION_WRAP,
                                      minor_status, security_context, encrypt,
                                      input, input_length, output);
}

static uint32_t provider_unwrap(
    void* context, uint32_t* minor_status, void* security_context,
    int32_t* encrypt, uint8_t* input, int32_t input_length,
    RinAuthProviderBufferV1* output)
{
    (void)context;
    return provider_message_operation(RIN_KERBEROS_OPERATION_UNWRAP,
                                      minor_status, security_context, encrypt,
                                      input, input_length, output);
}

static uint32_t provider_get_mic(
    void* context, uint32_t* minor_status, void* security_context,
    uint8_t* input, int32_t input_length, RinAuthProviderBufferV1* output)
{
    uint32_t status;
    (void)context;
    status = provider_message_operation(RIN_KERBEROS_OPERATION_GET_MIC,
                                         minor_status, security_context, NULL,
                                         input, input_length, output);
    if (status == RIN_AUTH_PROVIDER_OK &&
        !provider_spnego_mic_is_valid(
            output != NULL ? (const uint8_t*)output->data : NULL,
            output != NULL ? (uint32_t)output->length : 0u)) {
        if (output != NULL && output->data != NULL) {
            provider_zero(output->data, (size_t)output->length);
            provider_buffer_dispose(output->data);
            output->data = NULL;
            output->length = 0u;
        }
        return provider_unavailable(minor_status);
    }
    return status;
}

static uint32_t provider_verify_mic_bytes(
    void* context, uint32_t* minor_status, void* security_context,
    const uint8_t* input, int32_t input_length, const uint8_t* token,
    int32_t token_length)
{
    RinOsKerberosProviderContext* provider_context =
        (RinOsKerberosProviderContext*)security_context;
    RinOsKerberosProviderCredential credential = {0};
    RinKerberosProviderMessagePairInputV1 header;
    RinKerberosOperationRequestV1 request = {0};
    uint8_t* envelope;
    uint32_t total;
    uint32_t status;
    size_t input_size;
    size_t token_size;
    (void)context;
    if (!provider_context_valid(provider_context) ||
        provider_context->state != RINOS_KERBEROS_CONTEXT_ESTABLISHED ||
        input_length < 0 ||
        token_length < 0 ||
        (input_length != 0 && input == NULL) ||
        (token_length != 0 && token == NULL) ||
        (uint32_t)input_length > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE ||
        (uint32_t)token_length > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE ||
        (uint32_t)input_length > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE -
            sizeof(header) ||
        (uint32_t)token_length > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE -
            sizeof(header) - (uint32_t)input_length)
        return provider_unavailable(minor_status);
    input_size = (size_t)(uint32_t)input_length;
    token_size = (size_t)(uint32_t)token_length;
    total = (uint32_t)sizeof(header) + (uint32_t)input_length +
            (uint32_t)token_length;
    envelope = (uint8_t*)calloc(1u, total);
    if (envelope == NULL) return provider_unavailable(minor_status);
    header.struct_size = sizeof(header);
    header.version = RIN_KERBEROS_PROVIDER_INPUT_ABI_VERSION;
    header.kind = RIN_KERBEROS_PROVIDER_INPUT_MESSAGE_PAIR;
    header.first_size = (uint32_t)input_length;
    header.second_size = (uint32_t)token_length;
    header.flags = 0u;
    memcpy(envelope, &header, sizeof(header));
    if (input_size != 0u)
        memcpy(envelope + sizeof(header), input, input_size);
    if (token_length != 0)
        memcpy(envelope + sizeof(header) + input_size, token, token_size);
    credential.magic = RINOS_KERBEROS_CREDENTIAL_MAGIC;
    credential.kind = provider_context->kind;
    credential.owner_credential = provider_context->owner_credential;
    /* Use the owner retained with the live context.  The context lifetime
     * contract keeps this table reachable until the context is deleted. */
    credential.owner = provider_context->credential->owner;
    request.struct_size = sizeof(request);
    request.version = RIN_KERBEROS_OPERATION_ABI_VERSION;
    request.operation = RIN_KERBEROS_OPERATION_VERIFY_MIC;
    request.credential_kind = provider_context->kind;
    request.input_size = total;
    request.output_capacity = 0u;
    status = provider_operation(&credential, provider_context, &request,
                                envelope, total, NULL, 1u, NULL,
                                minor_status);
    provider_zero(envelope, total);
    free(envelope);
    /* Keep the operation's failure classification intact.  The other
     * per-message paths clear the mechanism minor only after a successful
     * operation; verify_mic must follow the same failure-atomic rule so a
     * provider-side diagnostic is not erased on a rejected MIC. */
    if (status == RIN_AUTH_PROVIDER_OK && minor_status != NULL)
        *minor_status = 0u;
    return status;
}

static uint32_t provider_verify_mic(
    void* context, uint32_t* minor_status, void* security_context,
    uint8_t* input, int32_t input_length, uint8_t* token, int32_t token_length)
{
    return provider_verify_mic_bytes(context, minor_status, security_context,
                                     input, input_length, token, token_length);
}

static void provider_release_buffer(void* context, void* buffer,
                                    uint64_t length)
{
    (void)context;
    (void)length;
    provider_buffer_dispose(buffer);
}

/* Kerberos protocol names are diagnostic metadata only.  The assigned names
 * below are taken from the upstream MIT krb5 protocol table, including the
 * later RFC-defined extensions.  Slots without an assigned symbolic name are
 * deliberately absent: the numeric mechanism minor is the contract, and an
 * invented-looking "KRB5 error code N" label must not be exposed as a formal
 * protocol name during troubleshooting. */
static const char* provider_kerberos_error_name(uint32_t value)
{
    switch (value) {
    case 0u: return "KDC_ERR_NONE";
    case 1u: return "KDC_ERR_NAME_EXP";
    case 2u: return "KDC_ERR_SERVICE_EXP";
    case 3u: return "KDC_ERR_BAD_PVNO";
    case 4u: return "KDC_ERR_C_OLD_MAST_KVNO";
    case 5u: return "KDC_ERR_S_OLD_MAST_KVNO";
    case 6u: return "KDC_ERR_C_PRINCIPAL_UNKNOWN";
    case 7u: return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
    case 8u: return "KDC_ERR_PRINCIPAL_NOT_UNIQUE";
    case 9u: return "KDC_ERR_NULL_KEY";
    case 10u: return "KDC_ERR_CANNOT_POSTDATE";
    case 11u: return "KDC_ERR_NEVER_VALID";
    case 12u: return "KDC_ERR_POLICY";
    case 13u: return "KDC_ERR_BADOPTION";
    case 14u: return "KDC_ERR_ETYPE_NOSUPP";
    case 15u: return "KDC_ERR_SUMTYPE_NOSUPP";
    case 16u: return "KDC_ERR_PADATA_TYPE_NOSUPP";
    case 17u: return "KDC_ERR_TRTYPE_NOSUPP";
    case 18u: return "KDC_ERR_CLIENT_REVOKED";
    case 19u: return "KDC_ERR_SERVICE_REVOKED";
    case 20u: return "KDC_ERR_TGT_REVOKED";
    case 21u: return "KDC_ERR_CLIENT_NOTYET";
    case 22u: return "KDC_ERR_SERVICE_NOTYET";
    case 23u: return "KDC_ERR_KEY_EXP";
    case 24u: return "KDC_ERR_PREAUTH_FAILED";
    case 25u: return "KDC_ERR_PREAUTH_REQUIRED";
    case 26u: return "KDC_ERR_SERVER_NOMATCH";
    case 27u: return "KDC_ERR_MUST_USE_USER2USER";
    case 28u: return "KDC_ERR_PATH_NOT_ACCEPTED";
    case 29u: return "KDC_ERR_SVC_UNAVAILABLE";
    case 31u: return "KRB_AP_ERR_BAD_INTEGRITY";
    case 32u: return "KRB_AP_ERR_TKT_EXPIRED";
    case 33u: return "KRB_AP_ERR_TKT_NYV";
    case 34u: return "KRB_AP_ERR_REPEAT";
    case 35u: return "KRB_AP_ERR_NOT_US";
    case 36u: return "KRB_AP_ERR_BADMATCH";
    case 37u: return "KRB_AP_ERR_SKEW";
    case 38u: return "KRB_AP_ERR_BADADDR";
    case 39u: return "KRB_AP_ERR_BADVERSION";
    case 40u: return "KRB_AP_ERR_MSG_TYPE";
    case 41u: return "KRB_AP_ERR_MODIFIED";
    case 42u: return "KRB_AP_ERR_BADORDER";
    case 43u: return "KRB_AP_ERR_ILL_CR_TKT";
    case 44u: return "KRB_AP_ERR_BADKEYVER";
    case 45u: return "KRB_AP_ERR_NOKEY";
    case 46u: return "KRB_AP_ERR_MUT_FAIL";
    case 47u: return "KRB_AP_ERR_BADDIRECTION";
    case 48u: return "KRB_AP_ERR_METHOD";
    case 49u: return "KRB_AP_ERR_BADSEQ";
    case 50u: return "KRB_AP_ERR_INAPP_CKSUM";
    case 51u: return "KRB_AP_PATH_NOT_ACCEPTED";
    case 52u: return "KRB_ERR_RESPONSE_TOO_BIG";
    case 60u: return "KRB_ERR_GENERIC";
    case 61u: return "KRB_ERR_FIELD_TOOLONG";
    case 62u: return "KDC_ERR_CLIENT_NOT_TRUSTED";
    case 63u: return "KDC_ERR_KDC_NOT_TRUSTED";
    case 64u: return "KDC_ERR_INVALID_SIG";
    case 65u: return "KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED";
    case 66u: return "KDC_ERR_CERTIFICATE_MISMATCH";
    case 67u: return "KRB_AP_ERR_NO_TGT";
    case 68u: return "KDC_ERR_WRONG_REALM";
    case 69u: return "KRB_AP_ERR_USER_TO_USER_REQUIRED";
    case 70u: return "KDC_ERR_CANT_VERIFY_CERTIFICATE";
    case 71u: return "KDC_ERR_INVALID_CERTIFICATE";
    case 72u: return "KDC_ERR_REVOKED_CERTIFICATE";
    case 73u: return "KDC_ERR_REVOCATION_STATUS_UNKNOWN";
    case 74u: return "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE";
    case 75u: return "KDC_ERR_CLIENT_NAME_MISMATCH";
    case 76u: return "KDC_ERR_KDC_NAME_MISMATCH";
    case 77u: return "KDC_ERR_INCONSISTENT_KEY_PURPOSE";
    case 78u: return "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED";
    case 79u: return "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED";
    case 80u: return "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED";
    case 81u: return "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED";
    case 85u: return "KRB_AP_ERR_IAKERB_KDC_NOT_FOUND";
    case 86u: return "KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE";
    case 90u: return "KDC_ERR_PREAUTH_EXPIRED";
    case 91u: return "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED";
    case 92u: return "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET";
    case 93u: return "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS";
    case 100u: return "KDC_ERR_NO_ACCEPTABLE_KDF";
    default: return NULL;
    }
}

static uint32_t provider_display_status_value(
    uint32_t* minor_status, uint32_t status_value, int is_minor,
    RinAuthProviderBufferV1* output)
{
    static const char* const hex = "0123456789ABCDEF";
    const char* message = NULL;
    const char* prefix = NULL;
    char formatted[128];
    size_t length = 0u;
    size_t prefix_length;
    uint32_t index;
    uint8_t* bytes;

    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    if (output == NULL) return provider_unavailable(minor_status);

    if (!is_minor && status_value == 0u)
        message = "GSS status: complete";
    else if (!is_minor && status_value == PAL_GSS_CONTINUE_NEEDED)
        message = "GSS status: continuation needed";
    else if (!is_minor && status_value == (UINT32_C(16) << 16))
        message = "GSS status: RinOS authentication provider unavailable";

    if (message != NULL) {
        length = strlen(message);
        memcpy(formatted, message, length);
    } else if (is_minor &&
               (status_value & RIN_KERBEROS_OPERATION_MINOR_PROTOCOL_ERROR) != 0u) {
        static const char prefix_text[] = "Kerberos protocol error ";
        static const char name_separator[] = " (";
        static const char name_suffix[] = ")";
        char digits[10];
        uint32_t value = status_value &
                         RIN_KERBEROS_OPERATION_MINOR_ERROR_CODE_MASK;
        const char* name = provider_kerberos_error_name(value);
        size_t digit_count = 0u;
        memcpy(formatted, prefix_text, sizeof(prefix_text) - 1u);
        length = sizeof(prefix_text) - 1u;
        do {
            digits[digit_count++] = (char)('0' + (value % 10u));
            value /= 10u;
        } while (value != 0u);
        while (digit_count != 0u) formatted[length++] = digits[--digit_count];
        if (name != NULL) {
            const size_t name_length = strlen(name);
            memcpy(formatted + length, name_separator,
                   sizeof(name_separator) - 1u);
            length += sizeof(name_separator) - 1u;
            memcpy(formatted + length, name, name_length);
            length += name_length;
            memcpy(formatted + length, name_suffix, sizeof(name_suffix) - 1u);
            length += sizeof(name_suffix) - 1u;
        }
    } else {
        prefix = is_minor ? "RinOS mechanism status 0x" : "GSS status 0x";
        prefix_length = strlen(prefix);
        memcpy(formatted, prefix, prefix_length);
        for (index = 0u; index < 8u; ++index) {
            const uint32_t shift = 28u - index * 4u;
            formatted[prefix_length + index] =
                hex[(status_value >> shift) & UINT32_C(0x0f)];
        }
        length = prefix_length + 8u;
    }

    bytes = provider_buffer_alloc(length);
    if (bytes == NULL) return provider_unavailable(minor_status);
    memcpy(bytes, formatted, length);
    output->data = bytes;
    output->length = length;
    if (minor_status != NULL) *minor_status = 0u;
    return RIN_AUTH_PROVIDER_OK;
}

static uint32_t provider_display_minor_status(
    void* context, uint32_t* minor_status, uint32_t status_value,
    RinAuthProviderBufferV1* output)
{
    (void)context;
    return provider_display_status_value(minor_status, status_value, 1,
                                         output);
}

static uint32_t provider_display_major_status(
    void* context, uint32_t* minor_status, uint32_t status_value,
    RinAuthProviderBufferV1* output)
{
    (void)context;
    return provider_display_status_value(minor_status, status_value, 0,
                                         output);
}

static int provider_escaped_principal_hex_digit(uint8_t byte)
{
    return (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
           (byte >= (uint8_t)'a' && byte <= (uint8_t)'f') ||
           (byte >= (uint8_t)'A' && byte <= (uint8_t)'F');
}

/* The session owner returns the bounded escaped form used by MIT's
 * krb5_unparse_name(), not an arbitrary display label.  Keep this check
 * local to the provider boundary: the owner remains responsible for
 * obtaining the authenticated principal, while the runtime refuses to
 * project malformed bytes as DefaultCredentials/RemoteIdentity. */
static int provider_escaped_principal_valid(const uint8_t* bytes,
                                             uint32_t size)
{
    uint32_t index;
    int escaped = 0;
    int seen_realm = 0;
    int component_has_value = 0;
    int realm_has_value = 0;

    if (bytes == NULL || size == 0u) return 0;
    for (index = 0u; index < size; ++index) {
        const uint8_t byte = bytes[index];
        if (byte == 0u) return 0;
        /* krb5_unparse_name() escapes C0 controls and DEL.  Do not accept a
         * producer that places them directly in the principal identity: raw
         * controls can cross the managed DefaultCredentials/RemoteIdentity
         * boundary and change logging or line-oriented consumers.  Escaped
         * `\\xHH` sequences are handled by the branch below and remain valid. */
        if (byte < 0x20u || byte == 0x7fu) return 0;
        if (escaped) {
            if (byte == (uint8_t)'x') {
                if (size - index < 3u ||
                    !provider_escaped_principal_hex_digit(bytes[index + 1u]) ||
                    !provider_escaped_principal_hex_digit(bytes[index + 2u]))
                    return 0;
                index += 2u;
            } else if (byte != (uint8_t)'\\' && byte != (uint8_t)'/' &&
                       byte != (uint8_t)'@' && byte != (uint8_t)'0' &&
                       byte != (uint8_t)'t' && byte != (uint8_t)'n' &&
                       byte != (uint8_t)'b') {
                return 0;
            }
            if (seen_realm)
                realm_has_value = 1;
            else
                component_has_value = 1;
            escaped = 0;
            continue;
        }
        if (byte == (uint8_t)'\\') {
            escaped = 1;
            continue;
        }
        if (seen_realm) {
            if (byte == (uint8_t)'/' || byte == (uint8_t)'@') return 0;
            realm_has_value = 1;
            continue;
        }
        if (byte == (uint8_t)'/') {
            if (!component_has_value) return 0;
            component_has_value = 0;
            continue;
        }
        if (byte == (uint8_t)'@') {
            if (!component_has_value) return 0;
            seen_realm = 1;
            continue;
        }
        component_has_value = 1;
    }
    return !escaped && seen_realm && component_has_value && realm_has_value;
}

static uint32_t provider_get_user(
    void* context, uint32_t* minor_status, void* security_context,
    RinAuthProviderBufferV1* output)
{
    RinOsKerberosProviderContext* provider_context =
        (RinOsKerberosProviderContext*)security_context;
    const RinKerberosCredentialOwnerV1* owner;
    RinOsKerberosProviderCredential credential = {0};
    RinKerberosOperationRequestV1 request = {0};
    uint8_t* principal;
    uint32_t principal_size = 0u;
    uint64_t generation = 0u;
    uint32_t owner_minor = 0u;
    uint32_t status;
    (void)context;
    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    if (output == NULL || !provider_context_valid(provider_context) ||
        provider_context->state != RINOS_KERBEROS_CONTEXT_ESTABLISHED ||
        provider_context->generation == 0u)
        return provider_unavailable(minor_status);

    if (provider_context->kind ==
        RIN_KERBEROS_OPERATION_CREDENTIAL_ACCEPTOR) {
        /* RemoteIdentity is bound to the authenticated context's owner.  A
         * fresh global owner probe may be temporarily unavailable while this
         * context is still valid, so use the retained credential owner. */
        owner = provider_context->credential->owner;
        if (owner == NULL)
            return provider_unavailable(minor_status);
        credential.magic = RINOS_KERBEROS_CREDENTIAL_MAGIC;
        credential.kind = provider_context->kind;
        credential.owner_credential = provider_context->owner_credential;
        credential.owner = owner;
        request.struct_size = sizeof(request);
        request.version = RIN_KERBEROS_OPERATION_ABI_VERSION;
        request.operation = RIN_KERBEROS_OPERATION_GET_PEER_PRINCIPAL;
        request.credential_kind = provider_context->kind;
        request.output_capacity = RINOS_KERBEROS_MAX_PRINCIPAL_SIZE;
        status = provider_operation(
            &credential, provider_context, &request, NULL, 0u, output, 0u,
            NULL, minor_status);
        if (status != RIN_AUTH_PROVIDER_OK || output->data == NULL ||
            output->length == 0u ||
            output->length > RINOS_KERBEROS_MAX_PRINCIPAL_SIZE ||
            !provider_escaped_principal_valid(
                output->data, (uint32_t)output->length)) {
            if (output->data != NULL) {
                provider_release_buffer(context, output->data, output->length);
                output->data = NULL;
                output->length = 0u;
            }
            return status == RIN_AUTH_PROVIDER_OK
                ? provider_unavailable(minor_status) : status;
        }
        return status;
    }

    if (provider_context->kind !=
        RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR)
        return provider_unavailable(minor_status);
    /* DefaultCredentials identity is also read from the owner retained by
     * the established context, never from a replacement/global probe. */
    owner = provider_context->credential->owner;
    if (owner == NULL || owner->get_session_principal == NULL)
        return provider_unavailable(minor_status);
    principal = provider_buffer_alloc(RINOS_KERBEROS_MAX_PRINCIPAL_SIZE);
    if (principal == NULL) return provider_unavailable(minor_status);
    status = owner->get_session_principal(
        owner->context, &owner_minor, provider_context->owner_credential,
        principal, RINOS_KERBEROS_MAX_PRINCIPAL_SIZE, &principal_size,
        &generation);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK) {
        provider_zero(principal, RINOS_KERBEROS_MAX_PRINCIPAL_SIZE);
        provider_buffer_dispose(principal);
        return provider_status_from_owner(status, minor_status);
    }
    /* A successful owner callback must also clear its minor status.  Treating
     * OK plus a diagnostic as a valid identity would hide a producer-side
     * partial failure and turn an untrusted principal buffer into successful
     * DefaultCredentials/RemoteIdentity state. */
    if (owner_minor != 0u) {
        provider_zero(principal, RINOS_KERBEROS_MAX_PRINCIPAL_SIZE);
        provider_buffer_dispose(principal);
        return provider_unavailable(minor_status);
    }
    /* An owner OK result is not sufficient to establish an identity.  Do not
     * turn an empty principal or a stale generation into a successful
     * DefaultCredentials/RemoteIdentity result. */
    if (principal_size == 0u ||
        principal_size > RINOS_KERBEROS_MAX_PRINCIPAL_SIZE ||
        generation != provider_context->generation ||
        !provider_escaped_principal_valid(principal, principal_size)) {
        provider_zero(principal, RINOS_KERBEROS_MAX_PRINCIPAL_SIZE);
        provider_buffer_dispose(principal);
        return provider_unavailable(minor_status);
    }
    output->data = principal;
    output->length = principal_size;
    if (minor_status != NULL) *minor_status = 0u;
    return RIN_AUTH_PROVIDER_OK;
}

static RinAuthProviderV1 g_provider = {
    .struct_size = sizeof(RinAuthProviderV1),
    .version = RIN_AUTH_PROVIDER_ABI_VERSION,
    .reserved0 = 0u,
    .package_mask = RIN_AUTH_PROVIDER_PACKAGE_NEGOTIATE |
                    RIN_AUTH_PROVIDER_PACKAGE_KERBEROS,
    .max_token_size = RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE,
    .context = NULL,
    .release_buffer = provider_release_buffer,
    .display_minor_status = provider_display_minor_status,
    .display_major_status = provider_display_major_status,
    .import_user_name = provider_import_user_name,
    .import_principal_name = provider_import_principal_name,
    .release_name = provider_release_name,
    .acquire_acceptor_cred = provider_acquire_acceptor_cred,
    .initiate_cred_spnego = provider_initiate_cred_spnego,
    .release_cred = provider_release_cred,
    .init_sec_context = provider_init_sec_context,
    .init_sec_context_ex = provider_init_sec_context_ex,
    .accept_sec_context = provider_accept_sec_context,
    .delete_sec_context = provider_delete_sec_context,
    .wrap = provider_wrap,
    .unwrap = provider_unwrap,
    .get_mic = provider_get_mic,
    .verify_mic = provider_verify_mic,
    .initiate_cred_with_password = NULL,
    .is_ntlm_installed = NULL,
    .get_user = provider_get_user,
};
#endif /* RINOS_KERBEROS_RFC_PROVIDER_LINKED */

const RinAuthProviderV1* rin_auth_provider_get_v1(void)
{
#if !defined(RINOS_KERBEROS_RFC_PROVIDER_LINKED)
    /* A transport-only build must not advertise a usable Kerberos provider. */
    return NULL;
#else
    const RinKerberosCredentialOwnerV1* credential_owner =
        provider_credential_owner();
    const RinKerberosOperationOwnerV1* operation_owner =
        provider_operation_owner();
    /* Capability advertisement is also conditional on the live RinOS
     * credential and operation owners.  The provider must never make a
     * username, fixed token, or success-only stub look like session
     * credentials. */
    if (credential_owner == NULL || operation_owner == NULL)
        return NULL;
    return &g_provider;
#endif
}
