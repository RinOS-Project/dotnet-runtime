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
 * bounded RFC 4121 per-message operations; it still rejects every RFC feature
 * it has not implemented.
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
/* Keep a peer-supplied RFC 4120 error code distinguishable from local
 * provider diagnostics while preserving every non-negative Int32 code. */
#define RINOS_KERBEROS_MINOR_PROTOCOL_ERROR UINT32_C(0x80000000)

#if defined(__GNUC__) || defined(__clang__)
#define RINOS_KERBEROS_WEAK __attribute__((weak))
#else
#define RINOS_KERBEROS_WEAK
#endif

#if defined(RINOS_KERBEROS_OWNER_LINKED)
extern const RinKerberosCredentialOwnerV1*
rin_kerberos_credential_owner_get_v1(void);
extern const RinKerberosOperationOwnerV1*
rin_kerberos_operation_owner_get_v1(void);
#else
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
} RinOsKerberosProviderName;

typedef struct RinOsKerberosProviderCredential {
    uint32_t magic;
    uint32_t kind;
    void* owner_credential;
    const RinKerberosCredentialOwnerV1* owner;
} RinOsKerberosProviderCredential;

typedef struct RinOsKerberosProviderContext {
    uint32_t magic;
    uint32_t kind;
    uint64_t generation;
    uint32_t token_size;
    uint32_t state;
    uint32_t reserved;
    void* owner_credential;
    const RinKerberosOperationOwnerV1* owner;
    uint8_t token[RIN_KERBEROS_OPERATION_MAX_CONTEXT_TOKEN_SIZE];
} RinOsKerberosProviderContext;

static void provider_zero(void* pointer, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    while (size-- != 0u) *bytes++ = 0u;
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
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_INVALID_SESSION) {
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_DEFECTIVE_CREDENTIAL;
    }
    if (status == RIN_KERBEROS_CREDENTIAL_OWNER_EXPIRED) {
        if (minor_status != NULL) *minor_status = 0u;
        return RIN_AUTH_PROVIDER_CREDENTIALS_EXPIRED;
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
        (size < 5u && (bytes[0] & 0x80u) != 0u) ||
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
    }
    return 1;
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
    int have_service_realm = 0;
    int have_service_name = 0;
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
        if (tag == 0xa9u) have_service_realm = 1;
        if (tag == 0xaau) have_service_name = 1;
        (void)ignored_bytes;
        (void)ignored_size;
    }
    return have_service_realm && have_service_name;
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
    return name != NULL && name->magic == RINOS_KERBEROS_NAME_MAGIC &&
           name->size != 0u &&
           name->size <= RIN_KERBEROS_PROVIDER_MAX_TARGET_NAME_SIZE;
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

static int provider_context_valid(
    const RinOsKerberosProviderContext* context)
{
    return context != NULL && context->magic == RINOS_KERBEROS_CONTEXT_MAGIC &&
           (context->kind == RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR ||
            context->kind == RIN_KERBEROS_OPERATION_CREDENTIAL_ACCEPTOR) &&
           context->owner != NULL && context->owner_credential != NULL &&
           context->owner->operation != NULL &&
           (context->state == RINOS_KERBEROS_CONTEXT_NEGOTIATING ||
            context->state == RINOS_KERBEROS_CONTEXT_ESTABLISHED) &&
           context->token_size <= RIN_KERBEROS_OPERATION_MAX_CONTEXT_TOKEN_SIZE;
}

static const RinKerberosCredentialOwnerV1* provider_credential_owner(void)
{
#if !defined(RINOS_KERBEROS_OWNER_LINKED)
    if (rin_kerberos_credential_owner_get_v1 == NULL) return NULL;
#endif
    return rin_kerberos_credential_owner_get_v1();
}

static const RinKerberosOperationOwnerV1* provider_operation_owner(void)
{
#if !defined(RINOS_KERBEROS_OWNER_LINKED)
    if (rin_kerberos_operation_owner_get_v1 == NULL) return NULL;
#endif
    return rin_kerberos_operation_owner_get_v1();
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
    name = (RinOsKerberosProviderName*)*input;
    if (!provider_name_valid(name)) {
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
    credential->owner = owner;
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
    if (owner == NULL || owner->acquire_acceptor_keytab == NULL)
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
    (void)context;
    if (output == NULL) return provider_unavailable(minor_status);
    *output = NULL;
    /* Named credentials require a product policy that is not part of the
     * current owner ABI. Never substitute a username or fixed token. */
    if (desired_name != NULL || owner == NULL ||
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
    uint32_t status;
    (void)context;
    if (input == NULL || *input == NULL)
        return provider_unavailable(minor_status);
    credential = (RinOsKerberosProviderCredential*)*input;
    if (!provider_credential_valid(credential, credential->kind)) {
        *input = NULL;
        return provider_unavailable(minor_status);
    }
    status = credential->owner->release_credential(
        credential->owner->context, minor_status, &credential->owner_credential);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK ||
        credential->owner_credential != NULL)
        return provider_status_from_owner(
            status == RIN_KERBEROS_CREDENTIAL_OWNER_OK
                ? RIN_KERBEROS_CREDENTIAL_OWNER_UNAVAILABLE : status,
            minor_status);
    provider_zero(credential, sizeof(*credential));
    free(credential);
    *input = NULL;
    return provider_status_from_owner(status, minor_status);
}

static uint32_t provider_build_sec_context_input(
    uint32_t mechanism, uint32_t requested_flags,
    const RinOsKerberosProviderName* target_name, const void* channel_binding,
    uint32_t channel_binding_size, const uint8_t* token, uint32_t token_size,
    uint8_t** output, uint32_t* output_size)
{
    RinKerberosProviderSecContextInputV1 header = {0};
    uint32_t total;
    uint8_t* bytes;
    if (output == NULL || output_size == NULL ||
        (target_name != NULL && !provider_name_valid(target_name)) ||
        (requested_flags &
         ~RIN_KERBEROS_OPERATION_KNOWN_RETURN_FLAGS) != 0u ||
        channel_binding_size > RIN_KERBEROS_PROVIDER_MAX_CHANNEL_BINDING_SIZE ||
        (channel_binding_size != 0u && channel_binding == NULL) ||
        token_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE ||
        (token_size != 0u && token == NULL))
        return 0u;
    total = (uint32_t)sizeof(header);
    if ((target_name != NULL && target_name->size >
         RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE - total) ||
        channel_binding_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE - total ||
        token_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE - total)
        return 0u;
    total += target_name != NULL ? target_name->size : 0u;
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
    header.target_name_size = target_name != NULL ? target_name->size : 0u;
    header.channel_binding_size = channel_binding_size;
    header.token_size = token_size;
    memcpy(bytes, &header, sizeof(header));
    total = (uint32_t)sizeof(header);
    if (target_name != NULL) {
        memcpy(bytes + total, target_name->bytes, target_name->size);
        total += target_name->size;
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
        operation_output = (uint8_t*)calloc(1u, request->output_capacity);
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
            free(operation_output);
        }
        provider_zero(next_context, sizeof(next_context));
        /* Preserve the owner-defined GSS-relevant failure classification.
         * The owner is the authority for ticket/context lifetime and channel
         * bindings; collapsing these values to UNAVAILABLE would hide a
         * real protocol result from the PAL. */
        return provider_status_from_owner(status, minor_status);
    }
    if (owner_minor_status != 0u ||
        provider_result > RIN_KERBEROS_OPERATION_RESULT_ERROR ||
        operation_generation == 0u ||
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
         (request->operation != RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT ||
          operation_output_size == 0u || next_context_size != 0u ||
          (operation_return_flags &
           ~RIN_KERBEROS_OPERATION_RETURN_FLAG_EXTENDED_ERROR) != 0u)) ||
        (operation_return_flags &
         ~RIN_KERBEROS_OPERATION_KNOWN_RETURN_FLAGS) != 0u) {
        if (operation_output != NULL) {
            provider_zero(operation_output, request->output_capacity);
            free(operation_output);
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
                free(operation_output);
            }
            provider_zero(next_context, sizeof(next_context));
            return provider_unavailable(minor_status);
        }
        if (minor_status != NULL)
            *minor_status = RINOS_KERBEROS_MINOR_PROTOCOL_ERROR | error_code;
    }
    if (provider_context != NULL) {
        if (provider_context->generation != 0u &&
            provider_context->generation != operation_generation) {
            if (operation_output != NULL) {
                provider_zero(operation_output, request->output_capacity);
                free(operation_output);
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
        free(operation_output);
    }
    if (return_flags != NULL) *return_flags = operation_return_flags;
    provider_zero(next_context, sizeof(next_context));
    if (provider_result == RIN_KERBEROS_OPERATION_RESULT_ERROR)
        return RIN_AUTH_PROVIDER_KRB_ERROR;
    return provider_result == RIN_KERBEROS_OPERATION_RESULT_CONTINUE_NEEDED
               ? RIN_AUTH_PROVIDER_CONTINUE_NEEDED
               : RIN_AUTH_PROVIDER_OK;
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
    if (input_length != 0u) {
        received_error = provider_gss_krb_error(
            input, input_length, &received_error_code);
        if (received_error < 0) return provider_defective_token(minor_status);
        if (received_error > 0) {
            if (minor_status != NULL)
                *minor_status = RINOS_KERBEROS_MINOR_PROTOCOL_ERROR |
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
        created_context = 1;
    }
    /* RinOS currently has a Kerberos-only provider.  The managed Unix PAL
     * enters credential acquisition through InitiateCredSpNego and may retain
     * PackageType.Negotiate for the first context call; normalize that
     * selector to the Kerberos GSS mechanism instead of advertising an
     * unimplemented SPNEGO exchange. */
    mechanism = package_type == PAL_GSS_NEGOTIATE
                    ? PAL_GSS_KERBEROS
                    : package_type;
    if (provider_context->owner == NULL ||
        !provider_build_sec_context_input(
            mechanism, requested_flags, name, NULL, 0u, input,
            input_length, &operation_input, &operation_input_size)) {
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
    if (operation_input != NULL) {
        provider_zero(operation_input, operation_input_size);
        free(operation_input);
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
    if (input_length != 0u) {
        received_error = provider_gss_krb_error(
            input, input_length, &received_error_code);
        if (received_error < 0) return provider_defective_token(minor_status);
        if (received_error > 0) {
            if (minor_status != NULL)
                *minor_status = RINOS_KERBEROS_MINOR_PROTOCOL_ERROR |
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
        created_context = 1;
    }
    mechanism = package_type == PAL_GSS_NEGOTIATE
                    ? PAL_GSS_KERBEROS
                    : package_type;
    if (provider_context->owner == NULL ||
        !provider_build_sec_context_input(
            mechanism, requested_flags, name, channel_binding,
            (uint32_t)channel_binding_size, input, input_length,
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
    provider_zero(operation_input, operation_input_size);
    free(operation_input);
    if (status != RIN_AUTH_PROVIDER_OK &&
        status != RIN_AUTH_PROVIDER_CONTINUE_NEEDED) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return status;
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
    (void)context;
    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    if (return_flags != NULL) *return_flags = 0u;
    if (ntlm_used != NULL) *ntlm_used = 0;
    if (security_context == NULL || output == NULL || return_flags == NULL ||
        ntlm_used == NULL || channel_binding_size < 0 ||
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
        created_context = 1;
    }
    if (provider_context->owner == NULL ||
        !provider_build_sec_context_input(
            PAL_GSS_KERBEROS, 0u, NULL, channel_binding,
            (uint32_t)channel_binding_size, input, input_length,
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
    if (status != RIN_AUTH_PROVIDER_OK &&
        status != RIN_AUTH_PROVIDER_CONTINUE_NEEDED) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
        return status;
    }
    *security_context = provider_context;
    if (minor_status != NULL) *minor_status = 0u;
    return status;
}

static uint32_t provider_delete_sec_context(
    void* context, uint32_t* minor_status, void** security_context)
{
    RinOsKerberosProviderContext* provider_context;
    RinOsKerberosProviderCredential credential = {0};
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
    credential.magic = RINOS_KERBEROS_CREDENTIAL_MAGIC;
    credential.kind = provider_context->kind;
    credential.owner_credential = provider_context->owner_credential;
    credential.owner = provider_credential_owner();
    request.struct_size = sizeof(request);
    request.version = RIN_KERBEROS_OPERATION_ABI_VERSION;
    request.operation = RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT;
    request.credential_kind = provider_context->kind;
    request.context_token_size = provider_context->token_size;
    request.output_capacity = 0u;
    status = provider_operation(&credential, provider_context, &request, NULL,
                                0u, NULL, 0u, NULL, minor_status);
    if (status != RIN_AUTH_PROVIDER_OK) {
        /* The owner still owns the remote context when cleanup fails.  Keep
         * the local handle alive so the caller can retry after a transient
         * transport failure; successful cleanup below is the commit point. */
        if (minor_status != NULL) *minor_status = 0u;
        return status;
    }
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
    credential.owner = provider_credential_owner();
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
    (void)context;
    return provider_message_operation(RIN_KERBEROS_OPERATION_GET_MIC,
                                      minor_status, security_context, NULL,
                                      input, input_length, output);
}

static uint32_t provider_verify_mic(
    void* context, uint32_t* minor_status, void* security_context,
    uint8_t* input, int32_t input_length, uint8_t* token, int32_t token_length)
{
    RinOsKerberosProviderContext* provider_context =
        (RinOsKerberosProviderContext*)security_context;
    RinOsKerberosProviderCredential credential = {0};
    RinKerberosProviderMessagePairInputV1 header;
    RinKerberosOperationRequestV1 request = {0};
    uint8_t* envelope;
    uint32_t total;
    uint32_t status;
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
    if (input_length != 0) memcpy(envelope + sizeof(header), input, input_length);
    if (token_length != 0)
        memcpy(envelope + sizeof(header) + input_length, token, token_length);
    credential.magic = RINOS_KERBEROS_CREDENTIAL_MAGIC;
    credential.kind = provider_context->kind;
    credential.owner_credential = provider_context->owner_credential;
    credential.owner = provider_credential_owner();
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
    if (minor_status != NULL) *minor_status = 0u;
    return status;
}

static void provider_release_buffer(void* context, void* buffer,
                                    uint64_t length)
{
    (void)context;
    if (buffer != NULL) {
        if (length <= SIZE_MAX) provider_zero(buffer, (size_t)length);
        free(buffer);
    }
}

static uint32_t provider_display_status_value(
    uint32_t* minor_status, uint32_t status_value, int is_minor,
    RinAuthProviderBufferV1* output)
{
    static const char* const hex = "0123456789ABCDEF";
    const char* message = NULL;
    const char* prefix = NULL;
    char formatted[64];
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
               (status_value & RINOS_KERBEROS_MINOR_PROTOCOL_ERROR) != 0u) {
        static const char prefix_text[] = "Kerberos protocol error ";
        char digits[10];
        uint32_t value = status_value & ~RINOS_KERBEROS_MINOR_PROTOCOL_ERROR;
        size_t digit_count = 0u;
        memcpy(formatted, prefix_text, sizeof(prefix_text) - 1u);
        length = sizeof(prefix_text) - 1u;
        do {
            digits[digit_count++] = (char)('0' + (value % 10u));
            value /= 10u;
        } while (value != 0u);
        while (digit_count != 0u) formatted[length++] = digits[--digit_count];
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

    bytes = (uint8_t*)malloc(length);
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

static uint32_t provider_get_user(
    void* context, uint32_t* minor_status, void* security_context,
    RinAuthProviderBufferV1* output)
{
    RinOsKerberosProviderContext* provider_context =
        (RinOsKerberosProviderContext*)security_context;
    const RinKerberosCredentialOwnerV1* owner;
    uint8_t* principal;
    uint32_t principal_size = 0u;
    uint64_t generation = 0u;
    uint32_t status;
    (void)context;
    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    if (output == NULL || !provider_context_valid(provider_context) ||
        provider_context->kind != RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR ||
        provider_context->state != RINOS_KERBEROS_CONTEXT_ESTABLISHED ||
        provider_context->generation == 0u)
        return provider_unavailable(minor_status);
    owner = provider_credential_owner();
    if (owner == NULL || owner->get_session_principal == NULL)
        return provider_unavailable(minor_status);
    principal = (uint8_t*)calloc(1u, RINOS_KERBEROS_MAX_PRINCIPAL_SIZE);
    if (principal == NULL) return provider_unavailable(minor_status);
    status = owner->get_session_principal(
        owner->context, minor_status, provider_context->owner_credential,
        principal, RINOS_KERBEROS_MAX_PRINCIPAL_SIZE, &principal_size,
        &generation);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK || principal_size == 0u ||
        principal_size > RINOS_KERBEROS_MAX_PRINCIPAL_SIZE ||
        generation != provider_context->generation) {
        provider_zero(principal, RINOS_KERBEROS_MAX_PRINCIPAL_SIZE);
        free(principal);
        return provider_status_from_owner(status, minor_status);
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
    return &g_provider;
#endif
}
