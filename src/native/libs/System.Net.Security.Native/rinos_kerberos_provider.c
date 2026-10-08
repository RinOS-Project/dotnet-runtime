// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS Kerberos transport provider.
 *
 * This file is intentionally a transport boundary, not a replacement for
 * RFC 4120/4121.  The authenticated keyring owner receives the only access to
 * raw ccache/keytab bytes.  This provider sends bounded GSS inputs to the owner,
 * carries back opaque context/output tokens, and refuses to manufacture a
 * credential or a successful token when the service-side RFC implementation is
 * absent.
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
    return provider_unavailable(minor_status);
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
    RinKerberosProviderSecContextInputV1 header;
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
    if (token_size != 0u) memcpy(bytes + total, token, token_size);
    *output = bytes;
    *output_size = total;
    return 1u;
}

static uint32_t provider_operation(
    RinOsKerberosProviderCredential* credential,
    RinOsKerberosProviderContext* provider_context,
    RinKerberosOperationRequestV1* request, const uint8_t* input,
    uint32_t input_size, RinAuthProviderBufferV1* output,
    uint32_t update_context, uint32_t* return_flags)
{
    const RinKerberosOperationOwnerV1* owner;
    uint8_t* operation_output = NULL;
    uint8_t next_context[RIN_KERBEROS_OPERATION_MAX_CONTEXT_TOKEN_SIZE];
    uint32_t operation_output_size = 0u;
    uint32_t next_context_size = 0u;
    uint64_t operation_generation = 0u;
    uint32_t provider_result = 0u;
    uint32_t operation_return_flags = 0u;
    uint32_t status;

    memset(next_context, 0, sizeof(next_context));
    if (return_flags != NULL) *return_flags = 0u;
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
        request->context_token_size = provider_context->token_size;
    }
    if (request->output_capacity != 0u) {
        operation_output = (uint8_t*)calloc(1u, request->output_capacity);
        if (operation_output == NULL) return RIN_AUTH_PROVIDER_UNAVAILABLE;
    }
    status = owner->operation(
        owner->context, NULL, credential->owner_credential, request,
        provider_context != NULL ? provider_context->token : NULL,
        provider_context != NULL ? provider_context->token_size : 0u, input,
        input_size, operation_output, request->output_capacity,
        &operation_output_size, next_context, sizeof(next_context),
        &next_context_size, &operation_generation, &provider_result,
        &operation_return_flags);
    if (status != RIN_KERBEROS_CREDENTIAL_OWNER_OK ||
        provider_result > RIN_KERBEROS_OPERATION_RESULT_CONTINUE_NEEDED ||
        operation_generation == 0u ||
        operation_output_size > request->output_capacity ||
        next_context_size > sizeof(next_context) ||
        (operation_output_size != 0u && output == NULL) ||
        (!update_context && next_context_size != 0u) ||
        (update_context && provider_context == NULL) ||
        (provider_result == RIN_KERBEROS_OPERATION_RESULT_CONTINUE_NEEDED &&
         request->operation != RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT &&
         request->operation != RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT) ||
        (operation_return_flags &
         ~RIN_KERBEROS_OPERATION_KNOWN_RETURN_FLAGS) != 0u) {
        if (operation_output != NULL) {
            provider_zero(operation_output, request->output_capacity);
            free(operation_output);
        }
        provider_zero(next_context, sizeof(next_context));
        return RIN_AUTH_PROVIDER_UNAVAILABLE;
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
    int created_context = 0;
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
        provider_context->owner_credential = credential->owner_credential;
        provider_context->owner = provider_operation_owner();
        created_context = 1;
    }
    if (provider_context->owner == NULL ||
        !provider_build_sec_context_input(
            package_type, requested_flags, name, NULL, 0u, input,
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
                                1u, return_flags);
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
        !provider_name_valid(name) ||
        (package_type != PAL_GSS_NEGOTIATE &&
         package_type != PAL_GSS_KERBEROS) ||
        !provider_credential_valid(credential,
                                   RIN_KERBEROS_OPERATION_CREDENTIAL_INITIATOR))
        return provider_unavailable(minor_status);
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
        provider_context->owner_credential = credential->owner_credential;
        provider_context->owner = provider_operation_owner();
        created_context = 1;
    }
    if (provider_context->owner == NULL ||
        !provider_build_sec_context_input(
            package_type, requested_flags, name, channel_binding,
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
                                1u, return_flags);
    provider_zero(operation_input, operation_input_size);
    free(operation_input);
    if (status != RIN_AUTH_PROVIDER_OK &&
        status != RIN_AUTH_PROVIDER_CONTINUE_NEEDED) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
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
                                1u, return_flags);
    provider_zero(operation_input, operation_input_size);
    free(operation_input);
    if (status != RIN_AUTH_PROVIDER_OK &&
        status != RIN_AUTH_PROVIDER_CONTINUE_NEEDED) {
        if (created_context) {
            provider_zero(provider_context, sizeof(*provider_context));
            free(provider_context);
            *security_context = NULL;
        }
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
                                0u, NULL, 0u, NULL);
    if (status != RIN_AUTH_PROVIDER_OK) {
        if (minor_status != NULL) *minor_status = 0u;
        return provider_unavailable(minor_status);
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
    RinKerberosOperationRequestV1 request = {0};
    uint32_t status;
    if (!provider_context_valid(provider_context) || output == NULL ||
        input_length < 0 ||
        (input_length != 0 && input == NULL))
        return provider_unavailable(minor_status);
    credential.magic = RINOS_KERBEROS_CREDENTIAL_MAGIC;
    credential.kind = provider_context->kind;
    credential.owner_credential = provider_context->owner_credential;
    credential.owner = provider_credential_owner();
    request.struct_size = sizeof(request);
    request.version = RIN_KERBEROS_OPERATION_ABI_VERSION;
    request.operation = operation;
    request.credential_kind = provider_context->kind;
    request.flags = encrypt != NULL && *encrypt != 0
                        ? RIN_KERBEROS_OPERATION_FLAG_ENCRYPT
                        : 0u;
    request.input_size = (uint32_t)input_length;
    request.output_capacity = RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE;
    status = provider_operation(&credential, provider_context, &request, input,
                                (uint32_t)input_length, output, 1u, NULL);
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
    if (!provider_context_valid(provider_context) || input_length < 0 ||
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
                                envelope, total, NULL, 1u, NULL);
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

static uint32_t provider_display_status(
    void* context, uint32_t* minor_status, uint32_t status_value,
    RinAuthProviderBufferV1* output)
{
    (void)context;
    (void)status_value;
    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    return provider_unavailable(minor_status);
}

static uint32_t provider_get_user(
    void* context, uint32_t* minor_status, void* security_context,
    RinAuthProviderBufferV1* output)
{
    (void)context;
    (void)security_context;
    if (output != NULL) {
        output->data = NULL;
        output->length = 0u;
    }
    /* The operation ABI has no authenticated principal inquiry yet; do not
     * turn a local name or fixed string into DefaultCredentials identity. */
    return provider_unavailable(minor_status);
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
    .display_minor_status = provider_display_status,
    .display_major_status = provider_display_status,
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
    /* The transport is compiled and audited, but capability advertisement is
     * withheld until the service-side RFC 4120/4121 engine is linked. */
    return NULL;
#else
    return &g_provider;
#endif
}
