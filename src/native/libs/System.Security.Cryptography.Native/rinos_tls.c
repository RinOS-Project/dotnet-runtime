// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include <stdint.h>

#include "rintls.h"

/* System.Net.Security drives RinTLS with a bounded, non-blocking buffer pair.
 * No socket is owned by this adapter: the managed Socket remains responsible
 * for moving the ciphertext returned by ReadOutput to the peer and for feeding
 * received ciphertext back to Handshake/Decrypt. */
#define RINOS_TLS_INPUT_CAP  (64u * 1024u)
#define RINOS_TLS_OUTPUT_CAP (64u * 1024u)

typedef struct rinos_tls_adapter {
    rintls_ctx* context;
    u8 input[RINOS_TLS_INPUT_CAP];
    rin_size_t input_offset;
    rin_size_t input_length;
    u8 output[RINOS_TLS_OUTPUT_CAP];
    rin_size_t output_offset;
    rin_size_t output_length;
    int closed;
} rinos_tls_adapter;

static void rinos_move(u8* destination, const u8* source, rin_size_t length)
{
    if (destination == source || length == 0u) return;
    if (destination < source) {
        while (length--) *destination++ = *source++;
    } else {
        destination += length;
        source += length;
        while (length--) *--destination = *--source;
    }
}

static int rinos_append_input(rinos_tls_adapter* adapter,
                              const u8* data, rin_size_t length)
{
    if (!adapter || (!data && length != 0u)) return RINTLS_ERR_MEMORY;
    if (adapter->input_offset > RINOS_TLS_INPUT_CAP ||
        adapter->input_length > RINOS_TLS_INPUT_CAP - adapter->input_offset)
        return RINTLS_ERR_MEMORY;
    if (length > RINOS_TLS_INPUT_CAP - adapter->input_offset -
                     adapter->input_length) {
        if (adapter->input_offset != 0u) {
            rinos_move(adapter->input,
                       adapter->input + adapter->input_offset,
                       adapter->input_length);
            adapter->input_offset = 0u;
        }
    }
    if (length > RINOS_TLS_INPUT_CAP - adapter->input_length)
        return RINTLS_ERR_WANT_WRITE;
    if (length != 0u)
        rintls_memcpy(adapter->input + adapter->input_offset + adapter->input_length,
                      data, length);
    adapter->input_length += length;
    return RINTLS_OK;
}

static int rinos_append_output(rinos_tls_adapter* adapter,
                               const u8* data, rin_size_t length)
{
    if (!adapter || (!data && length != 0u)) return RINTLS_ERR_MEMORY;
    if (adapter->output_offset > RINOS_TLS_OUTPUT_CAP ||
        adapter->output_length > RINOS_TLS_OUTPUT_CAP - adapter->output_offset)
        return RINTLS_ERR_MEMORY;
    if (length > RINOS_TLS_OUTPUT_CAP - adapter->output_offset -
                     adapter->output_length) {
        if (adapter->output_offset != 0u) {
            rinos_move(adapter->output,
                       adapter->output + adapter->output_offset,
                       adapter->output_length);
            adapter->output_offset = 0u;
        }
    }
    if (length > RINOS_TLS_OUTPUT_CAP - adapter->output_length)
        return RINTLS_ERR_WANT_WRITE;
    if (length != 0u)
        rintls_memcpy(adapter->output + adapter->output_offset + adapter->output_length,
                      data, length);
    adapter->output_length += length;
    return RINTLS_OK;
}

static int rinos_send(void* opaque, const u8* data, rin_size_t length)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)opaque;
    int result = rinos_append_output(adapter, data, length);
    return result == RINTLS_OK ? (int)length : result;
}

static int rinos_recv(void* opaque, u8* data, rin_size_t capacity)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)opaque;
    rin_size_t length;

    if (!adapter || (!data && capacity != 0u)) return RINTLS_ERR_MEMORY;
    if (adapter->input_length == 0u) return RINTLS_ERR_WANT_READ;
    length = adapter->input_length < capacity ? adapter->input_length : capacity;
    if (length != 0u)
        rintls_memcpy(data, adapter->input + adapter->input_offset, length);
    adapter->input_offset += length;
    adapter->input_length -= length;
    if (adapter->input_length == 0u) adapter->input_offset = 0u;
    return (int)length;
}

static rin_size_t rinos_consumed(rinos_tls_adapter* adapter,
                                 rin_size_t old_input_length,
                                 rin_size_t supplied_length)
{
    rin_size_t newly_consumed = 0u;
    if (adapter->input_length > old_input_length) {
        rin_size_t remaining_new = adapter->input_length - old_input_length;
        newly_consumed = supplied_length > remaining_new
            ? supplied_length - remaining_new : 0u;
    } else {
        newly_consumed = supplied_length;
    }
    return newly_consumed;
}

void* CryptoNative_RinTlsCreate(int32_t is_server, const char* hostname,
                                uint32_t options, uint64_t trusted_time,
                                int32_t* error)
{
    rinos_tls_adapter* adapter;
    int result;

    if (error) *error = RINTLS_OK;
    if (is_server != 0) {
        if (error) *error = RINTLS_ERR_UNSUPPORTED;
        return RIN_NULL;
    }
    if (!hostname || hostname[0] == '\0') {
        if (error) *error = RINTLS_ERR_HOSTNAME;
        return RIN_NULL;
    }

    adapter = (rinos_tls_adapter*)rintls_malloc(sizeof(*adapter));
    if (!adapter) {
        if (error) *error = RINTLS_ERR_MEMORY;
        return RIN_NULL;
    }
    rintls_memset(adapter, 0, sizeof(*adapter));
    adapter->context = rintls_new();
    if (!adapter->context) {
        rintls_mem_free(adapter);
        if (error) *error = RINTLS_ERR_MEMORY;
        return RIN_NULL;
    }

    result = rintls_set_io(adapter->context, rinos_send, rinos_recv, adapter);
    if (result == RINTLS_OK) result = rintls_set_hostname(adapter->context, hostname);
    if (result == RINTLS_OK) result = rintls_set_options(adapter->context, options);
    if (result == RINTLS_OK) result = rintls_set_trusted_time(adapter->context, trusted_time);
    if (result != RINTLS_OK) {
        rintls_free(adapter->context);
        rintls_memzero(adapter, sizeof(*adapter));
        rintls_mem_free(adapter);
        if (error) *error = result;
        return RIN_NULL;
    }
    return adapter;
}

void CryptoNative_RinTlsDestroy(void* handle)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    if (!adapter) return;
    if (adapter->context) rintls_free(adapter->context);
    rintls_memzero(adapter, sizeof(*adapter));
    rintls_mem_free(adapter);
}

int32_t CryptoNative_RinTlsSetCipherSuites(void* handle,
                                           const uint16_t* cipher_suites,
                                           int32_t cipher_suite_count)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    if (!adapter || cipher_suite_count <= 0 ||
        (cipher_suite_count != 0 && !cipher_suites))
        return RINTLS_ERR_MEMORY;
    return rintls_set_cipher_suites(adapter->context, cipher_suites,
                                    (rin_size_t)cipher_suite_count);
}

int32_t CryptoNative_RinTlsLoadTrustStore(void* handle,
                                          const uint8_t* bundle,
                                          int32_t bundle_length)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    if (!adapter || bundle_length < 0 ||
        (bundle_length != 0 && !bundle)) return RINTLS_ERR_MEMORY;
    return rintls_load_trust_store(adapter->context, bundle,
                                   (rin_size_t)bundle_length);
}

int32_t CryptoNative_RinTlsHandshake(void* handle, const uint8_t* input,
                                     int32_t input_length, int32_t* consumed)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rin_size_t old_input_length;
    int result;

    if (consumed) *consumed = 0;
    if (!adapter || input_length < 0 ||
        (input_length != 0 && !input)) return RINTLS_ERR_MEMORY;
    if (adapter->closed) return RINTLS_ERR_CLOSED;
    old_input_length = adapter->input_length;
    result = rinos_append_input(adapter, input, (rin_size_t)input_length);
    if (result != RINTLS_OK) return result;
    result = rintls_handshake_step(adapter->context);
    /* RinTLS pauses immediately after a TLS 1.3 CertificateRequest. Surface
     * that protocol state as the PAL's credential callback status; the
     * managed side can then install a certificate-list and signer without
     * feeding the already-consumed CertificateRequest a second time. */
    if ((result == RINTLS_ERR_WANT_READ ||
         result == RINTLS_ERR_CERTIFICATE) &&
        rintls_client_certificate_requested(adapter->context) &&
        !rintls_client_certificate_configured(adapter->context)) {
        result = RINTLS_ERR_WANT_CREDENTIALS;
    }
    if (consumed)
        *consumed = (int32_t)rinos_consumed(adapter, old_input_length,
                                            (rin_size_t)input_length);
    return result;
}

int32_t CryptoNative_RinTlsSetClientCertificate(
    void* handle, const uint8_t* certificate_list, int32_t certificate_list_length,
    void* signer, void* signer_opaque)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    if (!adapter || certificate_list_length < 0 ||
        (certificate_list_length != 0 && !certificate_list))
        return RINTLS_ERR_MEMORY;
    return rintls_set_client_certificate(
        adapter->context, certificate_list, (rin_size_t)certificate_list_length,
        (rintls_client_certificate_sign_func)signer, signer_opaque);
}

int32_t CryptoNative_RinTlsClientCertificateRequested(void* handle)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    return adapter && rintls_client_certificate_requested(adapter->context)
        ? 1 : 0;
}

int32_t CryptoNative_RinTlsPendingOutputLength(void* handle)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    return adapter ? (int32_t)adapter->output_length : 0;
}

int32_t CryptoNative_RinTlsReadOutput(void* handle, uint8_t* destination,
                                      int32_t capacity)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rin_size_t length;

    if (!adapter || capacity < 0 || (capacity != 0 && !destination))
        return RINTLS_ERR_MEMORY;
    length = adapter->output_length < (rin_size_t)capacity
        ? adapter->output_length : (rin_size_t)capacity;
    if (length != 0u)
        rintls_memcpy(destination, adapter->output + adapter->output_offset, length);
    adapter->output_offset += length;
    adapter->output_length -= length;
    if (adapter->output_length == 0u) adapter->output_offset = 0u;
    return (int32_t)length;
}

int32_t CryptoNative_RinTlsEncrypt(void* handle, const uint8_t* plaintext,
                                   int32_t plaintext_length, int32_t* consumed)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    int result;
    if (consumed) *consumed = 0;
    if (!adapter || plaintext_length < 0 ||
        (plaintext_length != 0 && !plaintext)) return RINTLS_ERR_MEMORY;
    if (adapter->closed) return RINTLS_ERR_CLOSED;
    result = rintls_send(adapter->context, plaintext,
                         (rin_size_t)plaintext_length);
    if (result >= 0 && consumed) *consumed = result;
    return result < 0 ? result : RINTLS_OK;
}

int32_t CryptoNative_RinTlsDecrypt(void* handle, const uint8_t* encrypted,
                                   int32_t encrypted_length, uint8_t* plaintext,
                                   int32_t plaintext_capacity, int32_t* consumed,
                                   int32_t* written)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rin_size_t old_input_length;
    int result;

    if (consumed) *consumed = 0;
    if (written) *written = 0;
    if (!adapter || encrypted_length < 0 || plaintext_capacity < 0 ||
        (encrypted_length != 0 && !encrypted) ||
        (plaintext_capacity != 0 && !plaintext)) return RINTLS_ERR_MEMORY;
    if (adapter->closed) return RINTLS_ERR_CLOSED;
    old_input_length = adapter->input_length;
    result = rinos_append_input(adapter, encrypted, (rin_size_t)encrypted_length);
    if (result != RINTLS_OK) return result;
    result = rintls_recv(adapter->context, plaintext,
                         (rin_size_t)plaintext_capacity);
    if (consumed)
        *consumed = (int32_t)rinos_consumed(adapter, old_input_length,
                                            (rin_size_t)encrypted_length);
    if (result == 0 && rintls_get_error(adapter->context) == RINTLS_ERR_CLOSED) {
        adapter->closed = 1;
        return RINTLS_ERR_CLOSED;
    }
    if (result < 0) return result;
    if (written) *written = result;
    return RINTLS_OK;
}

int32_t CryptoNative_RinTlsShutdown(void* handle)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    int result;
    if (!adapter) return RINTLS_ERR_MEMORY;
    if (adapter->closed) return RINTLS_OK;
    result = rintls_close(adapter->context);
    adapter->closed = 1;
    return result;
}

int32_t CryptoNative_RinTlsIsClosed(void* handle)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    return !adapter || adapter->closed;
}

int32_t CryptoNative_RinTlsGetVersion(void* handle)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    return adapter ? (int32_t)rintls_get_version(adapter->context) : 0;
}

int32_t CryptoNative_RinTlsGetCipherSuite(void* handle)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    return adapter ? (int32_t)rintls_get_cipher_suite(adapter->context) : 0;
}

int32_t CryptoNative_RinTlsGetApplicationProtocolLength(void* handle,
                                                        int32_t* length)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rin_size_t required = 0u;
    int result;

    if (length) *length = 0;
    if (!adapter || !length) return RINTLS_ERR_MEMORY;
    result = rintls_get_application_protocol(adapter->context, RIN_NULL, 0u,
                                             &required);
    if (result != RINTLS_ERR_MEMORY && result != RINTLS_OK)
        return result;
    if (required > 0x7fffffffU) return RINTLS_ERR_MEMORY;
    *length = (int32_t)required;
    return RINTLS_OK;
}

int32_t CryptoNative_RinTlsCopyApplicationProtocol(void* handle,
                                                   uint8_t* destination,
                                                   int32_t capacity)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rin_size_t length = 0u;

    if (!adapter || capacity < 0 || (capacity != 0 && !destination))
        return RINTLS_ERR_MEMORY;
    return rintls_get_application_protocol(adapter->context, destination,
                                           (rin_size_t)capacity, &length);
}

int32_t CryptoNative_RinTlsGetError(void* handle)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    return adapter ? rintls_get_error(adapter->context) : RINTLS_ERR_MEMORY;
}

int32_t CryptoNative_RinTlsGetPeerCertificateLength(void* handle,
                                                    int32_t* length)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rin_size_t required = 0u;
    int result;
    if (length) *length = 0;
    if (!adapter || !length) return RINTLS_ERR_MEMORY;
    result = rintls_get_peer_certificate(adapter->context, RIN_NULL, 0u,
                                         &required);
    if (result != RINTLS_ERR_MEMORY) return result;
    if (required > 0x7fffffffU) return RINTLS_ERR_MEMORY;
    *length = (int32_t)required;
    return RINTLS_OK;
}

int32_t CryptoNative_RinTlsCopyPeerCertificate(void* handle, uint8_t* destination,
                                               int32_t capacity)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rin_size_t length = 0u;
    if (!adapter || capacity < 0 || (capacity != 0 && !destination))
        return RINTLS_ERR_MEMORY;
    return rintls_get_peer_certificate(adapter->context, destination,
                                       (rin_size_t)capacity, &length);
}

int32_t CryptoNative_RinTlsGetPeerCertificateChainLength(void* handle,
                                                         int32_t* length)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rin_size_t required = 0u;
    int result;
    if (length) *length = 0;
    if (!adapter || !length) return RINTLS_ERR_MEMORY;
    result = rintls_get_peer_certificate_chain(adapter->context, RIN_NULL, 0u,
                                               &required);
    if (result != RINTLS_ERR_MEMORY) return result;
    if (required > 0x7fffffffU) return RINTLS_ERR_MEMORY;
    *length = (int32_t)required;
    return RINTLS_OK;
}

int32_t CryptoNative_RinTlsCopyPeerCertificateChain(void* handle,
                                                    uint8_t* destination,
                                                    int32_t capacity)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rin_size_t length = 0u;
    if (!adapter || capacity < 0 || (capacity != 0 && !destination))
        return RINTLS_ERR_MEMORY;
    return rintls_get_peer_certificate_chain(adapter->context, destination,
                                             (rin_size_t)capacity, &length);
}

int32_t CryptoNative_RinTlsGetPeerRevocationEndpoint(
    void* handle, int32_t source, uint8_t* destination, int32_t capacity,
    int32_t* length)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rintls_revocation_endpoints endpoints;
    const char* selected = RIN_NULL;
    rin_size_t selected_length = 0u;
    int result;

    if (length) *length = 0;
    if (!adapter || capacity < 0 || (capacity != 0 && !destination) ||
        !length || (source != (int32_t)RINTLS_REVOCATION_SOURCE_OCSP &&
                    source != (int32_t)RINTLS_REVOCATION_SOURCE_CRL))
        return RINTLS_ERR_MEMORY;

    rintls_memset(&endpoints, 0, sizeof(endpoints));
    result = rintls_get_peer_revocation_endpoints(adapter->context, &endpoints);
    if (result != RINTLS_OK) return result;
    selected = source == (int32_t)RINTLS_REVOCATION_SOURCE_OCSP
        ? endpoints.ocsp_url : endpoints.crl_url;
    while (selected_length < RINTLS_MAX_REVOCATION_URL_BYTES &&
           selected[selected_length] != '\0') {
        ++selected_length;
    }
    if (selected_length == RINTLS_MAX_REVOCATION_URL_BYTES ||
        selected_length > (rin_size_t)capacity -
                           (selected_length < (rin_size_t)capacity ? 1u : 0u)) {
        return RINTLS_ERR_MEMORY;
    }
    if (selected_length != 0u)
        rintls_memcpy(destination, selected, selected_length);
    if (capacity > (int32_t)selected_length)
        destination[selected_length] = 0;
    *length = (int32_t)selected_length;
    rintls_secure_zero(&endpoints, sizeof(endpoints));
    return RINTLS_OK;
}

int32_t CryptoNative_RinTlsVerifyPeerRevocation(
    void* handle, int32_t source, const uint8_t* response,
    int32_t response_length, uint64_t sequence, int32_t* status)
{
    rinos_tls_adapter* adapter = (rinos_tls_adapter*)handle;
    rintls_revocation_evidence evidence;
    int result;

    if (status) *status = 0;
    if (!adapter || response_length <= 0 || !response || sequence == 0u ||
        !status || (source != (int32_t)RINTLS_REVOCATION_SOURCE_OCSP &&
                    source != (int32_t)RINTLS_REVOCATION_SOURCE_CRL))
        return RINTLS_ERR_MEMORY;

    rintls_memset(&evidence, 0, sizeof(evidence));
    if (source == (int32_t)RINTLS_REVOCATION_SOURCE_OCSP) {
        result = rintls_verify_peer_ocsp(
            adapter->context, response, (rin_size_t)response_length, sequence,
            &evidence);
    } else {
        result = rintls_verify_peer_crl(
            adapter->context, response, (rin_size_t)response_length, sequence,
            &evidence);
    }
    if (result == RINTLS_OK &&
        (evidence.status == RINTLS_REVOCATION_STATUS_GOOD ||
         evidence.status == RINTLS_REVOCATION_STATUS_REVOKED)) {
        *status = (int32_t)evidence.status;
    } else if (result == RINTLS_OK) {
        result = RINTLS_ERR_CERTIFICATE;
    }
    rintls_secure_zero(&evidence, sizeof(evidence));
    return result;
}
