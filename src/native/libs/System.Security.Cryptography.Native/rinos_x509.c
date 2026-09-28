// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS X.509 chain-signature adapter.
 *
 * Certificate parsing and signature policy are owned by RinTLS.  Keeping the
 * managed chain PAL on this boundary prevents it from silently selecting a
 * host crypto provider or accepting algorithms that the product verifier
 * rejects (notably RSA-SHA1).
 */

#include <stdint.h>

#include "../Common/pal_compiler.h"
#include "rintls_config.h"
#include "x509/cert.h"

static int rinos_x509_der_length_valid(const uint8_t* der, int32_t length)
{
    return der != NULL && length > 0 &&
        (uint32_t)length <= RINTLS_MAX_CERT_SIZE;
}

PALEXPORT int32_t CryptoNative_RinOSX509VerifySignature(
    const uint8_t* certificate_der,
    int32_t certificate_length,
    const uint8_t* issuer_der,
    int32_t issuer_length)
{
    x509_cert_t certificate = { 0 };
    x509_cert_t issuer = { 0 };
    int32_t verified = 0;

    if (!rinos_x509_der_length_valid(certificate_der, certificate_length) ||
        !rinos_x509_der_length_valid(issuer_der, issuer_length)) {
        return 0;
    }

    if (x509_parse_cert(&certificate, certificate_der,
                        (rin_size_t)certificate_length) != X509_OK ||
        x509_parse_cert(&issuer, issuer_der,
                        (rin_size_t)issuer_length) != X509_OK) {
        goto cleanup;
    }

    verified = x509_verify_signature(&certificate, &issuer) == X509_OK ? 1 : 0;

cleanup:
    x509_cert_clear(&issuer);
    x509_cert_clear(&certificate);
    return verified;
}
