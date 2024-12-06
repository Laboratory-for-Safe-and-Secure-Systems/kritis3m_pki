#ifndef KRITIS3M_PKI_SERVER_H
#define KRITIS3M_PKI_SERVER_H

#include <stdbool.h>
#include <stdint.h>

#include "kritis3m_pki_common.h"

/* Forward declarations of our data types.
 * The actual declarations are in the source file to hide
 * the internal dependencies. */
typedef struct issuerCert IssuerCert;
typedef struct outputCert OutputCert;

/* Initialize the PKCS#11 token for the issuer key. Use the library from `path` and
 * the token found at `slot_id`. If `-1` is supplied as `slot_id`, the first found
 * token is used automatically. The `pin` for the token is optional (supply `NULL`
 * and `0` as parameters).
 *
 * Return value is the `device_id` for the initialized token in case of success
 * (positive integer > 0), negative error code otherwise.
 */
KRITIS3M_PKI_API int kritis3m_pki_init_issuer_token(char const* path,
                                                    int slot_id,
                                                    uint8_t const* pin,
                                                    size_t pin_size);

/* Close the PKCS#11 token for the issuer key. */
KRITIS3M_PKI_API int kritis3m_pki_close_issuer_token(void);

/* Create a new IssuerCert object. */
KRITIS3M_PKI_API IssuerCert* issuerCert_new(void);

/* Initialize the given IssuerCert `cert` using the PEM encoded data in the provided `buffer`
 * with `buffer_size` bytes. Check if it is compatible with the provided issuer private key.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int issuerCert_initFromBuffer(IssuerCert* cert,
                                               uint8_t const* buffer,
                                               size_t buffer_size,
                                               PrivateKey* issuerKey);

/* Free the memory of given IssuerCert */
KRITIS3M_PKI_API void issuerCert_free(IssuerCert* cert);

/* Create a new OutputCert object. */
KRITIS3M_PKI_API OutputCert* outputCert_new(void);

/* Initialize the given OutputCert from the CSR, PEM encoded in the provided `bufffer` with
 * `buffer_size` bytes.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int
        outputCert_initFromCsr(OutputCert* outputCert, uint8_t const* buffer, size_t buffer_size);

/* Set issuer data of the new OutputCert `outputCert` using data from IssuerCert `issuerCert`
 * and issuer private key `issuerKey`.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int outputCert_setIssuerData(OutputCert* outputCert,
                                              IssuerCert* issuerCert,
                                              PrivateKey* issuerKey);

/* Set the validity period to `days` days of the new OutputCert `outputCert`.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int outputCert_setValidity(OutputCert* outputCert, int days);

/* Configure the new OutputCert to be a CA certificate, capable of signing new certificates.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int outputCert_configureAsCA(OutputCert* outputCert);

/* Configure the new OutputCert to be an entity certificate for authentication.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int outputCert_configureAsEntity(OutputCert* outputCert);

/* Finalize the new OutputCert by signing it with the issuer private key. Store the final PEM
 * encoded output in the buffer `buffer`. On function entry, `buffer_size` must contain the
 * size of the provided output buffer. After successful completion, `buffer_size` will contain
 * the size of the written output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int outputCert_finalize(OutputCert* outputCert,
                                         PrivateKey* issuerKey,
                                         uint8_t* buffer,
                                         size_t* buffer_size);

/* Free the memory of given OutputCert */
KRITIS3M_PKI_API void outputCert_free(OutputCert* outputCert);

#endif /* KRITIS3M_PKI_SERVER_H */
