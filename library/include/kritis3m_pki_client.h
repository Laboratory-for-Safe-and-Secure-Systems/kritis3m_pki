#ifndef KRITIS3M_PKI_CLIENT_H
#define KRITIS3M_PKI_CLIENT_H

#include <stdint.h>
#include <stdbool.h>

#include "kritis3m_pki_common.h"


/* Structure for the metadata to be placed in the CSR */
typedef struct
{
        char const* CN;
        char const* O;
        char const* OU;
        char const* altName;
}
SigningRequestMetadata;


/* Forward declarations of our data types.
 * The actual declarations are in the source file to hide
 * the internal dependencies. */
typedef struct signingRequest SigningRequest;


/* Create a new SigningRequest object. */
SigningRequest* signingRequest_new(void);


/* Initialize the SigningRequest with given metadata.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int signingRequest_init(SigningRequest* request, SigningRequestMetadata const* metadata);


/* Finalize the SigningRequest using the related private key. Store the final PEM encoded output
 * in the buffer `buffer`. On function entry, `buffer_size` must contain the size of the provided
 * output buffer. After successful completion, `buffer_size` will contain the size of the written
 * output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int signingRequest_finalize(SigningRequest* request, PrivateKey* key, uint8_t* buffer, size_t* buffer_size);


/* Free the memory of given SigningRequest */
void signingRequest_free(SigningRequest* request);

#endif /* KRITIS3M_PKI_CLIENT_H */
