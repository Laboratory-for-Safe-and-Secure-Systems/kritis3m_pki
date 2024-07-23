#ifndef KRITIS3M_PKI_COMMON_H
#define KRITIS3M_PKI_COMMON_H


#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


/* Forward declarations of our data types.
 * The actual declarations are in the source file to hide
 * the internal dependencies. */
typedef struct privateKey PrivateKey;


/* Error Codes */
enum KRITIS3M_PKI_ERROR_CODES {
        KRITIS3M_PKI_SUCCESS = 0,
        KRITIS3M_PKI_MEMORY_ERROR = -1,
        KRITIS3M_PKI_ARGUMENT_ERROR = -2,
        KRITIS3M_PKI_PEM_DECODE_ERROR = -3,
        KRITIS3M_PKI_PEM_ENCODE_ERROR = -4,
        KRITIS3M_PKI_KEY_ERROR = -5,
        KRITIS3M_PKI_KEY_UNSUPPORTED = -6,
        KRITIS3M_PKI_CSR_ERROR = -7,
        KRITIS3M_PKI_CSR_EXT_ERROR = -8,
        KRITIS3M_PKI_CSR_SIGN_ERROR = -9,
        KRITIS3M_PKI_CERT_ERROR = -10,
        KRITIS3M_PKI_CERT_EXT_ERROR = -11,
        KRITIS3M_PKI_CERT_SIGN_ERROR = -12,
};


/* Print a human-readable error message for the provided error code. */
char const* kritis3m_pki_error_message(int error_code);


/* Create a new PrivateKey object */
PrivateKey* privateKey_new(void);


/* Reference an external PrivateKey for secure element interaction. The ID is copied into the
 * object.
 * Must be called *before* generating a new key or loading the key from an existing buffer.
 * This method also sets the external ref data for the alternative key. However, the user
 * can always overwrite this data by calling `privateKey_setAltExternalRef()`.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_setExternalRef(PrivateKey* key, int deviceId, uint8_t const* id, size_t size);


/* Reference an external alternative PrivateKey for secure element interaction. The ID is copied
 * into the object.
 * Must be called *before* generating a new key or loading the key from an existing buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_setAltExternalRef(PrivateKey* key, int deviceId, uint8_t const* id, size_t size);


/* Initialize the given PrivateKey `key` using the PEM encoded data in the provided `buffer`
 * with `buffer_size` bytes. The key type is determined automatically. When the PEM file
 * contains both a primary and an alternative key, both are loaded. Otherwise, an alternative
 * key could be loaded from a separate buffer using `loadAltPrivateKeyFromPemBuffer()` if
 * required.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_loadKeyFromBuffer(PrivateKey* key, uint8_t const* buffer, size_t buffer_size);


/* Load an alternative private key from the PEM encoded data in the provided `buffer` with
 * `buffer_size` bytes and store it decoded in the `key` PrivateKey object.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_loadAltKeyFromBuffer(PrivateKey* key, uint8_t const* buffer, size_t buffer_size);


/* Generate a new public/private key pair for given `algorithm` and store the result in
 * the `key` object.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_generateKey(PrivateKey* key, char const* algorithm);


/* Generate a new public/private key pair for given `algorithm` and store the result in
 * the `key` object as the alternative key.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_generateAltKey(PrivateKey* key, char const* algorithm);


/* Convert the primary key in `key` to PEM and write the result into `buffer`. On function
 * entry, `buffer_size` must contain the size of the provided output buffer. After successful
 * completion, `buffer_size` will contain the size of the written output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_writeKeyToBuffer(PrivateKey* key, uint8_t* buffer, size_t* buffer_size);


/* Convert the alternative key in `key` to PEM and write the result into `buffer`. On function
 * entry, `buffer_size` must contain the size of the provided output buffer. After successful
 * completion, `buffer_size` will contain the size of the written output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_writeAltKeyToBuffer(PrivateKey* key, uint8_t* buffer, size_t* buffer_size);


/* Free the memory of given PrivateKey */
void privateKey_free(PrivateKey* key);


#endif /* KRITIS3M_PKI_COMMON_H */
