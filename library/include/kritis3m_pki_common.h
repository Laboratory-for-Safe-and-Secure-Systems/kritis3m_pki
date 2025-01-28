#ifndef KRITIS3M_PKI_COMMON_H
#define KRITIS3M_PKI_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Properly set the API visibility */
#if defined(BUILDING_KRITIS3M_PKI)
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || defined(_WIN32_WCE)
#if defined(BUILDING_KRITIS3M_PKI_SHARED)
#define KRITIS3M_PKI_API __declspec(dllexport)
#else
#define KRITIS3M_PKI_API
#endif
#else
#define KRITIS3M_PKI_API
#endif
#else /* BUILDING_KRITIS3M_PKI */
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || defined(_WIN32_WCE)
#if defined(BUILDING_KRITIS3M_PKI_SHARED)
#define KRITIS3M_PKI_API __declspec(dllimport)
#else
#define KRITIS3M_PKI_API
#endif
#else
#define KRITIS3M_PKI_API
#endif
#endif /* BUILDING_KRITIS3M_PKI */

#define PKCS11_LABEL_IDENTIFIER "pkcs11:"
#define PKCS11_LABEL_IDENTIFIER_LEN 7

/* Forward declarations of our data types.
 * The actual declarations are in the source file to hide
 * the internal dependencies. */
typedef struct privateKey PrivateKey;
typedef struct inputCert InputCert;

/* Error Codes */
enum KRITIS3M_PKI_ERROR_CODES
{
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
        KRITIS3M_PKI_PKCS11_ERROR = -13,
};

/* Available Log levels. Default is ERR. */
enum KRITIS3M_PKI_LOG_LEVEL
{
        KRITIS3M_PKI_LOG_LEVEL_ERR = 1U,
        KRITIS3M_PKI_LOG_LEVEL_WRN = 2U,
        KRITIS3M_PKI_LOG_LEVEL_INF = 3U,
        KRITIS3M_PKI_LOG_LEVEL_DBG = 4U,
};

/* Function pointer type for logging callbacks. */
typedef void (*kritis3m_pki_log_callback)(int32_t level, char const* message);

/* Data structure for the library configuration */
typedef struct
{
        bool logging_enabled;
        int32_t log_level;
        kritis3m_pki_log_callback log_callback;
} kritis3m_pki_configuration;

/* Initialize the KRITIS3M PKI libraries.
 *
 * Parameter is a pointer to a filled kritis3m_pki_configuration structure.
 *
 * Returns KRITIS3M_PKI_SUCCESS on success, negative error code in case of an error
 * (error message is logged to the console).
 */
KRITIS3M_PKI_API int kritis3m_pki_init(kritis3m_pki_configuration const* config);

/* Print a human-readable error message for the provided error code. */
KRITIS3M_PKI_API char const* kritis3m_pki_error_message(int error_code);

/* Create a new PrivateKey object */
KRITIS3M_PKI_API PrivateKey* privateKey_new(void);

/* Reference an external PrivateKey for secure element interaction. The `label` is copied
 * into the object.
 * Must be called *before* generating a new key or loading the key from an existing buffer.
 * This method also sets the external ref data for the alternative key. However, the user
 * can always overwrite this data by calling `privateKey_setAltExternalRef()`.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int privateKey_setExternalRef(PrivateKey* key, int deviceId, char const* label);

/* Reference an external alternative PrivateKey for secure element interaction. The `label`
 * is copied into the object.
 * Must be called *before* generating a new key or loading the key from an existing buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int privateKey_setAltExternalRef(PrivateKey* key, int deviceId, char const* label);

/* Initialize the given PrivateKey `key` using the PEM encoded data in the provided `buffer`
 * with `buffer_size` bytes. The key type is determined automatically. When the PEM file
 * contains both a primary and an alternative key, both are loaded. Otherwise, an alternative
 * key could be loaded from a separate buffer using `loadAltPrivateKeyFromPemBuffer()` if
 * required.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int
        privateKey_loadKeyFromBuffer(PrivateKey* key, uint8_t const* buffer, size_t buffer_size);

/* Load an alternative private key from the PEM encoded data in the provided `buffer` with
 * `buffer_size` bytes and store it decoded in the `key` PrivateKey object.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int
        privateKey_loadAltKeyFromBuffer(PrivateKey* key, uint8_t const* buffer, size_t buffer_size);

/* Generate a new public/private key pair for given `algorithm` and store the result in
 * the `key` object.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int privateKey_generateKey(PrivateKey* key, char const* algorithm);

/* Generate a new public/private key pair for given `algorithm` and store the result in
 * the `key` object as the alternative key.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int privateKey_generateAltKey(PrivateKey* key, char const* algorithm);

/* Copy a Privatekey object to another one.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int privateKey_copyKey(PrivateKey* destination, PrivateKey* source);

/* Convert the primary key in `key` to PEM and write the result into `buffer`. On function
 * entry, `buffer_size` must contain the size of the provided output buffer. After successful
 * completion, `buffer_size` will contain the size of the written output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int privateKey_writeKeyToBuffer(PrivateKey* key, uint8_t* buffer, size_t* buffer_size);

/* Convert the alternative key in `key` to PEM and write the result into `buffer`. On function
 * entry, `buffer_size` must contain the size of the provided output buffer. After successful
 * completion, `buffer_size` will contain the size of the written output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int privateKey_writeAltKeyToBuffer(PrivateKey* key, uint8_t* buffer, size_t* buffer_size);

/* Free the memory of given PrivateKey */
KRITIS3M_PKI_API void privateKey_free(PrivateKey* key);

/* Create a new InputCert object. */
KRITIS3M_PKI_API InputCert* inputCert_new(void);

/* Initialize the given InputCert `cert` using the PEM encoded data in the provided `buffer`
 * with `buffer_size` bytes. Check if it is compatible with the provided private key.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int inputCert_initFromBuffer(InputCert* cert,
                                              uint8_t const* buffer,
                                              size_t buffer_size,
                                              PrivateKey* privateKey);

/* Free the memory of given InputCert */
KRITIS3M_PKI_API void inputCert_free(InputCert* cert);

/* Shutdown and cleanup for the KRITIS3M PKI libraries. */
KRITIS3M_PKI_API void kritis3m_pki_shutdown(void);

#endif /* KRITIS3M_PKI_COMMON_H */
