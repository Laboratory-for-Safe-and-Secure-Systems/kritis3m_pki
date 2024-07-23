#include "kritis3m_pki_common.h"
#include "kritis3m_pki_priv.h"


/* Print a human-readable error message for the provided error code. */
char const* kritis3m_pki_error_message(int error_code)
{
        switch (error_code)
        {
        case KRITIS3M_PKI_SUCCESS:
                return "Success";
        case KRITIS3M_PKI_MEMORY_ERROR:
                return "Memory allocation error";
        case KRITIS3M_PKI_ARGUMENT_ERROR:
                return "Invalid argument";
        case KRITIS3M_PKI_PEM_DECODE_ERROR:
                return "PEM decode error";
        case KRITIS3M_PKI_PEM_ENCODE_ERROR:
                return "PEM encode error";
        case KRITIS3M_PKI_KEY_ERROR:
                return "Key error";
        case KRITIS3M_PKI_KEY_UNSUPPORTED:
                return "Unsupported key type";
        case KRITIS3M_PKI_CSR_ERROR:
                return "CSR error";
        case KRITIS3M_PKI_CSR_EXT_ERROR:
                return "CSR extension error";
        case KRITIS3M_PKI_CSR_SIGN_ERROR:
                return "CSR signing error";
        case KRITIS3M_PKI_CERT_ERROR:
                return "Certificate error";
        case KRITIS3M_PKI_CERT_EXT_ERROR:
                return "Certificate extension error";
        case KRITIS3M_PKI_CERT_SIGN_ERROR:
                return "Certificate signing error";
        default:
                return "Unknown error";
        }
}


/* Create a new PrivateKey object */
PrivateKey* privateKey_new(void)
{
        PrivateKey* key = (PrivateKey*) malloc(sizeof(PrivateKey));
        if (key == NULL)
                return NULL;

        memset(&key->primaryKey, 0, sizeof(SinglePrivateKey));
        memset(&key->alternativeKey, 0, sizeof(SinglePrivateKey));

        key->primaryKey.external.deviceId = INVALID_DEVID;
        key->primaryKey.external.id = NULL;
        key->alternativeKey.external.deviceId = INVALID_DEVID;
        key->alternativeKey.external.id = NULL;

        return key;
}


/* Reference an external PrivateKey for secure element interaction. The ID is copied into the
 * object.
 * Must be called *before* generating a new key or loading the key from an existing buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_setExternalRef(PrivateKey* key, int deviceId, uint8_t const* id, size_t size)
{
        if (key == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if ((id != NULL) && (size > 0))
        {
                /* Free previous if present */
                if (key->primaryKey.external.id != NULL)
                {
                        free(key->primaryKey.external.id);
                }

                /* Allocate memory */
                key->primaryKey.external.id = (uint8_t*) malloc(size);
                if (key->primaryKey.external.id == NULL)
                        return KRITIS3M_PKI_MEMORY_ERROR;

                /* Copy */
                memcpy(key->primaryKey.external.id, id, size);
                key->primaryKey.external.idSize = size;
                key->primaryKey.external.deviceId = deviceId;
        }
        else
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        return privateKey_setAltExternalRef(key, deviceId, id, size);
}


/* Reference an external alternative PrivateKey for secure element interaction. The ID is copied
 * into the object.
 * Must be called *before* generating a new key or loading the key from an existing buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_setAltExternalRef(PrivateKey* key, int deviceId, uint8_t const* id, size_t size)
{
        if (key == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if ((id != NULL) && (size > 0))
        {
                /* Free previous if present */
                if (key->alternativeKey.external.id != NULL)
                {
                        free(key->alternativeKey.external.id);
                }

                /* Allocate memory */
                key->alternativeKey.external.id = (uint8_t*) malloc(size);
                if (key->alternativeKey.external.id == NULL)
                        return KRITIS3M_PKI_MEMORY_ERROR;

                /* Copy */
                memcpy(key->alternativeKey.external.id, id, size);
                key->alternativeKey.external.idSize = size;
                key->alternativeKey.external.deviceId = deviceId;
        }
        else
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        return KRITIS3M_PKI_SUCCESS;
}


/* Internal helper method */
static int parsePemFile(uint8_t const* buffer, size_t buffer_size, SinglePrivateKey* key, EncryptedInfo* info)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        word32 index = 0;
        DerBuffer* der = NULL;

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer object. */
        ret = PemToDer(buffer, buffer_size, PRIVATEKEY_TYPE, &der, NULL, info, &key->type);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PEM_DECODE_ERROR);

        /* Decode the key and store it in our object */
        if (key->type == RSAk)
        {
                ret = wc_InitRsaKey_Id(&key->key.rsa, key->external.id, key->external.idSize,
                                       NULL, key->external.deviceId);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                key->certKeyType = RSA_TYPE;
                ret = wc_RsaPrivateKeyDecode(der->buffer, &index, &key->key.rsa, der->length);
        }
        else if (key->type == ECDSAk)
        {
                ret = wc_ecc_init_id(&key->key.ecc, key->external.id, key->external.idSize,
                                     NULL, key->external.deviceId);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                key->certKeyType = ECC_TYPE;
                ret = wc_EccPrivateKeyDecode(der->buffer, &index, &key->key.ecc, der->length);
        }
        else if ((key->type == DILITHIUM_LEVEL2k) || (key->type == DILITHIUM_LEVEL3k) ||
                (key->type == DILITHIUM_LEVEL5k))
        {
                wc_dilithium_init_id(&key->key.dilithium, key->external.id, key->external.idSize,
                                     NULL, key->external.deviceId);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                switch (key->type)
                {
                case DILITHIUM_LEVEL2k:
                        key->certKeyType = DILITHIUM_LEVEL2_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, 2);
                        break;
                case DILITHIUM_LEVEL3k:
                        key->certKeyType = DILITHIUM_LEVEL3_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, 3);
                        break;
                case DILITHIUM_LEVEL5k:
                        key->certKeyType = DILITHIUM_LEVEL5_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, 5);
                        break;
                default:
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index,
                                &key->key.dilithium, der->length);
        }
        else if ((key->type == FALCON_LEVEL1k) || (key->type == FALCON_LEVEL5k))
        {
                wc_falcon_init_id(&key->key.falcon, key->external.id, key->external.idSize,
                                  NULL, key->external.deviceId);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                switch (key->type)
                {
                case FALCON_LEVEL1k:
                        key->certKeyType = FALCON_LEVEL1_TYPE;
                        ret = wc_falcon_set_level(&key->key.falcon, 1);
                        break;
                case FALCON_LEVEL5k:
                        key->certKeyType = FALCON_LEVEL5_TYPE;
                        ret = wc_falcon_set_level(&key->key.falcon, 5);
                        break;
                default:
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                ret = wc_Falcon_PrivateKeyDecode(der->buffer, &index,
                                &key->key.falcon, der->length);
        }
        else
        {
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);
        }

        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

        key->init = true;
        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        FreeDer(&der);

        return ret;
}

/* Initialize the given PrivateKey `key` using the PEM encoded data in the provided `buffer`
 * with `buffer_size` bytes. The key type is determined automatically. When the PEM file
 * contains both a primary and an alternative key, both are loaded. Otherwise, an alternative
 * key could be loaded from a separate buffer using `loadAltPrivateKeyFromPemBuffer()` if
 * required.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_loadKeyFromBuffer(PrivateKey* key, uint8_t const* buffer, size_t buffer_size)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        EncryptedInfo info;

        if (key == NULL || buffer == NULL)
                ERROR_OUT(KRITIS3M_PKI_ARGUMENT_ERROR);

        memset(&info, 0, sizeof(EncryptedInfo));

        /* Parse primary key */
        ret = parsePemFile(buffer, buffer_size, &key->primaryKey, &info);
        if (ret != 0)
                ERROR_OUT(ret);

        /* Parse alternative key if present in the PEM file */
        if (info.consumed < buffer_size)
        {
                ret = parsePemFile(buffer + info.consumed, buffer_size - info.consumed, &key->alternativeKey, &info);
        }

cleanup:
        return ret;
}


/* Load an alternative private key from the PEM encoded data in the provided `buffer` with
 * `buffer_size` bytes and store it decoded in the `key` PrivateKey object.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_loadAltKeyFromBuffer(PrivateKey* key, uint8_t const* buffer, size_t buffer_size)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        EncryptedInfo info;

        if (key == NULL || buffer == NULL)
                ERROR_OUT(KRITIS3M_PKI_ARGUMENT_ERROR);

        memset(&info, 0, sizeof(EncryptedInfo));

        /* Parse alternative key */
        ret = parsePemFile(buffer, buffer_size, &key->alternativeKey, &info);

cleanup:
        return ret;
}


/* Internal helper method to generate a single key pair for given algorithm. */
int generateKey(SinglePrivateKey* key, char const* algorithm)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if (key == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Key generation needs an RNG */
        WC_RNG rng;
        ret = wc_InitRng(&rng);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

        /* Check which algorithm we need */
        if (strncmp(algorithm, "rsa", 3) == 0)
        {
                ret = wc_InitRsaKey_Id(&key->key.rsa, key->external.id, key->external.idSize,
                                       NULL, key->external.deviceId);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                int size = 0;
                if (strcmp(algorithm, "rsa2048") == 0)
                        size = 2048;
                else if (strcmp(algorithm, "rsa3072") == 0)
                        size = 3072;
                else if (strcmp(algorithm, "rsa4096") == 0)
                        size = 4096;
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);

                key->type = RSAk;
                key->certKeyType = RSA_TYPE;
                ret = wc_MakeRsaKey(&key->key.rsa, size, 65537, &rng);
        }
        else if (strncmp(algorithm, "ecc", 3) == 0)
        {
                ret = wc_ecc_init_id(&key->key.ecc, key->external.id, key->external.idSize,
                                     NULL, key->external.deviceId);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                int size = 0;
                int curve_id = 0;
                if (strcmp(algorithm, "ecc256") == 0)
                {
                        size = 32;
                        curve_id = ECC_SECP256R1;
                }
                else if (strcmp(algorithm, "ecc384") == 0)
                {
                        size = 48;
                        curve_id = ECC_SECP384R1;
                }
                else if (strcmp(algorithm, "ecc521") == 0)
                {
                        size = 66;
                        curve_id = ECC_SECP521R1;
                }
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);

                key->type = ECDSAk;
                key->certKeyType = ECC_TYPE;
                ret = wc_ecc_make_key_ex(&rng, size, &key->key.ecc, curve_id);
        }
        else if (strncmp(algorithm, "mldsa", 5) == 0)
        {
                wc_dilithium_init_id(&key->key.dilithium, key->external.id, key->external.idSize,
                                     NULL, key->external.deviceId);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                if (strcmp(algorithm, "mldsa44") == 0)
                {
                        key->type = DILITHIUM_LEVEL2k;
                        key->certKeyType = DILITHIUM_LEVEL2_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, 2);
                }
                else if (strcmp(algorithm, "mldsa65") == 0)
                {
                        key->type = DILITHIUM_LEVEL3k;
                        key->certKeyType = DILITHIUM_LEVEL3_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, 3);
                }
                else if (strcmp(algorithm, "mldsa87") == 0)
                {
                        key->type = DILITHIUM_LEVEL5k;
                        key->certKeyType = DILITHIUM_LEVEL5_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, 5);
                }
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);

                ret = wc_dilithium_make_key(&key->key.dilithium, &rng);
        }
        else
        {
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);
        }

        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

        key->init = true;
        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        wc_FreeRng(&rng);

        return ret;
}


/* Generate a new public/private key pair for given `algorithm` and store the result in
 * the `key` object.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_generateKey(PrivateKey* key, char const* algorithm)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if ((key == NULL) || (algorithm == NULL))
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Generate primary key */
        ret = generateKey(&key->primaryKey, algorithm);

        return ret;
}


/* Generate a new public/private key pair for given `algorithm` and store the result in
 * the `key` object as the alternative key.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_generateAltKey(PrivateKey* key, char const* algorithm)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if ((key == NULL) || (algorithm == NULL))
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Generate primary key */
        ret = generateKey(&key->alternativeKey, algorithm);

        return ret;
}


/* Internal helper method to export a single private key */
int exportPrivateKey(SinglePrivateKey* key, uint8_t* buffer, size_t* buffer_size)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if (key->init == false)
                return KRITIS3M_PKI_KEY_ERROR;

        /* Allocate temporary buffers */
        uint8_t* derBuffer = (uint8_t*) malloc(LARGE_TEMP_SZ);
        size_t derSize = LARGE_TEMP_SZ;

        if (derBuffer == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

        if (key->type == RSAk)
        {
                /* Encode the key and store it in DER encoding */
                ret = wc_RsaKeyToDer(&key->key.rsa, derBuffer, derSize);
        }
        else if (key->type == ECDSAk)
        {
                /* Encode the key and store it in DER encoding */
                ret = wc_EccKeyToDer(&key->key.ecc, derBuffer, derSize);
        }
        else if ((key->type == DILITHIUM_LEVEL2k) ||
                 (key->type == DILITHIUM_LEVEL3k) ||
                 (key->type == DILITHIUM_LEVEL5k))
        {
                /* Encode the key and store it in DER encoding */
                /* wc_Dilithium_KeyToDer() not working currently... */
                // ret = wc_Dilithium_KeyToDer(&key->key.dilithium, derBuffer, derSize);
                ret = wc_Dilithium_PrivateKeyToDer(&key->key.dilithium, derBuffer, derSize);
        }
        else if ((key->type == FALCON_LEVEL1k) ||
                 (key->type == FALCON_LEVEL5k))
        {
                /* Encode the key and store it in DER encoding */
                /* wc_Falcon_KeyToDer() not working currently... */
                // ret = wc_Falcon_KeyToDer(&key->key.falcon, derBuffer, derSize);
                ret = wc_Falcon_PrivateKeyToDer(&key->key.falcon, derBuffer, derSize);
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);

        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

        derSize = ret;

        /* Convert DER to PEM */
        ret = wc_DerToPem(derBuffer, ret, buffer, *buffer_size, PKCS8_PRIVATEKEY_TYPE);
        if (ret > 0)
                *buffer_size = ret;
        else
                ERROR_OUT(KRITIS3M_PKI_PEM_ENCODE_ERROR);
        // memcpy(buffer, derBuffer, derSize);
        // *buffer_size = derSize;

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        if (derBuffer != NULL)
                free(derBuffer);

        return ret;
}


/* Convert the primary key in `key` to PEM and write the result into `buffer`. On function
 * entry, `buffer_size` must contain the size of the provided output buffer. After successful
 * completion, `buffer_size` will contain the size of the written output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_writeKeyToBuffer(PrivateKey* key, uint8_t* buffer, size_t* buffer_size)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if (key == NULL || buffer == NULL || buffer_size == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Export primary key */
        ret = exportPrivateKey(&key->primaryKey, buffer, buffer_size);

        return ret;
}


/* Convert the alternative key in `key` to PEM and write the result into `buffer`. On function
 * entry, `buffer_size` must contain the size of the provided output buffer. After successful
 * completion, `buffer_size` will contain the size of the written output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_writeAltKeyToBuffer(PrivateKey* key, uint8_t* buffer, size_t* buffer_size)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if (key == NULL || buffer == NULL || buffer_size == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Export alternative key */
        ret = exportPrivateKey(&key->alternativeKey, buffer, buffer_size);

        return ret;
}


/* Internal helper method */
int getSigAlgForKey(SinglePrivateKey* key)
{
        int sigAlg = 0;

        if (key == NULL || !key->init)
                return KRITIS3M_PKI_KEY_ERROR;

        switch (key->type)
        {
        case RSAk:
                sigAlg = CTC_SHA256wRSA; /* ToDo */
                break;
        case ECDSAk:
        {
                switch (key->key.ecc.dp->size)
                {
                case 32:
                        sigAlg = CTC_SHA256wECDSA;
                        break;
                case 48:
                        sigAlg = CTC_SHA384wECDSA;
                        break;
                case 66:
                        sigAlg = CTC_SHA512wECDSA;
                        break;
                default:
                        sigAlg = KRITIS3M_PKI_KEY_UNSUPPORTED;
                }
                break;
        }
        case DILITHIUM_LEVEL2k:
                sigAlg = CTC_DILITHIUM_LEVEL2;
                break;
        case DILITHIUM_LEVEL3k:
                sigAlg = CTC_DILITHIUM_LEVEL3;
                break;
        case DILITHIUM_LEVEL5k:
                sigAlg = CTC_DILITHIUM_LEVEL5;
                break;
        case FALCON_LEVEL1k:
                sigAlg = CTC_FALCON_LEVEL1;
                break;
        case FALCON_LEVEL5k:
                sigAlg = CTC_FALCON_LEVEL5;
                break;
        default:
                sigAlg = KRITIS3M_PKI_KEY_UNSUPPORTED;
                break;
        }

        return sigAlg;
}


void freeSinglePrivateKey(SinglePrivateKey* key)
{
        if (key != NULL && key->init)
        {
                if (key->init)
                {
                        switch (key->type)
                        {
                        case RSAk:
                                wc_FreeRsaKey(&key->key.rsa);
                                break;
                        case ECDSAk:
                                wc_ecc_free(&key->key.ecc);
                                break;
                        case DILITHIUM_LEVEL2k:
                        case DILITHIUM_LEVEL3k:
                        case DILITHIUM_LEVEL5k:
                                wc_dilithium_free(&key->key.dilithium);
                                break;
                        case FALCON_LEVEL1k:
                        case FALCON_LEVEL5k:
                                wc_falcon_free(&key->key.falcon);
                                break;
                        }
                }

                if (key->external.id != NULL)
                {
                        free(key->external.id);
                        key->external.id = NULL;
                }
        }
}

/* Free the memory of given PrivateKey */
void privateKey_free(PrivateKey* key)
{
        if (key != NULL)
        {
                freeSinglePrivateKey(&key->primaryKey);
                freeSinglePrivateKey(&key->alternativeKey);

                free(key);
        }
}

