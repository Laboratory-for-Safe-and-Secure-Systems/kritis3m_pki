#include "kritis3m_pki_common.h"
#include "kritis3m_pki_priv.h"

#include <string.h>


/* File global variable for the PKCS#11 middleware interface */
static Pkcs11Dev pkcs11_device;


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
        case KRITIS3M_PKI_PKCS11_ERROR:
                return "PKCS#11 error";
        default:
                return "Unknown error";
        }
}


/* Initialize the PKCS#11 support with given middleware library.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int kritis3m_pki_init_pkcs11(char const* middleware_path)
{
        /* Initialize WolfSSL */
	int ret = wolfSSL_Init();
        if (ret != WOLFSSL_SUCCESS)
                return KRITIS3M_PKI_PKCS11_ERROR;

        /* Initialize the PKCS#11 library */
        ret = wc_Pkcs11_Initialize(&pkcs11_device, middleware_path, NULL);
        if (ret != 0)
                return KRITIS3M_PKI_PKCS11_ERROR;

        return KRITIS3M_PKI_SUCCESS;
}


/* Internal helper method */
int initPkcs11Token(Pkcs11Token* token, int slot_id, uint8_t const* pin, size_t pin_size, int device_id)
{
        int ret = 0;

        /* Initialize the token */
        if (pin != NULL && pin_size > 0)
                ret = wc_Pkcs11Token_Init(token, &pkcs11_device, slot_id, NULL, pin, pin_size);
        else
                ret = wc_Pkcs11Token_Init_NoLogin(token, &pkcs11_device, slot_id, NULL);

        if (ret != 0)
                return KRITIS3M_PKI_PKCS11_ERROR;

        /* Register the device with WolfSSL */
        ret = wc_CryptoCb_RegisterDevice(device_id, wc_Pkcs11_CryptoDevCb, token);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR);

        /* Create a persistent session with the secure element */
        ret = wc_Pkcs11Token_Open(token, 1);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR);

        return KRITIS3M_PKI_SUCCESS;

cleanup:
        wc_Pkcs11Token_Final(token);

        return ret;
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
        key->primaryKey.external.label = NULL;
        key->alternativeKey.external.deviceId = INVALID_DEVID;
        key->alternativeKey.external.label = NULL;

        return key;
}


/* Reference an external PrivateKey for secure element interaction. The `label` is copied
 * into the object.
 * Must be called *before* generating a new key or loading the key from an existing buffer.
 * This method also sets the external ref data for the alternative key. However, the user
 * can always overwrite this data by calling `privateKey_setAltExternalRef()`.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_setExternalRef(PrivateKey* key, int deviceId, char const* label)
{
        if (key == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if (label)
        {
                /* Free previous if present */
                if (key->primaryKey.external.label != NULL)
                {
                        free(key->primaryKey.external.label);
                }

                /* Allocate memory */
                key->primaryKey.external.label = (char*) malloc(strlen(label) + 1);
                if (key->primaryKey.external.label == NULL)
                        return KRITIS3M_PKI_MEMORY_ERROR;

                /* Copy */
                strcpy(key->primaryKey.external.label, label);
                key->primaryKey.external.deviceId = deviceId;
        }
        else
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        return privateKey_setAltExternalRef(key, deviceId, label);
}


/* Reference an external alternative PrivateKey for secure element interaction. The `label`
 * is copied into the object.
 * Must be called *before* generating a new key or loading the key from an existing buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_setAltExternalRef(PrivateKey* key, int deviceId, char const* label)
{
        if (key == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if (label != NULL)
        {
                /* Free previous if present */
                if (key->alternativeKey.external.label != NULL)
                {
                        free(key->alternativeKey.external.label);
                }

                /* Allocate memory */
                key->alternativeKey.external.label = (char*) malloc(strlen(label) + 1);
                if (key->alternativeKey.external.label == NULL)
                        return KRITIS3M_PKI_MEMORY_ERROR;

                /* Copy */
                strcpy(key->alternativeKey.external.label, label);
                key->alternativeKey.external.deviceId = deviceId;
        }
        else
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        return KRITIS3M_PKI_SUCCESS;
}


/* Internal helper method to initialize a private key object */
int initPrivateKey(SinglePrivateKey* key, int type)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if (key == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if (type == RSAk)
        {
                if (key->external.label != NULL)
                        ret = wc_InitRsaKey_Label(&key->key.rsa, key->external.label,
                                                  NULL, key->external.deviceId);
                else
                        ret = wc_InitRsaKey(&key->key.rsa, NULL);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                key->type = RSAk;
                key->certKeyType = RSA_TYPE;
        }
        else if (type == ECDSAk)
        {
                if (key->external.label != NULL)
                        ret = wc_ecc_init_label(&key->key.ecc, key->external.label,
                                                NULL, key->external.deviceId);
                else
                        ret = wc_ecc_init(&key->key.ecc);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                key->type = ECDSAk;
                key->certKeyType = ECC_TYPE;
                wc_ecc_set_flags(&key->key.ecc, WC_ECC_FLAG_DEC_SIGN);
        }
        else if ((type == DILITHIUM_LEVEL2k) || (type == DILITHIUM_LEVEL3k) ||
                 (type == DILITHIUM_LEVEL5k))
        {
                if (key->external.label != NULL)
                        ret = wc_dilithium_init_label(&key->key.dilithium, key->external.label,
                                                      NULL, key->external.deviceId);
                else
                        ret = wc_dilithium_init(&key->key.dilithium);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                switch (type)
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

                key->type = type;
        }
        else if ((type == FALCON_LEVEL1k) || (type == FALCON_LEVEL5k))
        {
                if (key->external.label != NULL)
                        ret = wc_falcon_init_label(&key->key.falcon, key->external.label,
                                                   NULL, key->external.deviceId);
                else
                        ret = wc_falcon_init(&key->key.falcon);

                if (ret != 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                switch (type)
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

                key->type = type;
        }
        else if (type == ED25519k)
        {
                if (key->external.label != NULL)
                        ret = wc_ed25519_init_ex(&key->key.ed25519, NULL, key->external.deviceId);
                else
                        ret = wc_ed25519_init(&key->key.ed25519);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                key->type = ED25519k;
                key->certKeyType = ED25519_TYPE;
        }
        else if (type == ED448k)
        {
                if (key->external.label != NULL)
                        ret = wc_ed448_init_ex(&key->key.ed448, NULL, key->external.deviceId);
                else
                        ret = wc_ed448_init(&key->key.ed448);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                key->type = ED448k;
                key->certKeyType = ED448_TYPE;
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);

cleanup:
        return ret;
}


/* Internal helper method to import a public key into an existing key object with a private key.
 * This also checks that the private and public key belong together. */
int importPublicKey(SinglePrivateKey* key, uint8_t const* pubKey, size_t pubKeySize, int type)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        word32 idx = 0;
        uint8_t* privKeyBuffer = NULL;

        if (key == NULL || pubKey == NULL || pubKeySize == 0)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if (type == RSAk)
        {
                /* Import the public key */
                ret = wc_RsaPublicKeyDecode(pubKey, &idx, &key->key.rsa, pubKeySize);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Check if public and private key belong together */
                ret = wc_CheckRsaKey(&key->key.rsa);
        }
        else if (type == ECDSAk)
        {
                /* For ECC keys, we cannot simply import the public key data into the existing key object, as internal
                 * data is incorrectly overwritten. Instead, we have to export the private key from the existing key
                 * and then create a new key object with both the private and public key data. */

                /* Allocate temporary buffers */
                privKeyBuffer = (uint8_t*) malloc(TEMP_SZ);
                word32 privKeySize = TEMP_SZ;
                if (privKeyBuffer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                /* Export private key */
                ret = wc_ecc_export_private_only(&key->key.ecc, privKeyBuffer, &privKeySize);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Delete old key object and create a new one */
                freeSinglePrivateKey(key);
                ret = initPrivateKey(key, type);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Import both the public and private key */
                ret = wc_ecc_import_private_key(privKeyBuffer, privKeySize, pubKey, pubKeySize, &key->key.ecc);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Check if public and private key belong together */
                ret = wc_ecc_check_key(&key->key.ecc);
        }
        else if ((type == DILITHIUM_LEVEL2k) || (type == DILITHIUM_LEVEL3k) ||
                        (type == DILITHIUM_LEVEL5k))
        {
                /* Import the public key */
                ret = wc_Dilithium_PublicKeyDecode(pubKey, &idx, &key->key.dilithium,
                                                        pubKeySize);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Check if public and private key belong together */
                ret = wc_dilithium_check_key(&key->key.dilithium);
        }
        else if ((type == FALCON_LEVEL1k) || (type == FALCON_LEVEL5k))
        {
                /* Import the public key */
                ret = wc_Falcon_PublicKeyDecode(pubKey, &idx, &key->key.falcon,
                                                pubKeySize);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Check if public and private key belong together */
                ret = wc_falcon_check_key(&key->key.falcon);
        }
        else if (type == ED25519k)
        {
                /* Import the public key */
                ret = wc_Ed25519PublicKeyDecode(pubKey, &idx, &key->key.ed25519,
                                                        pubKeySize);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Check if public and private key belong together */
                ret = wc_ed25519_check_key(&key->key.ed25519);
        }
        else if (type == ED448k)
        {
                /* Import the public key */
                ret = wc_Ed448PublicKeyDecode(pubKey, &idx, &key->key.ed448,
                                                        pubKeySize);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Check if public and private key belong together */
                ret = wc_ed448_check_key(&key->key.ed448);
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);

        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

cleanup:
        if (privKeyBuffer != NULL)
                free(privKeyBuffer);

        return ret;
}


static int tryDecodeUnknownKey(SinglePrivateKey* key, DerBuffer const* der)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        word32 index = 0;

        /* Try RSA */
        initPrivateKey(key, RSAk);
        ret = wc_RsaPrivateKeyDecode(der->buffer, &index, &key->key.rsa, der->length);
        if (ret == 0)
                /* RSA was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try ECC */
        index = 0;
        initPrivateKey(key, ECDSAk);
        ret = wc_EccPrivateKeyDecode(der->buffer, &index, &key->key.ecc, der->length);
        if (ret == 0)
                /* ECC was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Dilithium Level 2 */
        index = 0;
        initPrivateKey(key, DILITHIUM_LEVEL2k);
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index, &key->key.dilithium, der->length);
        if (ret == 0)
                /* Dilithium Level 2 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Dilithium Level 3 */
        index = 0;
        initPrivateKey(key, DILITHIUM_LEVEL3k);
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index, &key->key.dilithium, der->length);
        if (ret == 0)
                /* Dilithium Level 3 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Dilithium Level 5 */
        index = 0;
        initPrivateKey(key, DILITHIUM_LEVEL5k);
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index, &key->key.dilithium, der->length);
        if (ret == 0)
                /* Dilithium Level 5 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Falcon Level 1 */
        index = 0;
        initPrivateKey(key, FALCON_LEVEL1k);
        ret = wc_Falcon_PrivateKeyDecode(der->buffer, &index, &key->key.falcon, der->length);
        if (ret == 0)
                /* Falcon Level 1 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Falcon Level 5 */
        index = 0;
        initPrivateKey(key, FALCON_LEVEL5k);
        ret = wc_Falcon_PrivateKeyDecode(der->buffer, &index, &key->key.falcon, der->length);
        if (ret == 0)
                /* Falcon Level 5 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Ed25519 */
        index = 0;
        initPrivateKey(key, ED25519k);
        ret = wc_Ed25519PrivateKeyDecode(der->buffer, &index, &key->key.ed25519, der->length);
        if (ret == 0)
                /* Ed25519 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Ed448 */
        index = 0;
        initPrivateKey(key, ED448k);
        ret = wc_Ed448PrivateKeyDecode(der->buffer, &index, &key->key.ed448, der->length);
        if (ret == 0)
                /* Ed448 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        return KRITIS3M_PKI_KEY_UNSUPPORTED;
}


/* Internal helper method for parsing a PEM buffer */
static int parsePemBuffer(uint8_t const* buffer, size_t buffer_size, SinglePrivateKey* key, EncryptedInfo* info)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        word32 index = 0;
        DerBuffer* der = NULL;
        int key_type = 0;

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer object. */
        ret = PemToDer(buffer, buffer_size, PRIVATEKEY_TYPE, &der, NULL, info, &key_type);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PEM_DECODE_ERROR);

        if (key_type == 0)
        {
                /* The DER doesn't contain information about which key is encoded. Hence, we have
                 * to brute force whether we can decode it. */
                ret = tryDecodeUnknownKey(key, der);
                if (ret != 0)
                        ERROR_OUT(ret);
        }
        else
        {
                /* Initialize the key */
                ret = initPrivateKey(key, key_type);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Store the private key in our object */
                if (key->type == RSAk)
                        ret = wc_RsaPrivateKeyDecode(der->buffer, &index, &key->key.rsa, der->length);
                else if (key->type == ECDSAk)
                        ret = wc_EccPrivateKeyDecode(der->buffer, &index, &key->key.ecc, der->length);
                else if ((key->type == DILITHIUM_LEVEL2k) || (key->type == DILITHIUM_LEVEL3k) ||
                        (key->type == DILITHIUM_LEVEL5k))
                        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index,
                                        &key->key.dilithium, der->length);
                else if ((key->type == FALCON_LEVEL1k) || (key->type == FALCON_LEVEL5k))
                        ret = wc_Falcon_PrivateKeyDecode(der->buffer, &index,
                                        &key->key.falcon, der->length);
                else if (key->type == ED25519k)
                {
                        ret = wc_Ed25519PrivateKeyDecode(der->buffer, &index,
                                        &key->key.ed25519, der->length);

                        if (ret == 0 && key->key.ed25519.pubKeySet == 0)
                        {
                                ret = wc_ed25519_make_public(&key->key.ed25519, key->key.ed25519.p, sizeof(key->key.ed25519.p));
                                if (ret == 0)
                                        ret = wc_ed25519_check_key(&key->key.ed25519);
                        }
                }
                else if (key->type == ED448k)
                {
                        ret = wc_Ed448PrivateKeyDecode(der->buffer, &index,
                                        &key->key.ed448, der->length);

                        if (ret == 0 && key->key.ed448.pubKeySet == 0)
                        {
                                ret = wc_ed448_make_public(&key->key.ed448, key->key.ed448.p, sizeof(key->key.ed448.p));
                                if (ret == 0)
                                        ret = wc_ed448_check_key(&key->key.ed448);
                        }
                }
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);
        }

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
        ret = parsePemBuffer(buffer, buffer_size, &key->primaryKey, &info);
        if (ret != 0)
                ERROR_OUT(ret);

        /* Parse alternative key if present in the PEM data */
        if (info.consumed < buffer_size)
        {
                ret = parsePemBuffer(buffer + info.consumed, buffer_size - info.consumed, &key->alternativeKey, &info);
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
        ret = parsePemBuffer(buffer, buffer_size, &key->alternativeKey, &info);

cleanup:
        return ret;
}


/* Internal helper method to generate a single key pair for given algorithm. */
int generateKey(SinglePrivateKey* key, char const* algorithm)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if ((key == NULL) || (algorithm == NULL))
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Key generation needs an RNG */
        WC_RNG rng;
        ret = wc_InitRng(&rng);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

        /* Check which algorithm we need */
        if (strncmp(algorithm, "rsa", 3) == 0)
        {
                /* Initialize the key */
                ret = initPrivateKey(key, RSAk);

                /* Generate the actual key pair depending on the requested size */
                int size = 0;
                if (strcmp(algorithm, "rsa2048") == 0)
                        ret = wc_MakeRsaKey(&key->key.rsa, 2048, 65537, &rng);
                else if (strcmp(algorithm, "rsa3072") == 0)
                        ret = wc_MakeRsaKey(&key->key.rsa, 3072, 65537, &rng);
                else if (strcmp(algorithm, "rsa4096") == 0)
                        ret = wc_MakeRsaKey(&key->key.rsa, 4096, 65537, &rng);
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);
        }
        else if (strncmp(algorithm, "secp", 3) == 0)
        {
                /* Initialize the key */
                ret = initPrivateKey(key, ECDSAk);

                /* Generate the actual key pair depending on the requested size */
                if (strcmp(algorithm, "secp256") == 0)
                        ret = wc_ecc_make_key_ex2(&rng, 32, &key->key.ecc, ECC_SECP256R1, WC_ECC_FLAG_DEC_SIGN);
                else if (strcmp(algorithm, "secp384") == 0)
                        ret = wc_ecc_make_key_ex2(&rng, 48, &key->key.ecc, ECC_SECP384R1, WC_ECC_FLAG_DEC_SIGN);
                else if (strcmp(algorithm, "secp521") == 0)
                        ret = wc_ecc_make_key_ex2(&rng, 66, &key->key.ecc, ECC_SECP521R1, WC_ECC_FLAG_DEC_SIGN);
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);
        }
        else if (strncmp(algorithm, "mldsa", 5) == 0)
        {
                /* Initialize the key depending on the requested type */
                if (strcmp(algorithm, "mldsa44") == 0)
                        ret = initPrivateKey(key, DILITHIUM_LEVEL2k);
                else if (strcmp(algorithm, "mldsa65") == 0)
                        ret = initPrivateKey(key, DILITHIUM_LEVEL3k);
                else if (strcmp(algorithm, "mldsa87") == 0)
                        ret = initPrivateKey(key, DILITHIUM_LEVEL5k);
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);

                /* Generate the actual key pair */
                ret = wc_dilithium_make_key(&key->key.dilithium, &rng);
        }
        /* Falcon not yet supported */
        else if (strcmp(algorithm, "ed25519") == 0)
        {
                /* Initialize the key */
                ret = initPrivateKey(key, ED25519k);

                /* Generate the actual key pair */
                ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key->key.ed25519);
        }
        else if (strcmp(algorithm, "ed448") == 0)
        {
                /* Initialize the key */
                ret = initPrivateKey(key, ED448k);

                /* Generate the actual key pair */
                ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key->key.ed448);
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);

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

        /* Generate alternative key */
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
        word32 derSize = LARGE_TEMP_SZ;

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
                // ret = wc_EccKeyToDer(&key->key.ecc, derBuffer, derSize);
                ret = wc_EccKeyToPKCS8(&key->key.ecc, derBuffer, &derSize);
        }
        else if ((key->type == DILITHIUM_LEVEL2k) ||
                 (key->type == DILITHIUM_LEVEL3k) ||
                 (key->type == DILITHIUM_LEVEL5k))
        {
                /* Encode the key and store it in DER encoding */
                // ret = wc_Dilithium_KeyToDer(&key->key.dilithium, derBuffer, derSize);
                ret = wc_Dilithium_PrivateKeyToDer(&key->key.dilithium, derBuffer, derSize);
        }
        else if ((key->type == FALCON_LEVEL1k) ||
                 (key->type == FALCON_LEVEL5k))
        {
                /* Encode the key and store it in DER encoding */
                // ret = wc_Falcon_KeyToDer(&key->key.falcon, derBuffer, derSize);
                ret = wc_Falcon_PrivateKeyToDer(&key->key.falcon, derBuffer, derSize);
        }
        else if (key->type == ED25519k)
        {
                /* Encode the key and store it in DER encoding */
                ret = wc_Ed25519PrivateKeyToDer(&key->key.ed25519, derBuffer, derSize);
                // ret = wc_Ed25519KeyToDer(&key->key.ed25519, derBuffer, derSize);
        }
        else if (key->type == ED448k)
        {
                /* Encode the key and store it in DER encoding */
                ret = wc_Ed448PrivateKeyToDer(&key->key.ed448, derBuffer, derSize);
                // ret = wc_Ed448KeyToDer(&key->key.ed25519, derBuffer, derSize);
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


/* Internal helper method to copy a single private key */
int copySinglePrivateKey(SinglePrivateKey* destination, SinglePrivateKey* source)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if ((destination == NULL) || (source == NULL))
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* No need to copy */
        if (source->init == false)
                return KRITIS3M_PKI_SUCCESS;

        /* Allocate temporary buffers */
        uint8_t* pemBuffer = (uint8_t*) malloc(LARGE_TEMP_SZ);
        size_t pemSize = LARGE_TEMP_SZ;

        if (pemBuffer == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

        /* Export the source key. We re-use our internal exportPrivateKey() method to
         * not duplicate code. This method exports PEM data. This is actually a very
         * inefficient method to copy a SinglePrivateKey, but it re-uses the maximum
         * of existing code.
         * ToDo: refactor the code to do more efficient deep copies of a key.
         * */
        ret = exportPrivateKey(source, pemBuffer, &pemSize);
        if (ret != 0)
                ERROR_OUT(ret);

        /* Decode PEM data into destination key */
        ret = parsePemBuffer(pemBuffer, pemSize, destination, NULL);
        if (ret != 0)
                ERROR_OUT(ret);

        /* Copy external reference data */
        if (source->external.label != NULL)
        {
                destination->external.label = (char*) malloc(strlen(source->external.label) + 1);
                if (destination->external.label == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                strcpy(destination->external.label, source->external.label);
                destination->external.deviceId = source->external.deviceId;
        }

        /* Copy remaining data */
        destination->init = true;
        destination->type = source->type;
        destination->certKeyType = source->certKeyType;

cleanup:
        if (pemBuffer != NULL)
                free(pemBuffer);

        return ret;
}


/* Copy a Privatekey object to another one.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_copyKey(PrivateKey* destination, PrivateKey* source)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if ((destination == NULL) || (source == NULL))
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Copy primary key */
        ret = copySinglePrivateKey(&destination->primaryKey, &source->primaryKey);
        if (ret != 0)
                return ret;

        /* Copy alternative key */
        ret = copySinglePrivateKey(&destination->alternativeKey, &source->alternativeKey);

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
        case ED25519k:
                sigAlg = CTC_ED25519;
                break;
        case ED448k:
                sigAlg = CTC_ED448;
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
                        case ED25519k:
                                wc_ed25519_free(&key->key.ed25519);
                                break;
                        case ED448k:
                                wc_ed448_free(&key->key.ed448);
                                break;
                        }
                }

                if (key->external.label != NULL)
                {
                        free(key->external.label);
                        key->external.label = NULL;
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

