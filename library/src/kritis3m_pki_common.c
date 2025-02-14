#include "kritis3m_pki_common.h"
#include "kritis3m_pki_priv.h"

#include <string.h>

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

/* Initialize the KRITIS3M PKI libraries.
 *
 * Parameter is a pointer to a filled kritis3m_pki_configuration structure.
 *
 * Returns KRITIS3M_PKI_SUCCESS on success, negative error code in case of an error
 * (error message is logged to the console).
 */
int kritis3m_pki_init(kritis3m_pki_configuration const* config)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if (config == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Configure the logging interface */
        kritis3m_pki_prepare_logging(config);

        /* Initialize WolfSSL */
        ret = wolfSSL_Init();
        if (ret != WOLFSSL_SUCCESS)
                return KRITIS3M_PKI_PKCS11_ERROR;

        return KRITIS3M_PKI_SUCCESS;
}

#ifdef HAVE_PKCS11

/* Internal helper method */
int initPkcs11Token(Pkcs11Dev* device,
                    Pkcs11Token* token,
                    char const* path,
                    int slot_id,
                    uint8_t const* pin,
                    size_t pin_size,
                    int device_id)
{
        int ret = 0;

        if (token == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Initialize the PKCS#11 library */
        int pkcs11_version = WC_PCKS11VERSION_3_2;
        ret = wc_Pkcs11_Initialize_ex(device, path, NULL, &pkcs11_version, "PKCS 11", NULL);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "PKCS#11 library initialization failed: %d", ret);
        if (pkcs11_version != WC_PCKS11VERSION_3_2)
                pki_log(KRITIS3M_PKI_LOG_LEVEL_WRN, "No PQC capable PKCS#11 version: %d", device->version);

        /* Initialize the token */
        if (pin != NULL && pin_size > 0)
                ret = wc_Pkcs11Token_Init(token, device, slot_id, NULL, pin, pin_size);
        else
                ret = wc_Pkcs11Token_Init_NoLogin(token, device, slot_id, NULL);

        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "PKCS#11 token initialization failed: %d", ret);

        /* Register the device with WolfSSL */
        ret = wc_CryptoCb_RegisterDevice(device_id, wc_Pkcs11_CryptoDevCb, token);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "PKCS#11 device registration failed: %d", ret);

        /* Create a persistent session with the secure element */
        ret = wc_Pkcs11Token_Open(token, 1);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "PKCS#11 token opening failed: %d", ret);

        return KRITIS3M_PKI_SUCCESS;

cleanup:
        wc_Pkcs11Token_Final(token);
        wc_Pkcs11_Finalize(device);
        return ret;
}

#endif

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
                        pki_log(KRITIS3M_PKI_LOG_LEVEL_WRN,
                                "Overwriting existing primary key reference");
                        free(key->primaryKey.external.label);
                }

                /* Allocate memory */
                size_t labelLen = strlen(label);
                key->primaryKey.external.label = (char*) malloc(labelLen + 1);
                if (key->primaryKey.external.label == NULL)
                        return KRITIS3M_PKI_MEMORY_ERROR;

                /* Copy */
                strcpy(key->primaryKey.external.label, label);
                key->primaryKey.external.deviceId = deviceId;

                /* If the key is already initialized, store the label directly
                 * in the key object, too. */
                if (key->primaryKey.init == true)
                {
                        switch (key->primaryKey.type)
                        {
                        case RSAk:
                                key->primaryKey.key.rsa.devId = deviceId;
                                key->primaryKey.key.rsa.labelLen = labelLen;
                                memcpy(key->primaryKey.key.rsa.label, label, labelLen);
                                break;
                        case ECDSAk:
                                key->primaryKey.key.ecc.devId = deviceId;
                                key->primaryKey.key.ecc.labelLen = labelLen;
                                memcpy(key->primaryKey.key.ecc.label, label, labelLen);
                                break;
                        case ML_DSA_LEVEL2k:
                        case ML_DSA_LEVEL3k:
                        case ML_DSA_LEVEL5k:
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                        case DILITHIUM_LEVEL2k:
                        case DILITHIUM_LEVEL3k:
                        case DILITHIUM_LEVEL5k:
#endif
                                key->primaryKey.key.dilithium.devId = deviceId;
                                key->primaryKey.key.dilithium.labelLen = labelLen;
                                memcpy(key->primaryKey.key.dilithium.label, label, labelLen);
                                break;
#ifdef HAVE_FALCON
                        case FALCON_LEVEL1k:
                        case FALCON_LEVEL5k:
                                key->primaryKey.key.falcon.devId = deviceId;
                                key->primaryKey.key.falcon.labelLen = labelLen;
                                memcpy(key->primaryKey.key.falcon.label, label, labelLen);
                                break;
#endif
                        case ED25519k:
                        case ED448k:
                                break;
                        default:
                                return KRITIS3M_PKI_KEY_UNSUPPORTED;
                        };
                }
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
                        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG,
                                "Overwriting existing alternative key reference");
                        free(key->alternativeKey.external.label);
                }

                /* Allocate memory */
                size_t labelLen = strlen(label);
                key->alternativeKey.external.label = (char*) malloc(labelLen + 1);
                if (key->alternativeKey.external.label == NULL)
                        return KRITIS3M_PKI_MEMORY_ERROR;

                /* Copy */
                strcpy(key->alternativeKey.external.label, label);
                key->alternativeKey.external.deviceId = deviceId;

                /* If the key is already initialized, store the label directly
                 * in the key object, too. */
                if (key->alternativeKey.init == true)
                {
                        switch (key->alternativeKey.type)
                        {
                        case RSAk:
                                key->alternativeKey.key.rsa.devId = deviceId;
                                key->alternativeKey.key.rsa.labelLen = labelLen;
                                memcpy(key->alternativeKey.key.rsa.label, label, labelLen);
                                break;
                        case ECDSAk:
                                key->alternativeKey.key.ecc.devId = deviceId;
                                key->alternativeKey.key.ecc.labelLen = labelLen;
                                memcpy(key->alternativeKey.key.ecc.label, label, labelLen);
                                break;
                        case ML_DSA_LEVEL2k:
                        case ML_DSA_LEVEL3k:
                        case ML_DSA_LEVEL5k:
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                        case DILITHIUM_LEVEL2k:
                        case DILITHIUM_LEVEL3k:
                        case DILITHIUM_LEVEL5k:
#endif
                                key->alternativeKey.key.dilithium.devId = deviceId;
                                key->alternativeKey.key.dilithium.labelLen = labelLen;
                                memcpy(key->alternativeKey.key.dilithium.label, label, labelLen);
                                break;
#ifdef HAVE_FALCON
                        case FALCON_LEVEL1k:
                        case FALCON_LEVEL5k:
                                key->alternativeKey.key.falcon.devId = deviceId;
                                key->alternativeKey.key.falcon.labelLen = labelLen;
                                memcpy(key->alternativeKey.key.falcon.label, label, labelLen);
                                break;
#endif
                        case ED25519k:
                        case ED448k:
                                break;
                        default:
                                return KRITIS3M_PKI_KEY_UNSUPPORTED;
                        };
                }
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
                        ret = wc_InitRsaKey_Label(&key->key.rsa,
                                                  key->external.label,
                                                  NULL,
                                                  key->external.deviceId);
                else
                        ret = wc_InitRsaKey(&key->key.rsa, NULL);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "RSA key initialization failed: %d", ret);

                key->type = RSAk;
                key->certKeyType = RSA_TYPE;
        }
        else if (type == ECDSAk)
        {
                if (key->external.label != NULL)
                        ret = wc_ecc_init_label(&key->key.ecc,
                                                key->external.label,
                                                NULL,
                                                key->external.deviceId);
                else
                        ret = wc_ecc_init(&key->key.ecc);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "ECC key initialization failed: %d", ret);

                key->type = ECDSAk;
                key->certKeyType = ECC_TYPE;
                wc_ecc_set_flags(&key->key.ecc, WC_ECC_FLAG_DEC_SIGN);
        }
        else if (
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                (type == DILITHIUM_LEVEL2k) || (type == DILITHIUM_LEVEL3k) ||
                (type == DILITHIUM_LEVEL5k) ||
#endif
                (type == ML_DSA_LEVEL2k) || (type == ML_DSA_LEVEL3k) || (type == ML_DSA_LEVEL5k))
        {
                if (key->external.label != NULL)
                        ret = wc_dilithium_init_label(&key->key.dilithium,
                                                      key->external.label,
                                                      NULL,
                                                      key->external.deviceId);
                else
                        ret = wc_dilithium_init(&key->key.dilithium);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Dilithium key initialization failed: %d", ret);

                switch (type)
                {
                case ML_DSA_LEVEL2k:
                        key->certKeyType = DILITHIUM_LEVEL2_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, WC_ML_DSA_44);
                        break;
                case ML_DSA_LEVEL3k:
                        key->certKeyType = DILITHIUM_LEVEL3_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, WC_ML_DSA_65);
                        break;
                case ML_DSA_LEVEL5k:
                        key->certKeyType = DILITHIUM_LEVEL5_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, WC_ML_DSA_87);
                        break;
#if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
                case DILITHIUM_LEVEL2k:
                        key->certKeyType = DILITHIUM_LEVEL2_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, WC_ML_DSA_44_DRAFT);
                        break;
                case DILITHIUM_LEVEL3k:
                        key->certKeyType = DILITHIUM_LEVEL3_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, WC_ML_DSA_65_DRAFT);
                        break;
                case DILITHIUM_LEVEL5k:
                        key->certKeyType = DILITHIUM_LEVEL5_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, WC_ML_DSA_87_DRAFT);
                        break;
#endif
                default:
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported Dilithium key level");
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Dilithium key level setting failed: %d", ret);

                key->type = type;
        }
#ifdef HAVE_FALCON
        else if ((type == FALCON_LEVEL1k) || (type == FALCON_LEVEL5k))
        {
                if (key->external.label != NULL)
                        ret = wc_falcon_init_label(&key->key.falcon,
                                                   key->external.label,
                                                   NULL,
                                                   key->external.deviceId);
                else
                        ret = wc_falcon_init(&key->key.falcon);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Falcon key initialization failed: %d", ret);

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
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported Falcon key level");
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Falcon key level setting failed: %d", ret);

                key->type = type;
        }
#endif
        else if (type == ED25519k)
        {
                if (key->external.label != NULL)
                        ret = wc_ed25519_init_ex(&key->key.ed25519, NULL, key->external.deviceId);
                else
                        ret = wc_ed25519_init(&key->key.ed25519);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Ed25519 key initialization failed: %d", ret);

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
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Ed448 key initialization failed: %d", ret);

                key->type = ED448k;
                key->certKeyType = ED448_TYPE;
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported key type: %d", type);

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

        /* Import the public key */
        if (type == RSAk)
        {
                ret = wc_RsaPublicKeyDecode(pubKey, &idx, &key->key.rsa, pubKeySize);
        }
        else if (type == ECDSAk)
        {
                /* For internal  ECC keys, we cannot simply import the public key data into the
                 * existing key object, as internal data is incorrectly overwritten. Instead, we
                 * have to export the private key from the existing key and then create a new key
                 * object with both the private and public key data. */
                if (key->external.label == NULL)
                {
                        /* Allocate temporary buffers */
                        privKeyBuffer = (uint8_t*) malloc(TEMP_SZ);
                        word32 privKeySize = TEMP_SZ;
                        if (privKeyBuffer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                          "Memory allocation for ECC private key failed");

                        /* Export private key */
                        ret = wc_ecc_export_private_only(&key->key.ecc, privKeyBuffer, &privKeySize);
                        if (ret != 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                          "ECC private key export failed: %d",
                                          ret);

                        /* Delete old key object and create a new one */
                        freeSinglePrivateKey(key);
                        ret = initPrivateKey(key, type);
                        if (ret != 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "ECC key initialization failed");

                        /* Import both the public and private key */
                        ret = wc_ecc_import_private_key(privKeyBuffer,
                                                        privKeySize,
                                                        pubKey,
                                                        pubKeySize,
                                                        &key->key.ecc);
                }
                else
                {
                        ret = wc_EccPublicKeyDecode(pubKey, &idx, &key->key.ecc, pubKeySize);
                }
        }
        else if (
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                (type == DILITHIUM_LEVEL2k) || (type == DILITHIUM_LEVEL3k) ||
                (type == DILITHIUM_LEVEL5k) ||
#endif
                (type == ML_DSA_LEVEL2k) || (type == ML_DSA_LEVEL3k) || (type == ML_DSA_LEVEL5k))
        {
                ret = wc_Dilithium_PublicKeyDecode(pubKey, &idx, &key->key.dilithium, pubKeySize);
        }
#ifdef HAVE_FALCON
        else if ((type == FALCON_LEVEL1k) || (type == FALCON_LEVEL5k))
        {
                ret = wc_Falcon_PublicKeyDecode(pubKey, &idx, &key->key.falcon, pubKeySize);
        }
#endif
        else if (type == ED25519k)
        {
                ret = wc_Ed25519PublicKeyDecode(pubKey, &idx, &key->key.ed25519, pubKeySize);
        }
        else if (type == ED448k)
        {
                ret = wc_Ed448PublicKeyDecode(pubKey, &idx, &key->key.ed448, pubKeySize);
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported key type: %d", type);

        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Public key import failed: %d", ret);

        /* Check if public key and private key belong together. */
        if (type == RSAk)
        {
                if (key->external.label != NULL)
                        ret = wc_CryptoCb_RsaCheckPrivKey(&key->key.rsa, pubKey, pubKeySize);
                else
                        ret = wc_CheckRsaKey(&key->key.rsa);
        }
        else if (type == ECDSAk)
        {
                if (key->external.label != NULL)
                        ret = wc_CryptoCb_EccCheckPrivKey(&key->key.ecc, pubKey, pubKeySize);
                else
                        ret = wc_ecc_check_key(&key->key.ecc);
        }
        else if (
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                (type == DILITHIUM_LEVEL2k) || (type == DILITHIUM_LEVEL3k) ||
                (type == DILITHIUM_LEVEL5k) ||
#endif
                (type == ML_DSA_LEVEL2k) || (type == ML_DSA_LEVEL3k) || (type == ML_DSA_LEVEL5k))
        {
                if (key->external.label != NULL)
                        ret = wc_CryptoCb_PqcSignatureCheckPrivKey(&key->key.dilithium,
                                                                   WC_PQC_SIG_TYPE_DILITHIUM,
                                                                   pubKey,
                                                                   pubKeySize);
                else
                        ret = wc_dilithium_check_key(&key->key.dilithium);
        }
#ifdef HAVE_FALCON
        else if ((type == FALCON_LEVEL1k) || (type == FALCON_LEVEL5k))
        {
                // if (key->external.label != NULL)
                //         ret = wc_CryptoCb_PqcSignatureCheckPrivKey(&key->key.falcon,
                //                         WC_PQC_SIG_TYPE_FALCON, pubKey, pubKeySize);
                // else
                /* Not supported currently... */
                // ret = wc_falcon_check_key(&key->key.falcon);
        }
#endif
        else if (type == ED25519k)
        {
                if (key->external.label == NULL)
                        ret = wc_ed25519_check_key(&key->key.ed25519);
        }
        else if (type == ED448k)
        {
                if (key->external.label == NULL)
                        ret = wc_ed448_check_key(&key->key.ed448);
        }

        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Public and private key mismatch: %d", ret);

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
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode RSA key");
        if ((ret = initPrivateKey(key, RSAk)) != 0)
                return ret;
        ret = wc_RsaPrivateKeyDecode(der->buffer, &index, &key->key.rsa, der->length);
        if (ret == 0)
                /* RSA was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try ECC */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode ECC key");
        index = 0;
        if ((ret = initPrivateKey(key, ECDSAk)) != 0)
                return ret;
        ret = wc_EccPrivateKeyDecode(der->buffer, &index, &key->key.ecc, der->length);
        if (ret == 0)
                /* ECC was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try ML-DSA 44 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode ML-DSA 44 key");
        index = 0;
        if ((ret = initPrivateKey(key, ML_DSA_LEVEL2k)) != 0)
                return ret;
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index, &key->key.dilithium, der->length);
        if (ret == 0)
                /* ML-DSA 44 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try ML-DSA 65 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode ML-DSA 65 key");
        index = 0;
        if ((ret = initPrivateKey(key, ML_DSA_LEVEL3k)) != 0)
                return ret;
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index, &key->key.dilithium, der->length);
        if (ret == 0)
                /* ML-DSA 65 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try ML-DSA 87 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode ML-DSA 87 key");
        index = 0;
        if ((ret = initPrivateKey(key, ML_DSA_LEVEL5k)) != 0)
                return ret;
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index, &key->key.dilithium, der->length);
        if (ret == 0)
                /* ML-DSA 87 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
        /* Try Dilithium Level 2 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode Dilithium Level 2 key");
        index = 0;
        if ((ret = initPrivateKey(key, DILITHIUM_LEVEL2k)) != 0)
                return ret;
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index, &key->key.dilithium, der->length);
        if (ret == 0)
                /* Dilithium Level 2 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Dilithium Level 3 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode Dilithium Level 3 key");
        index = 0;
        if ((ret = initPrivateKey(key, DILITHIUM_LEVEL3k)) != 0)
                return ret;
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index, &key->key.dilithium, der->length);
        if (ret == 0)
                /* Dilithium Level 3 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Dilithium Level 5 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode Dilithium Level 5 key");
        index = 0;
        if ((ret = initPrivateKey(key, DILITHIUM_LEVEL5k)) != 0)
                return ret;
        ret = wc_Dilithium_PrivateKeyDecode(der->buffer, &index, &key->key.dilithium, der->length);
        if (ret == 0)
                /* Dilithium Level 5 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);
#endif

#ifdef HAVE_FALCON
        /* Try Falcon Level 1 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode Falcon Level 1 key");
        index = 0;
        if ((ret = initPrivateKey(key, FALCON_LEVEL1k)) != 0)
                return ret;
        ret = wc_Falcon_PrivateKeyDecode(der->buffer, &index, &key->key.falcon, der->length);
        if (ret == 0)
                /* Falcon Level 1 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Falcon Level 5 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode Falcon Level 5 key");
        index = 0;
        if ((ret = initPrivateKey(key, FALCON_LEVEL5k)) != 0)
                return ret;
        ret = wc_Falcon_PrivateKeyDecode(der->buffer, &index, &key->key.falcon, der->length);
        if (ret == 0)
                /* Falcon Level 5 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);
#endif

        /* Try Ed25519 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode Ed25519 key");
        index = 0;
        if ((ret = initPrivateKey(key, ED25519k)) != 0)
                return ret;
        ret = wc_Ed25519PrivateKeyDecode(der->buffer, &index, &key->key.ed25519, der->length);
        if (ret == 0)
                /* Ed25519 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        /* Try Ed448 */
        pki_log(KRITIS3M_PKI_LOG_LEVEL_DBG, "Trying to decode Ed448 key");
        index = 0;
        if ((ret = initPrivateKey(key, ED448k)) != 0)
                return ret;
        ret = wc_Ed448PrivateKeyDecode(der->buffer, &index, &key->key.ed448, der->length);
        if (ret == 0)
                /* Ed448 was a success, so we are done */
                return KRITIS3M_PKI_SUCCESS;
        else
                freeSinglePrivateKey(key);

        return KRITIS3M_PKI_KEY_UNSUPPORTED;
}

/* Internal helper method for parsing a PEM buffer */
static int parsePemBuffer(uint8_t const* buffer,
                          size_t buffer_size,
                          SinglePrivateKey* key,
                          EncryptedInfo* info)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        word32 index = 0;
        DerBuffer* der = NULL;
        int key_type = 0;

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer object. */
        ret = wc_PemToDer(buffer, buffer_size, PRIVATEKEY_TYPE, &der, NULL, info, &key_type);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PEM_DECODE_ERROR, "PEM to DER conversion failed: %d", ret);

        if (key_type == 0)
        {
                /* The DER doesn't contain information about which key is encoded. Hence, we have
                 * to brute force whether we can decode it. */
                ret = tryDecodeUnknownKey(key, der);
                if (ret != 0)
                        ERROR_OUT(ret, "Decoding of unknown key type failed");
        }
        else
        {
                /* Initialize the key */
                ret = initPrivateKey(key, key_type);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Key initialization failed");

                /* Store the private key in our object */
                if (key->type == RSAk)
                        ret = wc_RsaPrivateKeyDecode(der->buffer, &index, &key->key.rsa, der->length);
                else if (key->type == ECDSAk)
                        ret = wc_EccPrivateKeyDecode(der->buffer, &index, &key->key.ecc, der->length);
                else if (
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                        (key->type == DILITHIUM_LEVEL2k) || (key->type == DILITHIUM_LEVEL3k) ||
                        (key->type == DILITHIUM_LEVEL5k) ||
#endif
                        (key->type == ML_DSA_LEVEL2k) || (key->type == ML_DSA_LEVEL3k) ||
                        (key->type == ML_DSA_LEVEL5k))
                        ret = wc_Dilithium_PrivateKeyDecode(der->buffer,
                                                            &index,
                                                            &key->key.dilithium,
                                                            der->length);
#ifdef HAVE_FALCON
                else if ((key->type == FALCON_LEVEL1k) || (key->type == FALCON_LEVEL5k))
                        ret = wc_Falcon_PrivateKeyDecode(der->buffer, &index, &key->key.falcon, der->length);
#endif
                else if (key->type == ED25519k)
                {
                        ret = wc_Ed25519PrivateKeyDecode(der->buffer,
                                                         &index,
                                                         &key->key.ed25519,
                                                         der->length);

                        if (ret == 0 && key->key.ed25519.pubKeySet == 0)
                        {
                                ret = wc_ed25519_make_public(&key->key.ed25519,
                                                             key->key.ed25519.p,
                                                             sizeof(key->key.ed25519.p));
                                if (ret == 0)
                                        ret = wc_ed25519_check_key(&key->key.ed25519);
                        }
                }
                else if (key->type == ED448k)
                {
                        ret = wc_Ed448PrivateKeyDecode(der->buffer, &index, &key->key.ed448, der->length);

                        if (ret == 0 && key->key.ed448.pubKeySet == 0)
                        {
                                ret = wc_ed448_make_public(&key->key.ed448,
                                                           key->key.ed448.p,
                                                           sizeof(key->key.ed448.p));
                                if (ret == 0)
                                        ret = wc_ed448_check_key(&key->key.ed448);
                        }
                }
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported key type: %d", key->type);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Key import failed: %d", ret);
        }

        key->init = true;
        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        wc_FreeDer(&der);

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
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        memset(&info, 0, sizeof(EncryptedInfo));

        /* Parse primary key */
        ret = parsePemBuffer(buffer, buffer_size, &key->primaryKey, &info);
        if (ret != 0)
                return ret;

        /* Parse alternative key if present in the PEM data */
        if (info.consumed < buffer_size)
        {
                ret = parsePemBuffer(buffer + info.consumed,
                                     buffer_size - info.consumed,
                                     &key->alternativeKey,
                                     &info);
        }

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
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        memset(&info, 0, sizeof(EncryptedInfo));

        /* Parse alternative key */
        ret = parsePemBuffer(buffer, buffer_size, &key->alternativeKey, &info);

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
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "RNG initialization failed: %d", ret);

        /* Check which algorithm we need */
        if (strncmp(algorithm, "rsa", 3) == 0)
        {
                /* Initialize the key */
                ret = initPrivateKey(key, RSAk);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "RSA key initialization failed");

                /* Generate the actual key pair depending on the requested size */
                int size = 0;
                if (strcmp(algorithm, "rsa2048") == 0)
                        ret = wc_MakeRsaKey(&key->key.rsa, 2048, 65537, &rng);
                else if (strcmp(algorithm, "rsa3072") == 0)
                        ret = wc_MakeRsaKey(&key->key.rsa, 3072, 65537, &rng);
                else if (strcmp(algorithm, "rsa4096") == 0)
                        ret = wc_MakeRsaKey(&key->key.rsa, 4096, 65537, &rng);
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported RSA key size: %s", algorithm);
        }
        else if (strncmp(algorithm, "secp", 3) == 0)
        {
                /* Initialize the key */
                ret = initPrivateKey(key, ECDSAk);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "ECC key initialization failed");

                /* Generate the actual key pair depending on the requested size */
                if (strcmp(algorithm, "secp256") == 0)
                        ret = wc_ecc_make_key_ex2(&rng, 32, &key->key.ecc, ECC_SECP256R1, WC_ECC_FLAG_DEC_SIGN);
                else if (strcmp(algorithm, "secp384") == 0)
                        ret = wc_ecc_make_key_ex2(&rng, 48, &key->key.ecc, ECC_SECP384R1, WC_ECC_FLAG_DEC_SIGN);
                else if (strcmp(algorithm, "secp521") == 0)
                        ret = wc_ecc_make_key_ex2(&rng, 66, &key->key.ecc, ECC_SECP521R1, WC_ECC_FLAG_DEC_SIGN);
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported ECC curve: %s", algorithm);
        }
        else if (strncmp(algorithm, "mldsa", 5) == 0)
        {
                /* Initialize the key depending on the requested type */
                if (strcmp(algorithm, "mldsa44") == 0)
                        ret = initPrivateKey(key, ML_DSA_LEVEL2k);
                else if (strcmp(algorithm, "mldsa65") == 0)
                        ret = initPrivateKey(key, ML_DSA_LEVEL3k);
                else if (strcmp(algorithm, "mldsa87") == 0)
                        ret = initPrivateKey(key, ML_DSA_LEVEL5k);
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED,
                                  "Unsupported ML-DSA key level: %s",
                                  algorithm);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "ML-DSA key initialization failed");

                /* Generate the actual key pair */
                ret = wc_dilithium_make_key(&key->key.dilithium, &rng);
        }
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
        else if (strncmp(algorithm, "dilithium", 9) == 0)
        {
                /* Initialize the key depending on the requested type */
                if (strcmp(algorithm, "dilithium2") == 0)
                        ret = initPrivateKey(key, DILITHIUM_LEVEL2k);
                else if (strcmp(algorithm, "dilithium3") == 0)
                        ret = initPrivateKey(key, DILITHIUM_LEVEL3k);
                else if (strcmp(algorithm, "dilithium5") == 0)
                        ret = initPrivateKey(key, DILITHIUM_LEVEL5k);
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED,
                                  "Unsupported Dilithium key level: %s",
                                  algorithm);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Dilithium key initialization failed");

                /* Generate the actual key pair */
                ret = wc_dilithium_make_key(&key->key.dilithium, &rng);
        }
#endif
#ifdef HAVE_FALCON
        else if (strncmp(algorithm, "falcon", 6) == 0)
        {
                /* Initialize the key depending on the requested type */
                if (strcmp(algorithm, "falcon512") == 0)
                        ret = initPrivateKey(key, FALCON_LEVEL1k);
                else if (strcmp(algorithm, "falcon1024") == 0)
                        ret = initPrivateKey(key, FALCON_LEVEL5k);
                else
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED,
                                  "Unsupported Falcon key level: %s",
                                  algorithm);

                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "ML-DSA key initialization failed");

                /* Generate the actual key pair */
                ret = wc_falcon_make_key(&key->key.falcon, &rng);
        }
#endif
        else if (strcmp(algorithm, "ed25519") == 0)
        {
                /* Initialize the key */
                ret = initPrivateKey(key, ED25519k);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Ed25519 key initialization failed");

                /* Generate the actual key pair */
                ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key->key.ed25519);
        }
        else if (strcmp(algorithm, "ed448") == 0)
        {
                /* Initialize the key */
                ret = initPrivateKey(key, ED448k);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Ed448 key initialization failed");

                /* Generate the actual key pair */
                ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key->key.ed448);
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported key algorithm: %s", algorithm);

        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Key generation failed: %d", ret);

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

        if (buffer == NULL || buffer_size == NULL || *buffer_size == 0)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Check if the private key is an external referenced one */
        if (key->external.label != NULL)
        {
                /* We cannot export the private key. However, we write the
                 * PKCS#11 label to the buffer to store the label for later
                 * use. */
                ret = snprintf((char*) buffer,
                               *buffer_size,
                               "%s%s%s",
                               PKCS11_LABEL_IDENTIFIER,
                               key->external.label,
                               PKCS11_LABEL_TERMINATOR);

                if (ret < 0 || ret >= *buffer_size)
                        return KRITIS3M_PKI_MEMORY_ERROR;

                *buffer_size = ret;

                return KRITIS3M_PKI_SUCCESS;
        }

        /* Allocate temporary buffers */
        uint8_t* derBuffer = (uint8_t*) malloc(LARGE_TEMP_SZ);
        word32 derSize = LARGE_TEMP_SZ;

        if (derBuffer == NULL)
                return KRITIS3M_PKI_MEMORY_ERROR;

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
        else if (
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                (key->type == DILITHIUM_LEVEL2k) || (key->type == DILITHIUM_LEVEL3k) ||
                (key->type == DILITHIUM_LEVEL5k) ||
#endif
                (key->type == ML_DSA_LEVEL2k) || (key->type == ML_DSA_LEVEL3k) ||
                (key->type == ML_DSA_LEVEL5k))
        {
                /* Encode the key and store it in DER encoding */
                // ret = wc_Dilithium_KeyToDer(&key->key.dilithium, derBuffer, derSize);
                ret = wc_Dilithium_PrivateKeyToDer(&key->key.dilithium, derBuffer, derSize);
        }
#ifdef HAVE_FALCON
        else if ((key->type == FALCON_LEVEL1k) || (key->type == FALCON_LEVEL5k))
        {
                /* Encode the key and store it in DER encoding */
                // ret = wc_Falcon_KeyToDer(&key->key.falcon, derBuffer, derSize);
                ret = wc_Falcon_PrivateKeyToDer(&key->key.falcon, derBuffer, derSize);
        }
#endif
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
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported key type: %d", key->type);

        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Key export failed: %d", ret);

        derSize = ret;

        /* Convert DER to PEM */
        ret = wc_DerToPem(derBuffer, ret, buffer, *buffer_size, PKCS8_PRIVATEKEY_TYPE);
        if (ret > 0)
                *buffer_size = ret;
        else
                ERROR_OUT(KRITIS3M_PKI_PEM_ENCODE_ERROR, "DER to PEM conversion failed: %d", ret);

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
        uint8_t* pemBuffer = NULL;

        if ((destination == NULL) || (source == NULL))
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* No need to copy */
        if (source->init == false)
                return KRITIS3M_PKI_SUCCESS;

        /* Copy external referenced key data */
        if (source->external.label != NULL)
        {
                destination->external.label = (char*) malloc(strlen(source->external.label) + 1);
                if (destination->external.label == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                  "Memory allocation for external label failed");

                strcpy(destination->external.label, source->external.label);
                destination->external.deviceId = source->external.deviceId;

                ret = initPrivateKey(destination, source->type);
                if (ret != 0)
                        ERROR_OUT(ret, "Key initialization failed");

                if (source->type == ECDSAk)
                {
                        destination->key.ecc.dp = source->key.ecc.dp;
                }
        }
        else
        {
                /* Allocate temporary buffers */
                pemBuffer = (uint8_t*) malloc(LARGE_TEMP_SZ);
                size_t pemSize = LARGE_TEMP_SZ;
                if (pemBuffer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Memory allocation for PEM buffer failed");

                /* Export the source key. We re-use our internal exportPrivateKey() method to
                 * not duplicate code. This method exports PEM data. This is actually a very
                 * inefficient method to copy a SinglePrivateKey, but it re-uses the maximum
                 * of existing code.
                 * ToDo: refactor the code to do more efficient deep copies of a key.
                 * */
                ret = exportPrivateKey(source, pemBuffer, &pemSize);
                if (ret != 0)
                        ERROR_OUT(ret, "Key export failed");

                /* Decode PEM data into destination key */
                ret = parsePemBuffer(pemBuffer, pemSize, destination, NULL);
                if (ret != 0)
                        ERROR_OUT(ret, "Key import failed");
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
        case ML_DSA_LEVEL2k:
                sigAlg = CTC_ML_DSA_LEVEL2;
                break;
        case ML_DSA_LEVEL3k:
                sigAlg = CTC_ML_DSA_LEVEL3;
                break;
        case ML_DSA_LEVEL5k:
                sigAlg = CTC_ML_DSA_LEVEL5;
                break;
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
        case DILITHIUM_LEVEL2k:
                sigAlg = CTC_DILITHIUM_LEVEL2;
                break;
        case DILITHIUM_LEVEL3k:
                sigAlg = CTC_DILITHIUM_LEVEL3;
                break;
        case DILITHIUM_LEVEL5k:
                sigAlg = CTC_DILITHIUM_LEVEL5;
                break;
#endif
#ifdef HAVE_FALCON
        case FALCON_LEVEL1k:
                sigAlg = CTC_FALCON_LEVEL1;
                break;
        case FALCON_LEVEL5k:
                sigAlg = CTC_FALCON_LEVEL5;
                break;
#endif
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
                        case ML_DSA_LEVEL2k:
                        case ML_DSA_LEVEL3k:
                        case ML_DSA_LEVEL5k:
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                        case DILITHIUM_LEVEL2k:
                        case DILITHIUM_LEVEL3k:
                        case DILITHIUM_LEVEL5k:
#endif
                                wc_dilithium_free(&key->key.dilithium);
                                break;
#ifdef HAVE_FALCON
                        case FALCON_LEVEL1k:
                        case FALCON_LEVEL5k:
                                wc_falcon_free(&key->key.falcon);
                                break;
#endif
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

/* Create a new InputCert object. */
InputCert* inputCert_new(void)
{
        InputCert* cert = (InputCert*) malloc(sizeof(InputCert));
        if (cert == NULL)
                return NULL;

        cert->buffer = NULL;
        cert->size = 0;
        cert->decoded = (DecodedCert*) malloc(sizeof(DecodedCert));
        if (cert->decoded == NULL)
        {
                free(cert);
                return NULL;
        }

        return cert;
}

/* Initialize the given InputCert `cert` using the PEM encoded data in the provided `buffer`
 * with `buffer_size` bytes. Check if it is compatible with the provided private key.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int inputCert_initFromBuffer(InputCert* cert, uint8_t const* buffer, size_t buffer_size, PrivateKey* privateKey)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        DerBuffer* der = NULL;
        EncryptedInfo info;

        if (cert == NULL || buffer == NULL) /* privateKey may be NULL */
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        memset(&info, 0, sizeof(EncryptedInfo));

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer object */
        ret = wc_PemToDer(buffer, buffer_size, CERT_TYPE, &der, NULL, &info, NULL);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PEM_DECODE_ERROR, "Failed to convert PEM to DER: %d", ret);

        /* Allocate buffer for the DER certificate */
        cert->buffer = (uint8_t*) malloc(der->length);
        if (cert->buffer == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for input cert");

        memcpy(cert->buffer, der->buffer, der->length);
        cert->size = der->length;

        /* Free the DER structure as it is not needed anymore */
        wc_FreeDer(&der);

        /* Decode the cert */
        wc_InitDecodedCert(cert->decoded, cert->buffer, cert->size, NULL);
        ret = wc_ParseCert(cert->decoded, CERT_TYPE, NO_VERIFY, NULL);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to parse input certificate: %d", ret);

        if (privateKey != NULL)
        {
                /* If the private key is not yet properly initialized, fill it with data from the
                 * certificate. This is the case when using an external private key stored on a
                 * secure element. */
                if (privateKey->primaryKey.init == false)
                {
                        /* Initialize the key */
                        ret = initPrivateKey(&privateKey->primaryKey, cert->decoded->keyOID);
                        if (ret != 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                          "Failed to initialize private key: %d",
                                          ret);

                        privateKey->primaryKey.init = true;
                }

                /* Import the public key from the certificate and check if the public key belongs
                 * to the private key */
                ret = importPublicKey(&privateKey->primaryKey,
                                      cert->decoded->publicKey,
                                      cert->decoded->pubKeySize,
                                      cert->decoded->keyOID);
                if (ret != 0)
                        ERROR_OUT(ret, "Failed to import public key from input cert: %d", ret);

#ifdef WOLFSSL_DUAL_ALG_CERTS
                if (cert->decoded->extSapkiSet)
                {
                        if (privateKey->alternativeKey.init == false)
                        {
                                /* Initialize the key */
                                ret = initPrivateKey(&privateKey->alternativeKey,
                                                     cert->decoded->sapkiOID);
                                if (ret != 0)
                                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize alternative private key: %d", ret);

                                privateKey->alternativeKey.init = true;
                        }

                        /* Import the alternative public key from the certificate and check if the
                         * the public key belongs to the private key */
                        ret = importPublicKey(&privateKey->alternativeKey,
                                              cert->decoded->sapkiDer,
                                              cert->decoded->sapkiLen,
                                              cert->decoded->sapkiOID);
                        if (ret != 0)
                                ERROR_OUT(ret, "Failed to import alternative public key from input cert: %d", ret);
                }
#endif
        }

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        if (der != NULL)
                wc_FreeDer(&der);

        return ret;
}

/* Free the memory of given InputCert */
void inputCert_free(InputCert* cert)
{
        if (cert != NULL)
        {
                if (cert->buffer != NULL)
                        free(cert->buffer);

                if (cert->decoded != NULL)
                {
                        wc_FreeDecodedCert(cert->decoded);
                        free(cert->decoded);
                }

                free(cert);
        }
}

/* Shutdown and cleanup for the KRITIS3M PKI libraries. */
void kritis3m_pki_shutdown(void)
{
        /* Cleanup WolfSSL */
        wolfSSL_Cleanup();
}
