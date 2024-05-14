#include "kritis3m_pki_common.h"
#include "kritis3m_pki_priv.h"


/* Create a new PrivateKey object */
PrivateKey* privateKey_new(void)
{
        PrivateKey* key = (PrivateKey*) malloc(sizeof(PrivateKey));
        if (key == NULL)
                return NULL;

        memset(&key->primaryKey, 0, sizeof(SinglePrivateKey));
        memset(&key->alternativeKey, 0, sizeof(SinglePrivateKey));

        return key;
}


/* Internal helper method */
int parsePemFile(uint8_t const* buffer, size_t buffer_size, SinglePrivateKey* key, EncryptedInfo* info)
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
                ret = wc_InitRsaKey(&key->key.rsa, NULL);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                key->certKeyType = RSA_TYPE;
                ret = wc_RsaPrivateKeyDecode(der->buffer, &index, &key->key.rsa, der->length);
        }
        else if (key->type == ECDSAk)
        {
                ret = wc_ecc_init(&key->key.ecc);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                key->certKeyType = ECC_TYPE;
                ret = wc_EccPrivateKeyDecode(der->buffer, &index, &key->key.ecc, der->length);
        }
        else if ((key->type == DILITHIUM_LEVEL2k) || (key->type == DILITHIUM_LEVEL3k) ||
                (key->type == DILITHIUM_LEVEL5k))
        {
                wc_dilithium_init(&key->key.dilithium);
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
                wc_falcon_init(&key->key.falcon);
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

        memset(&info, 0, sizeof(EncryptedInfo));

        /* Parse alternative key */
        ret = parsePemFile(buffer, buffer_size, &key->alternativeKey, &info);

        return ret;
}


/* Internal helper method */
int getSigAlgForKey(SinglePrivateKey* key)
{
        int sigAlg = 0;

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
}

/* Free the memory of given PrivateKey */
void privateKey_free(PrivateKey* key)
{
        freeSinglePrivateKey(&key->primaryKey);
        freeSinglePrivateKey(&key->alternativeKey);

        free(key);
}

