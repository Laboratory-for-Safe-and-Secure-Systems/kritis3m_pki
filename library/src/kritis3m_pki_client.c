#include "kritis3m_pki_client.h"
#include "kritis3m_pki_priv.h"

#include <arpa/inet.h>


#define SUBJECT_COUNTRY "DE"
#define SUBJECT_STATE "Bayern"
#define SUBJECT_LOCALITY "Regensburg"
#define SUBJECT_ORG "LaS3"
#define SUBJECT_UNIT "KRITIS3M"
#define SUBJECT_EMAIL "las3@oth-regensburg.de"


/* File global variable for the PKCS#11 token containing the entity key */
static Pkcs11Dev entityDevice;
static Pkcs11Token entityToken;
static bool entityTokenInitialized = false;


/* Initialize the PKCS#11 token for the entity key. Use the library from `path` and
 * the token found at `slot_id`. If `-1` is supplied as `slot_id`, the first found
 * token is used automatically. The `pin` for the token is optional (supply `NULL`
 * and `0` as parameters).
 *
 * Return value is the `device_id` for the initialized token in case of success
 * (positive integer > 0), negative error code otherwise.
 */
int kritis3m_pki_init_entity_token(char const* path, int slot_id, uint8_t const* pin,
                                   size_t pin_size)
{
        /* Initialize the token */
        int ret = initPkcs11Token(&entityDevice, &entityToken, path, slot_id,
                                  pin, pin_size, PKCS11_ENTITY_TOKEN_DEVICE_ID);
        if (ret != KRITIS3M_PKI_SUCCESS)
                return ret;

        entityTokenInitialized = true;

        return PKCS11_ENTITY_TOKEN_DEVICE_ID;
}


/* Import the PrivateKey object 'key' into an external reference.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int kritis3m_pki_entity_token_import_key(PrivateKey* key)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if ((key == NULL) || (key->primaryKey.init == false))
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if (entityTokenInitialized == false)
                ERROR_OUT(KRITIS3M_PKI_LOG_LEVEL_ERR, "PKCS#11 token not initialized");

        /* Determine primary key type */
        int type = -1;
        switch (key->primaryKey.type)
        {
                case RSAk:
                        type = PKCS11_KEY_TYPE_RSA;
                        break;
                case ECDSAk:
                        type = PKCS11_KEY_TYPE_EC;
                        break;
                case DILITHIUM_LEVEL2k:
                case DILITHIUM_LEVEL3k:
                case DILITHIUM_LEVEL5k:
                        type = PKCS11_KEY_TYPE_DILITHIUM;
                        break;
                case FALCON_LEVEL1k:
                case FALCON_LEVEL5k:
                        type = PKCS11_KEY_TYPE_FALCON;
                        break;
                default:
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported primary key type");
        }

        /* Import the primary key */
        ret = wc_Pkcs11StoreKey_ex(&entityToken, type, 0, &key->primaryKey.key, 1);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "Failed to import primary key: %d", ret);

        /* Import the alternative key */
        if (key->alternativeKey.init == true)
        {
               /* Determine alternative key type */
                int type = -1;
                switch (key->alternativeKey.type)
                {
                        case RSAk:
                                type = PKCS11_KEY_TYPE_RSA;
                                break;
                        case ECDSAk:
                                type = PKCS11_KEY_TYPE_EC;
                                break;
                        case DILITHIUM_LEVEL2k:
                        case DILITHIUM_LEVEL3k:
                        case DILITHIUM_LEVEL5k:
                                type = PKCS11_KEY_TYPE_DILITHIUM;
                                break;
                        case FALCON_LEVEL1k:
                        case FALCON_LEVEL5k:
                                type = PKCS11_KEY_TYPE_FALCON;
                                break;
                        default:
                                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported alternative key type");
                }

                /* Import the primary key */
                ret = wc_Pkcs11StoreKey_ex(&entityToken, type, 0, &key->alternativeKey.key, 1);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "Failed to import alternative key: %d", ret);
        }

cleanup:
        return ret;
}


/* Close the PKCS#11 token for the entity key. */
int kritis3m_pki_close_entity_token(void)
{
        if (entityTokenInitialized == true)
        {
                wc_Pkcs11Token_Final(&entityToken);
                wc_Pkcs11_Finalize(&entityDevice);
                entityTokenInitialized = false;
        }

        return KRITIS3M_PKI_SUCCESS;
}


/* Create a new SigningRequest object. */
SigningRequest* signingRequest_new(void)
{
        SigningRequest* request = (SigningRequest*) malloc(sizeof(SigningRequest));
        if (request == NULL)
                return NULL;

        memset(&request->req, 0, sizeof(Cert));
        request->altSigAlg = 0;
        request->altPubKeyDer = NULL;
        request->altSigAlgDer = NULL;
        request->altSigValDer = NULL;

        return request;
}


static int addAltNameEntry(DNS_entry** altNameList, char const* altName, int altNameLen, int type)
{
        int ret = 0;
        DNS_entry* newEntry = AltNameNew(NULL);
        if (newEntry == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to create a new AltName entry");

        newEntry->len = altNameLen;
        newEntry->type = type;
        newEntry->next = NULL; /* We put it at the end of the list */

        /* Allocate DNS Entry name - length of string plus 1 for NULL. */
        newEntry->name = (char*) XMALLOC((size_t)newEntry->len + 1,
                                         NULL,
                                         DYNAMIC_TYPE_ALTNAME);
        if (newEntry->name == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for AltName name entry");

        /* Copy alt name. We use memcpy() here instead of strcpy(), as altName may contain a
         * binary representation of an ip address containing zeros. That would break strcpy().
         */
        memcpy(newEntry->name, altName, altNameLen);
        newEntry->name[altNameLen] = '\0';

        /* Add entry to the end of the list */
        DNS_entry* current = *altNameList;
        if (current == NULL)
                *altNameList = newEntry;
        else
        {
                while (current->next != NULL)
                        current = current->next;

                 current->next = newEntry;
        }
        newEntry = NULL;

cleanup:
        if (newEntry != NULL)
                FreeAltNames(newEntry, NULL);

        return ret;
}


/* Initialize the SigningRequest with given metadata.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int signingRequest_init(SigningRequest* request, SigningRequestMetadata const* metadata)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        DNS_entry* altNames = NULL;

        if (request == NULL || metadata == NULL || metadata->commonName == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Initialize the certificate request structure */
        ret = wc_InitCert(&request->req);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to initialize certificate request structure: %d", ret);

        /* Set metadata */
        if (metadata->commonName != NULL)
                strncpy(request->req.subject.commonName, metadata->commonName, CTC_NAME_SIZE);
        else
                strncpy(request->req.subject.commonName, "KRITIS3M PKI Cert", CTC_NAME_SIZE);

        if (metadata->org != NULL)
                strncpy(request->req.subject.org, metadata->org, CTC_NAME_SIZE);

        if (metadata->unit != NULL)
                strncpy(request->req.subject.unit, metadata->unit, CTC_NAME_SIZE);

        if (metadata->country != NULL)
                strncpy(request->req.subject.country, metadata->country, CTC_NAME_SIZE);
        else
                strncpy(request->req.subject.state, SUBJECT_COUNTRY, CTC_NAME_SIZE);

        if (metadata->state != NULL)
                strncpy(request->req.subject.state, metadata->state, CTC_NAME_SIZE);


        /* Allocate DNS alt name objects */
        if (metadata->altNamesDNS != NULL)
        {
                char* altName = strtok((char*)metadata->altNamesDNS, ";");
                while (altName != NULL)
                {
                        ret = addAltNameEntry(&altNames, altName, strlen(altName), ASN_DNS_TYPE);
                        if (ret < 0)
                                ERROR_OUT(ret, "Failed to add DNS alt name entry");

                        altName = strtok(NULL, ";");
                }
        }

        /* Allocate URI alt name objects */
        if (metadata->altNamesURI != NULL)
        {
                char* altName = strtok((char*)metadata->altNamesURI, ";");
                while (altName != NULL)
                {
                        ret = addAltNameEntry(&altNames, altName, strlen(altName), ASN_URI_TYPE);
                        if (ret < 0)
                                ERROR_OUT(ret, "Failed to add URI alt name entry");

                        altName = strtok(NULL, ";");
                }
        }

        /* Allocate IP alt name objects */
        if (metadata->altNamesIP != NULL)
        {
                char* altName = strtok((char*)metadata->altNamesIP, ";");
                while (altName != NULL)
                {
                        struct in_addr ipv4_addr;
                        ret = inet_aton(altName, &ipv4_addr);
                        if (ret == 0)
                                ERROR_OUT(KRITIS3M_PKI_ARGUMENT_ERROR, "Invalid IPv4 address: %s", altName);

                        ret = addAltNameEntry(&altNames, (char const*) &ipv4_addr.s_addr,
                                              sizeof(ipv4_addr.s_addr), ASN_IP_TYPE);
                        if (ret < 0)
                                ERROR_OUT(ret, "Failed to add IP alt name entry");

                        altName = strtok(NULL, ";");
                }
        }

        /* Store the alt name encoded in the CSR. This uses WolfSSL internal API */
        if (altNames != NULL)
        {
                ret = FlattenAltNames(request->req.altNames, sizeof(request->req.altNames), altNames);
                if (ret >= 0)
                {
                        request->req.altNamesSz = ret;
                }
                else
                        ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to encode alt names: %d", ret);
        }

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        if (altNames != NULL)
                FreeAltNames(altNames, NULL);

        return ret;
}


static int encodeAltKeyData(SigningRequest* request, SinglePrivateKey* key)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if (request == NULL || key == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if (key->init == true)
        {
                /* Export the alternatvie public key for placement in the CSR */
                if (key->type == RSAk)
                {
                        /* Get output size */
                        ret = wc_RsaKeyToPublicDer(&key->key.rsa, NULL, 0);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to get RSA public key size: %d", ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for RSA public key");

                        /* Export public key */
                        ret = wc_RsaKeyToPublicDer(&key->key.rsa, request->altPubKeyDer,
                                                   (word32)ret);
                }
                else if (key->type == ECDSAk)
                {
                        /* Get output size */
                        ret = wc_EccPublicKeyToDer(&key->key.ecc, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to get ECC public key size: %d", ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for ECC public key");

                        ret = wc_EccPublicKeyToDer(&key->key.ecc, request->altPubKeyDer,
                                                   (word32)ret, 1);
                }
                else if ((key->type == DILITHIUM_LEVEL2k) || (key->type == DILITHIUM_LEVEL3k) ||
                        (key->type == DILITHIUM_LEVEL5k))
                {
                        /* Get output size */
                        ret = wc_Dilithium_PublicKeyToDer(&key->key.dilithium, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to get Dilithium public key size: %d", ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for Dilithium public key");

                        /* Export public key */
                        ret = wc_Dilithium_PublicKeyToDer(&key->key.dilithium, request->altPubKeyDer,
                                                          (word32)ret, 1);
                }
                else if ((key->type == FALCON_LEVEL1k) || (key->type == FALCON_LEVEL5k))
                {
                        /* Get output size */
                        ret = wc_Falcon_PublicKeyToDer(&key->key.falcon, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to get Falcon public key size: %d", ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for Falcon public key");

                        /* Export public key */
                        ret = wc_Falcon_PublicKeyToDer(&key->key.falcon, request->altPubKeyDer,
                                                       (word32)ret, 1);
                }
                else if (key->type == ED25519k)
                {
                        /* Get output size */
                        ret = wc_Ed25519PublicKeyToDer(&key->key.ed25519, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to get Ed25519 public key size: %d", ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for Ed25519 public key");

                        /* Export public key */
                        ret = wc_Ed25519PublicKeyToDer(&key->key.ed25519, request->altPubKeyDer,
                                                      (word32)ret, 1);
                }
                else if (key->type == ED448k)
                {
                        /* Get output size */
                        ret = wc_Ed448PublicKeyToDer(&key->key.ed448, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to get Ed448 public key size: %d", ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for Ed448 public key");

                        /* Export public key */
                        ret = wc_Ed448PublicKeyToDer(&key->key.ed448, request->altPubKeyDer,
                                                      (word32)ret, 1);
                }

                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to export public key: %d", ret);

                /* Store public key in CSR */
                ret = wc_SetCustomExtension(&request->req, 0,
                                            SubjectAltPublicKeyInfoExtension,
                                            request->altPubKeyDer, ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_EXT_ERROR, "Failed to store alt public key in CSR: %d", ret);

                /* Get OID of signature algorithm */
                request->altSigAlg = getSigAlgForKey(key);
                if (request->altSigAlg <= 0)
                        ERROR_OUT(request->altSigAlg, "Failed to get signature algorithm for key");

                /* Get size of encoded signature algorithm */
                ret = SetAlgoID(request->altSigAlg, NULL, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to get size of signature algorithm: %d", ret);

                /* Allocate memory */
                request->altSigAlgDer = (uint8_t*) malloc(ret);
                if (request->altSigAlgDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for signature algorithm");

                /* Encode signature algorithm */
                ret = SetAlgoID(request->altSigAlg, request->altSigAlgDer, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to encode alt signature algorithm: %d", ret);

                /* Store signature algorithm in CSR */
                ret = wc_SetCustomExtension(&request->req, 0,
                                            AltSignatureAlgorithmExtension,
                                            request->altSigAlgDer, ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_EXT_ERROR, "Failed to store alt signature algorithm in CSR: %d", ret);
        }

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        return ret;
}


/* Finalize the SigningRequest using the related private key. Store the final PEM encoded output
 * in the buffer `buffer`. On function entry, `buffer_size` must contain the size of the provided
 * output buffer. After successful completion, `buffer_size` will contain the size of the written
 * output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int signingRequest_finalize(SigningRequest* request, PrivateKey* key, uint8_t* buffer, size_t* buffer_size)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        WC_RNG rng;
        DecodedCert decodedCert;
        bool decodedCertInit = false;

        if (request == NULL || key == NULL || buffer == NULL || buffer_size == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Allocate temporary buffers */
        uint8_t* derBuffer = (uint8_t*) malloc(LARGE_TEMP_SZ);
        size_t derSize = LARGE_TEMP_SZ;

        if (derBuffer == NULL)
                return KRITIS3M_PKI_MEMORY_ERROR;

        /* Init RNG */
        ret = wc_InitRng(&rng);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to initialize RNG: %d", ret);

        /* Set primary signature type */
        request->req.sigType = getSigAlgForKey(&key->primaryKey);
        if (request->req.sigType <= 0)
                ERROR_OUT(request->req.sigType, "Failed to get signature algorithm for key");

        /* Check if have to create an alternative signature */
        if (key->alternativeKey.init == true)
        {
                /* Encode the alternative public key and signature algorithm */
                ret = encodeAltKeyData(request, &key->alternativeKey);
                if (ret < 0)
                        ERROR_OUT(ret, "Failed to encode alternative key data");

                /* Generate a temporary CSR to generate the TBS from it */
                ret = wc_MakeCertReq_ex(&request->req, derBuffer, LARGE_TEMP_SZ,
                                        key->primaryKey.certKeyType, &key->primaryKey.key);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to generate temporary CSR: %d", ret);

                /* Sign temporary CSR. Only needed so wc_ParseCert() doesn't fail down below. */
                ret = wc_SignCert_ex(request->req.bodySz, request->req.sigType,
                                derBuffer, LARGE_TEMP_SZ, key->primaryKey.certKeyType,
                                &key->primaryKey.key, &rng);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_SIGN_ERROR, "Failed to sign temporary CSR: %d", ret);

                derSize = ret;

                /* Extract the TBS data for signing with alternative key */
                InitDecodedCert(&decodedCert, derBuffer, derSize, 0);
                ret = ParseCert(&decodedCert, CERTREQ_TYPE, NO_VERIFY, NULL);
                decodedCertInit = true;
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to decode temporary CSR: %d", ret);

                ret = wc_GeneratePreTBS(&decodedCert, derBuffer, LARGE_TEMP_SZ);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to generate preTBS: %d", ret);

                derSize = ret;

                /* Allocate buffer for alternative signature */
                request->altSigValDer = (uint8_t*) malloc(LARGE_TEMP_SZ);
                if (request->altSigValDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for alternative signature");

                /* Generate the alternative signature. */
                ret = wc_MakeSigWithBitStr(request->altSigValDer, LARGE_TEMP_SZ,
                                           request->altSigAlg, derBuffer,
                                           derSize, key->alternativeKey.certKeyType,
                                           &key->alternativeKey.key, &rng);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_SIGN_ERROR, "Failed to generate alternative signature: %d", ret);

                /* Store the alternative signature in the new certificate */
                ret = wc_SetCustomExtension(&request->req, 0,
                                            AltSignatureValueExtension,
                                            request->altSigValDer,
                                            ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_EXT_ERROR, "Failed to store alt signature value in CSR: %d", ret);
        }

        /* Generate the final CSR */
        ret = wc_MakeCertReq_ex(&request->req, derBuffer, LARGE_TEMP_SZ,
                                key->primaryKey.certKeyType, &key->primaryKey.key);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to generate CSR: %d", ret);

        /* Sign the CSR */
        ret = wc_SignCert_ex(request->req.bodySz, request->req.sigType,
                             derBuffer, LARGE_TEMP_SZ, key->primaryKey.certKeyType,
                             &key->primaryKey.key, &rng);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_SIGN_ERROR, "Failed to sign CSR: %d", ret);

        derSize = ret;

        /* Convert the CSR to PEM */
        ret = wc_DerToPem(derBuffer, derSize, buffer, *buffer_size, CERTREQ_TYPE);
        if (ret > 0)
                *buffer_size = ret;
        else
                ERROR_OUT(KRITIS3M_PKI_PEM_ENCODE_ERROR, "Failed to convert CSR to PEM: %d", ret);

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        if (decodedCertInit == true)
                FreeDecodedCert(&decodedCert);
        wc_FreeRng(&rng);
        if (derBuffer != NULL)
                free(derBuffer);

        return ret;
}


/* Free the memory of given SigningRequest */
void signingRequest_free(SigningRequest* request)
{
        if (request != NULL)
        {
                if (request->altPubKeyDer != NULL)
                        free(request->altPubKeyDer);
                if (request->altSigAlgDer != NULL)
                        free(request->altSigAlgDer);
                if (request->altSigValDer != NULL)
                        free(request->altSigValDer);

                free(request);
        }
}
