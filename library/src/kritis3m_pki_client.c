#include "kritis3m_pki_client.h"
#include "kritis3m_pki_priv.h"

#include "wolfssl/wolfcrypt/coding.h"
#include "wolfssl/wolfcrypt/hmac.h"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define SUBJECT_COUNTRY "DE"
#define SUBJECT_STATE "Bayern"
#define SUBJECT_LOCALITY "Regensburg"
#define SUBJECT_ORG "LaS3"
#define SUBJECT_UNIT "KRITIS3M"
#define SUBJECT_EMAIL "las3@oth-regensburg.de"

#ifdef HAVE_PKCS11

/* File global variable for the PKCS#11 token containing the entity key */
static Pkcs11Dev entityDevice;
static Pkcs11Token entityToken;
static bool entityTokenInitialized = false;

#endif

/* Initialize the PKCS#11 token for the entity key. Use the library from `path` and
 * the token found at `slot_id`. If `-1` is supplied as `slot_id`, the first found
 * token is used automatically. The `pin` for the token is optional (supply `NULL`
 * and `0` as parameters).
 *
 * Return value is the `device_id` for the initialized token in case of success
 * (positive integer > 0), negative error code otherwise.
 */
int kritis3m_pki_init_entity_token(char const* path, int slot_id, uint8_t const* pin, size_t pin_size)
{
#ifdef HAVE_PKCS11
        /* Initialize the token */
        int ret = initPkcs11Token(&entityDevice,
                                  &entityToken,
                                  path,
                                  slot_id,
                                  pin,
                                  pin_size,
                                  PKCS11_ENTITY_TOKEN_DEVICE_ID);
        if (ret != KRITIS3M_PKI_SUCCESS)
                return ret;

        entityTokenInitialized = true;

        return PKCS11_ENTITY_TOKEN_DEVICE_ID;
#else
        pki_log(KRITIS3M_PKI_LOG_LEVEL_ERR, "PKCS#11 support not compiled in");
        return KRITIS3M_PKI_PKCS11_ERROR;
#endif
}

/* Import the PrivateKey object 'key' into an external reference.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int kritis3m_pki_entity_token_import_key(PrivateKey* key)
{
#ifdef HAVE_PKCS11
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
        case ML_DSA_LEVEL2k:
        case ML_DSA_LEVEL3k:
        case ML_DSA_LEVEL5k:
                type = PKCS11_KEY_TYPE_DILITHIUM;
                break;
#ifdef HAVE_FALCON
        case FALCON_LEVEL1k:
        case FALCON_LEVEL5k:
                type = PKCS11_KEY_TYPE_FALCON;
                break;
#endif
        default:
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported primary key type");
        }

        /* Import the primary key */
        ret = wc_Pkcs11StoreKey_ex(&entityToken, type, 0, &key->primaryKey.key, 1);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "Failed to import primary key: %d", ret);

#ifdef WOLFSSL_DUAL_ALG_CERTS
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
                case ML_DSA_LEVEL2k:
                case ML_DSA_LEVEL3k:
                case ML_DSA_LEVEL5k:
                        type = PKCS11_KEY_TYPE_DILITHIUM;
                        break;
#ifdef HAVE_FALCON
                case FALCON_LEVEL1k:
                case FALCON_LEVEL5k:
                        type = PKCS11_KEY_TYPE_FALCON;
                        break;
#endif
                default:
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported alternative key type");
                }

                /* Import the primary key */
                ret = wc_Pkcs11StoreKey_ex(&entityToken, type, 0, &key->alternativeKey.key, 1);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "Failed to import alternative key: %d", ret);
        }
#endif

cleanup:
        return ret;
#else
        pki_log(KRITIS3M_PKI_LOG_LEVEL_ERR, "PKCS#11 support not compiled in");
        return KRITIS3M_PKI_PKCS11_ERROR;
#endif
}

/* Import the InputCert object 'cert' into an external reference.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
KRITIS3M_PKI_API int kritis3m_pki_entity_token_import_cert(InputCert* cert, char const* label)
{
#ifdef HAVE_PKCS11
        int ret = KRITIS3M_PKI_SUCCESS;

        if ((cert == NULL) || (cert->buffer == NULL))
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if (entityTokenInitialized == false)
                ERROR_OUT(KRITIS3M_PKI_LOG_LEVEL_ERR, "PKCS#11 token not initialized");

        /* Determine certificate type */
        int type = -1;
        if (cert->decoded->isCA)
        {
                size_t len = MIN(cert->decoded->subjectRawLen, cert->decoded->issuerRawLen);

                if (memcmp(cert->decoded->issuerRaw, cert->decoded->subjectRaw, len) == 0)
                        type = PKCS11_CERT_TYPE_ROOT;
                else
                        type = PKCS11_CERT_TYPE_INTERMEDIATE;
        }
        else
                type = PKCS11_CERT_TYPE_ENTITY;

        /* Import the cert */
        ret = wc_Pkcs11StoreCert_ex(&entityToken, type, cert->decoded, label, 1);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "Failed to import cert: %d", ret);

cleanup:
        return ret;
#else
        pki_log(KRITIS3M_PKI_LOG_LEVEL_ERR, "PKCS#11 support not compiled in");
        return KRITIS3M_PKI_PKCS11_ERROR;
#endif
}

/* Import a Base64 encoded symmetric pre-shared key into an external reference.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int kritis3m_pki_entity_token_import_psk(char const* psk, char const* label)
{
#ifdef HAVE_PKCS11
        int ret = KRITIS3M_PKI_SUCCESS;
        byte pskBin[128];
        word32 pskBinLen = sizeof(pskBin);

        if ((psk == NULL) || (label == NULL))
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        if (entityTokenInitialized == false)
                ERROR_OUT(KRITIS3M_PKI_LOG_LEVEL_ERR, "PKCS#11 token not initialized");

        /* Base64 decode the given PSK */
        ret = Base64_Decode(psk, (word32) strlen(psk), pskBin, &pskBinLen);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_DECODE_ERROR, "Failed to decode PSK: %d", ret);

        Hkdf hkdf;
        ret = wc_HkdfInit_Label(&hkdf, SHA256, label, NULL, PKCS11_ENTITY_TOKEN_DEVICE_ID);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize HKDF: %d", ret);

        hkdf.key = pskBin;
        hkdf.keyLen = pskBinLen;

        /* Import the decoded key */
        ret = wc_Pkcs11StoreKey_ex(&entityToken, PKCS11_KEY_TYPE_HKDF, 0, &hkdf, 1);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PKCS11_ERROR, "Failed to import cert: %d", ret);

cleanup:
        wc_HkdfFree(&hkdf);
        return ret;
#else
        pki_log(KRITIS3M_PKI_LOG_LEVEL_ERR, "PKCS#11 support not compiled in");
        return KRITIS3M_PKI_PKCS11_ERROR;
#endif
}

/* Close the PKCS#11 token for the entity key. */
int kritis3m_pki_close_entity_token(void)
{
#ifdef HAVE_PKCS11
        if (entityTokenInitialized == true)
        {
                wc_Pkcs11Token_Final(&entityToken);
                wc_Pkcs11_Finalize(&entityDevice);
                entityTokenInitialized = false;
        }

        return KRITIS3M_PKI_SUCCESS;
#else
        return KRITIS3M_PKI_PKCS11_ERROR;
#endif
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
        newEntry->name = (char*) XMALLOC((size_t) newEntry->len + 1, NULL, DYNAMIC_TYPE_ALTNAME);
        if (newEntry->name == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                          "Failed to allocate memory for AltName name entry");

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
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR,
                          "Failed to initialize certificate request structure: %d",
                          ret);

        request->req.version = 0; /* Version 1 is hex 0. This is the default for CSRs */

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
                strncpy(request->req.subject.country, SUBJECT_COUNTRY, CTC_NAME_SIZE);

        if (metadata->state != NULL)
                strncpy(request->req.subject.state, metadata->state, CTC_NAME_SIZE);

        if (metadata->email != NULL)
                strncpy(request->req.subject.email, metadata->email, CTC_NAME_SIZE);

        /* Allocate DNS alt name objects */
        if (metadata->altNamesDNS != NULL)
        {
                char* altName = strtok((char*) metadata->altNamesDNS, ";");
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
                char* altName = strtok((char*) metadata->altNamesURI, ";");
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
                char* altName = strtok((char*) metadata->altNamesIP, ";");
                while (altName != NULL)
                {
                        struct in_addr ipv4_addr;
                        ret = inet_pton(AF_INET, altName, &ipv4_addr);
                        if (ret == 0)
                                ERROR_OUT(KRITIS3M_PKI_ARGUMENT_ERROR,
                                          "Invalid IPv4 address: %s",
                                          altName);

                        ret = addAltNameEntry(&altNames,
                                              (char const*) &ipv4_addr.s_addr,
                                              sizeof(ipv4_addr.s_addr),
                                              ASN_IP_TYPE);
                        if (ret < 0)
                                ERROR_OUT(ret, "Failed to add IP alt name entry");

                        altName = strtok(NULL, ";");
                }
        }

        /* Allocate Email alt name objects */
        if (metadata->altNamesEmail != NULL)
        {
                char* altName = strtok((char*) metadata->altNamesEmail, ";");
                while (altName != NULL)
                {
                        ret = addAltNameEntry(&altNames, altName, strlen(altName), ASN_RFC822_TYPE);
                        if (ret < 0)
                                ERROR_OUT(ret, "Failed to add Email alt name entry");

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

#ifdef WOLFSSL_DUAL_ALG_CERTS
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
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                          "Failed to get RSA public key size: %d",
                                          ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                          "Failed to allocate memory for RSA public key");

                        /* Export public key */
                        ret = wc_RsaKeyToPublicDer(&key->key.rsa, request->altPubKeyDer, (word32) ret);
                }
                else if (key->type == ECDSAk)
                {
                        /* Get output size */
                        ret = wc_EccPublicKeyToDer(&key->key.ecc, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                          "Failed to get ECC public key size: %d",
                                          ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                          "Failed to allocate memory for ECC public key");

                        ret = wc_EccPublicKeyToDer(&key->key.ecc, request->altPubKeyDer, (word32) ret, 1);
                }
                else if (
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                        (key->type == DILITHIUM_LEVEL2k) || (key->type == DILITHIUM_LEVEL3k) ||
                        (key->type == DILITHIUM_LEVEL5k) ||
#endif
                        (key->type == ML_DSA_LEVEL2k) || (key->type == ML_DSA_LEVEL3k) ||
                        (key->type == ML_DSA_LEVEL5k))
                {
                        /* Get output size */
                        ret = wc_Dilithium_PublicKeyToDer(&key->key.dilithium, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                          "Failed to get Dilithium public key size: %d",
                                          ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                          "Failed to allocate memory for Dilithium public key");

                        /* Export public key */
                        ret = wc_Dilithium_PublicKeyToDer(&key->key.dilithium,
                                                          request->altPubKeyDer,
                                                          (word32) ret,
                                                          1);
                }
#ifdef HAVE_FALCON
                else if ((key->type == FALCON_LEVEL1k) || (key->type == FALCON_LEVEL5k))
                {
                        /* Get output size */
                        ret = wc_Falcon_PublicKeyToDer(&key->key.falcon, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                          "Failed to get Falcon public key size: %d",
                                          ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                          "Failed to allocate memory for Falcon public key");

                        /* Export public key */
                        ret = wc_Falcon_PublicKeyToDer(&key->key.falcon,
                                                       request->altPubKeyDer,
                                                       (word32) ret,
                                                       1);
                }
#endif
                else if (key->type == ED25519k)
                {
                        /* Get output size */
                        ret = wc_Ed25519PublicKeyToDer(&key->key.ed25519, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                          "Failed to get Ed25519 public key size: %d",
                                          ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                          "Failed to allocate memory for Ed25519 public key");

                        /* Export public key */
                        ret = wc_Ed25519PublicKeyToDer(&key->key.ed25519,
                                                       request->altPubKeyDer,
                                                       (word32) ret,
                                                       1);
                }
                else if (key->type == ED448k)
                {
                        /* Get output size */
                        ret = wc_Ed448PublicKeyToDer(&key->key.ed448, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                          "Failed to get Ed448 public key size: %d",
                                          ret);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                          "Failed to allocate memory for Ed448 public key");

                        /* Export public key */
                        ret = wc_Ed448PublicKeyToDer(&key->key.ed448,
                                                     request->altPubKeyDer,
                                                     (word32) ret,
                                                     1);
                }

                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to export public key: %d", ret);

                /* Store public key in CSR */
                request->req.sapkiDer = request->altPubKeyDer;
                request->req.sapkiLen = ret;

                /* Get OID of signature algorithm */
                request->altSigAlg = getSigAlgForKey(key);
                if (request->altSigAlg <= 0)
                        ERROR_OUT(request->altSigAlg, "Failed to get signature algorithm for key");

                /* Get size of encoded signature algorithm */
                ret = SetAlgoID(request->altSigAlg, NULL, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                  "Failed to get size of signature algorithm: %d",
                                  ret);

                /* Allocate memory */
                request->altSigAlgDer = (uint8_t*) malloc(ret);
                if (request->altSigAlgDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                  "Failed to allocate memory for signature algorithm");

                /* Encode signature algorithm */
                ret = SetAlgoID(request->altSigAlg, request->altSigAlgDer, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                  "Failed to encode alt signature algorithm: %d",
                                  ret);

                /* Store signature algorithm in CSR */
                request->req.altSigAlgDer = request->altSigAlgDer;
                request->req.altSigAlgLen = ret;
        }

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        return ret;
}
#endif

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

#ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Check if have to create an alternative signature */
        if (key->alternativeKey.init == true)
        {
                /* Encode the alternative public key and signature algorithm */
                ret = encodeAltKeyData(request, &key->alternativeKey);
                if (ret < 0)
                        ERROR_OUT(ret, "Failed to encode alternative key data");

                /* Store the original signature type. We have to set that to zero here in order
                 * to generate the PreTBS certificate with wc_MakeCert_ex(). */
                int sigType = request->req.sigType;
                request->req.sigType = 0;

                /* Generate a temporary CSR to generate the TBS from it */
                ret = wc_MakeCertReq_ex(&request->req,
                                        derBuffer,
                                        LARGE_TEMP_SZ,
                                        key->primaryKey.certKeyType,
                                        &key->primaryKey.key);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to generate temporary CSR: %d", ret);

                derSize = ret;

                /* Allocate buffer for alternative signature */
                request->altSigValDer = (uint8_t*) malloc(LARGE_TEMP_SZ);
                if (request->altSigValDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                  "Failed to allocate memory for alternative signature");

                /* Generate the alternative signature. */
                ret = wc_MakeSigWithBitStr(request->altSigValDer,
                                           LARGE_TEMP_SZ,
                                           request->altSigAlg,
                                           derBuffer,
                                           derSize,
                                           key->alternativeKey.certKeyType,
                                           &key->alternativeKey.key,
                                           &rng);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_SIGN_ERROR,
                                  "Failed to generate alternative signature: %d",
                                  ret);

                /* Store the alternative signature in the new certificate */
                request->req.altSigValDer = request->altSigValDer;
                request->req.altSigValLen = ret;

                request->req.sigType = sigType;
        }
#endif

        /* Generate the final CSR */
        ret = wc_MakeCertReq_ex(&request->req,
                                derBuffer,
                                LARGE_TEMP_SZ,
                                key->primaryKey.certKeyType,
                                &key->primaryKey.key);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to generate CSR: %d", ret);

        /* Sign the CSR */
        ret = wc_SignCert_ex(request->req.bodySz,
                             request->req.sigType,
                             derBuffer,
                             LARGE_TEMP_SZ,
                             key->primaryKey.certKeyType,
                             &key->primaryKey.key,
                             &rng);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_SIGN_ERROR, "Failed to sign CSR: %d", ret);

        derSize = ret;

        /* Convert the CSR to PEM */
        ret = wc_DerToPem(derBuffer, derSize, buffer, *buffer_size, CERTREQ_TYPE);
        if (ret > 0)
                *buffer_size = ret;
        else
                ERROR_OUT(KRITIS3M_PKI_ENCODE_ERROR, "Failed to convert CSR to PEM: %d", ret);

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
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
