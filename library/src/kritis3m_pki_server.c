#include "kritis3m_pki_server.h"
#include "kritis3m_pki_priv.h"

#ifdef HAVE_PKCS11

/* File global variable for the PKCS#11 token containing the issuer key */
static Pkcs11Dev issuerDevice;
static Pkcs11Token issuerToken;
static bool issuerTokenInitialized = false;

#endif

/* Initialize the PKCS#11 token for the issuer key. Use the library from `path` and
 * the token found at `slot_id`. If `-1` is supplied as `slot_id`, the first found
 * token is used automatically. The `pin` for the token is optional (supply `NULL`
 * and `0` as parameters).
 *
 * Return value is the `device_id` for the initialized token in case of success
 * (positive integer > 0), negative error code otherwise.
 */
int kritis3m_pki_init_issuer_token(char const* path, int slot_id, uint8_t const* pin, size_t pin_size)
{
#ifdef HAVE_PKCS11
        /* Initialize the token */
        int ret = initPkcs11Token(&issuerDevice,
                                  &issuerToken,
                                  path,
                                  slot_id,
                                  pin,
                                  pin_size,
                                  PKCS11_ISSUER_TOKEN_DEVICE_ID);
        if (ret != KRITIS3M_PKI_SUCCESS)
                return ret;

        issuerTokenInitialized = true;

        return PKCS11_ISSUER_TOKEN_DEVICE_ID;
#else
        pki_log(KRITIS3M_PKI_LOG_LEVEL_ERR, "PKCS#11 support not compiled in");
        return KRITIS3M_PKI_PKCS11_ERROR;
#endif
}

/* Close the PKCS#11 token for the issuer key. */
int kritis3m_pki_close_issuer_token(void)
{
#ifdef HAVE_PKCS11
        if (issuerTokenInitialized == true)
        {
                wc_Pkcs11Token_Final(&issuerToken);
                wc_Pkcs11_Finalize(&issuerDevice);
                issuerTokenInitialized = false;
        }

        return KRITIS3M_PKI_SUCCESS;
#else
        pki_log(KRITIS3M_PKI_LOG_LEVEL_ERR, "PKCS#11 support not compiled in");
        return KRITIS3M_PKI_PKCS11_ERROR;
#endif
}

/* Create a new IssuerCert object. */
IssuerCert* issuerCert_new(void)
{
        IssuerCert* cert = (IssuerCert*) malloc(sizeof(IssuerCert));
        if (cert == NULL)
                return NULL;

        cert->buffer = NULL;
        cert->size = 0;
        cert->init = false;

        return cert;
}

/* Initialize the given IssuerCert `cert` using the PEM encoded data in the provided `buffer`
 * with `buffer_size` bytes. Check if it is compatible with the provided issuer private key.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int issuerCert_initFromBuffer(IssuerCert* cert,
                              uint8_t const* buffer,
                              size_t buffer_size,
                              PrivateKey* issuerKey)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        DerBuffer* der = NULL;
        EncryptedInfo info;
        DecodedCert decodedCert;
        bool decodedCertInit = false;

        if (cert == NULL || buffer == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        memset(&info, 0, sizeof(EncryptedInfo));

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer object */
        ret = wc_PemToDer(buffer, buffer_size, CERT_TYPE, &der, NULL, &info, NULL);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PEM_DECODE_ERROR, "Failed to convert PEM to DER: %d", ret);

        /* Decode the parsed issuer cert */
        wc_InitDecodedCert(&decodedCert, der->buffer, der->length, NULL);
        ret = wc_ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
        decodedCertInit = true;
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to parse issuer certificate: %d", ret);

        /* If the issuer key is not yet properly initialized, fill it with data from the issuer
         * certificate. This is the case when using an external issuer key stored on a secure
         * element. */
        if (issuerKey->primaryKey.init == false)
        {
                /* Initialize the key */
                ret = initPrivateKey(&issuerKey->primaryKey, decodedCert.keyOID);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize private key: %d", ret);

                issuerKey->primaryKey.init = true;
        }

        /* Import the public key from the certificate and check if the public key belongs
         * to the private key */
        ret = importPublicKey(&issuerKey->primaryKey,
                              decodedCert.publicKey,
                              decodedCert.pubKeySize,
                              decodedCert.keyOID);
        if (ret != 0)
                ERROR_OUT(ret, "Failed to import public key from issuer cert: %d", ret);

#ifdef WOLFSSL_DUAL_ALG_CERTS
        if (decodedCert.extSapkiSet)
        {
                if (issuerKey->alternativeKey.init == false)
                {
                        /* Initialize the key */
                        ret = initPrivateKey(&issuerKey->alternativeKey, decodedCert.sapkiOID);
                        if (ret != 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                          "Failed to initialize alternative private key: %d",
                                          ret);

                        issuerKey->alternativeKey.init = true;
                }

                /* Import the alternative public key from the certificate and check if the
                 * the public key belongs to the private key */
                ret = importPublicKey(&issuerKey->alternativeKey,
                                      decodedCert.sapkiDer,
                                      decodedCert.sapkiLen,
                                      decodedCert.sapkiOID);
                if (ret != 0)
                        ERROR_OUT(ret,
                                  "Failed to import alternative public key from issuer cert: %d",
                                  ret);
        }
#endif

        /* Allocate buffer for the decoded certificate */
        cert->buffer = (uint8_t*) malloc(der->length);
        if (cert->buffer == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for issuer cert");

        /* Replace PEM data with DER data as we don't need the PEM anymore. As DER
         * encoded data is always smaller than PEM, we are sure that the buffer can
         * hold the DER data safely. */
        memcpy(cert->buffer, der->buffer, der->length);
        cert->size = der->length;

        cert->init = true;
        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        wc_FreeDer(&der);
        if (decodedCertInit)
                wc_FreeDecodedCert(&decodedCert);

        return ret;
}

/* Free the memory of given IssuerCert */
void issuerCert_free(IssuerCert* cert)
{
        if (cert != NULL)
        {
                if (cert->init && cert->buffer != NULL)
                {
                        free(cert->buffer);
                }

                free(cert);
        }
}

/* Create a new OutputCert object. */
OutputCert* outputCert_new(void)
{
        OutputCert* outputCert = (OutputCert*) malloc(sizeof(OutputCert));
        if (outputCert == NULL)
                return NULL;

        memset(&outputCert->ownKey, 0, sizeof(SinglePrivateKey));

        outputCert->ownKey.init = false;
        outputCert->altSigAlg = 0;
        outputCert->altPubKeyDer = NULL;
        outputCert->altSigAlgDer = NULL;
        outputCert->altSigValDer = NULL;
        memset(&outputCert->cert, 0, sizeof(Cert));

        return outputCert;
}

/* Initialize the given OutputCert from the CSR, PEM encoded in the provided `bufffer` with
 * `buffer_size` bytes.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int outputCert_initFromCsr(OutputCert* outputCert, uint8_t const* buffer, size_t buffer_size)
{
        int ret = 0;
        uint32_t index = 0;
        DerBuffer* der = NULL;
        DecodedCert decodedCsr;
        bool decodedCsrInit = false;

        if (outputCert == NULL || buffer == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer object. */
        ret = wc_PemToDer(buffer, buffer_size, CERTREQ_TYPE, &der, NULL, NULL, NULL);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PEM_DECODE_ERROR, "Failed to convert PEM to DER: %d", ret);

        /* Decode the parsed CSR to access its internal fields for the final certificate */
        wc_InitDecodedCert(&decodedCsr, der->buffer, der->length, NULL);
        ret = wc_ParseCert(&decodedCsr, CERTREQ_TYPE, VERIFY, NULL);
        decodedCsrInit = true;
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR, "Failed to parse CSR: %d", ret);

        /* Decode the primary public key */
        if (decodedCsr.keyOID == RSAk)
        {
                ret = wc_InitRsaKey(&outputCert->ownKey.key.rsa, NULL);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize RSA key: %d", ret);

                outputCert->ownKey.type = RSAk;
                outputCert->ownKey.certKeyType = RSA_TYPE;
                outputCert->ownKey.init = true;

                ret = wc_RsaPublicKeyDecode(decodedCsr.publicKey,
                                            &index,
                                            &outputCert->ownKey.key.rsa,
                                            decodedCsr.pubKeySize);
        }
        else if (decodedCsr.keyOID == ECDSAk)
        {
                ret = wc_ecc_init(&outputCert->ownKey.key.ecc);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize ECC key: %d", ret);

                outputCert->ownKey.type = ECDSAk;
                outputCert->ownKey.certKeyType = ECC_TYPE;
                outputCert->ownKey.init = true;

                ret = wc_EccPublicKeyDecode(decodedCsr.publicKey,
                                            &index,
                                            &outputCert->ownKey.key.ecc,
                                            decodedCsr.pubKeySize);
        }
        else if (
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                (decodedCsr.keyOID == DILITHIUM_LEVEL2k) ||
                (decodedCsr.keyOID == DILITHIUM_LEVEL3k) || (decodedCsr.keyOID == DILITHIUM_LEVEL5k) ||
#endif
                (decodedCsr.keyOID == ML_DSA_LEVEL2k) || (decodedCsr.keyOID == ML_DSA_LEVEL3k) ||
                (decodedCsr.keyOID == ML_DSA_LEVEL5k))
        {
                wc_dilithium_init(&outputCert->ownKey.key.dilithium);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize Dilithium key: %d", ret);

                outputCert->ownKey.type = decodedCsr.keyOID;
                outputCert->ownKey.init = true;

                switch (decodedCsr.keyOID)
                {
                case ML_DSA_LEVEL2k:
                        outputCert->ownKey.certKeyType = ML_DSA_LEVEL2_TYPE;
                        ret = wc_dilithium_set_level(&outputCert->ownKey.key.dilithium, WC_ML_DSA_44);
                        break;
                case ML_DSA_LEVEL3k:
                        outputCert->ownKey.certKeyType = ML_DSA_LEVEL3_TYPE;
                        ret = wc_dilithium_set_level(&outputCert->ownKey.key.dilithium, WC_ML_DSA_65);
                        break;
                case ML_DSA_LEVEL5k:
                        outputCert->ownKey.certKeyType = ML_DSA_LEVEL5_TYPE;
                        ret = wc_dilithium_set_level(&outputCert->ownKey.key.dilithium, WC_ML_DSA_87);
                        break;
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                case DILITHIUM_LEVEL2k:
                        outputCert->ownKey.certKeyType = DILITHIUM_LEVEL2_TYPE;
                        ret = wc_dilithium_set_level(&outputCert->ownKey.key.dilithium,
                                                     WC_ML_DSA_44_DRAFT);
                        break;
                case DILITHIUM_LEVEL3k:
                        outputCert->ownKey.certKeyType = DILITHIUM_LEVEL3_TYPE;
                        ret = wc_dilithium_set_level(&outputCert->ownKey.key.dilithium,
                                                     WC_ML_DSA_65_DRAFT);
                        break;
                case DILITHIUM_LEVEL5k:
                        outputCert->ownKey.certKeyType = DILITHIUM_LEVEL5_TYPE;
                        ret = wc_dilithium_set_level(&outputCert->ownKey.key.dilithium,
                                                     WC_ML_DSA_87_DRAFT);
                        break;
#endif
                default:
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED,
                                  "Unsupported Dilithium key type: %d",
                                  decodedCsr.keyOID);
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to set Dilithium level: %d", ret);

                ret = wc_Dilithium_PublicKeyDecode(decodedCsr.publicKey,
                                                   &index,
                                                   &outputCert->ownKey.key.dilithium,
                                                   decodedCsr.pubKeySize);
        }
#ifdef HAVE_FALCON
        else if ((decodedCsr.keyOID == FALCON_LEVEL1k) || (decodedCsr.keyOID == FALCON_LEVEL5k))
        {
                wc_falcon_init(&outputCert->ownKey.key.falcon);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize Falcon key: %d", ret);

                outputCert->ownKey.type = decodedCsr.keyOID;
                outputCert->ownKey.init = true;

                switch (decodedCsr.keyOID)
                {
                case FALCON_LEVEL1k:
                        outputCert->ownKey.certKeyType = FALCON_LEVEL1_TYPE;
                        ret = wc_falcon_set_level(&outputCert->ownKey.key.falcon, 1);
                        break;
                case FALCON_LEVEL5k:
                        outputCert->ownKey.certKeyType = FALCON_LEVEL5_TYPE;
                        ret = wc_falcon_set_level(&outputCert->ownKey.key.falcon, 5);
                        break;
                default:
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED,
                                  "Unsupported Falcon key type: %d",
                                  decodedCsr.keyOID);
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to set Falcon level: %d", ret);

                ret = wc_Falcon_PublicKeyDecode(decodedCsr.publicKey,
                                                &index,
                                                &outputCert->ownKey.key.falcon,
                                                decodedCsr.pubKeySize);
        }
#endif
        else if (decodedCsr.keyOID == ED25519k)
        {
                wc_ed25519_init(&outputCert->ownKey.key.ed25519);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize Ed25519 key: %d", ret);

                outputCert->ownKey.type = ED25519k;
                outputCert->ownKey.certKeyType = ED25519_TYPE;
                outputCert->ownKey.init = true;

                ret = wc_Ed25519PublicKeyDecode(decodedCsr.publicKey,
                                                &index,
                                                &outputCert->ownKey.key.ed25519,
                                                decodedCsr.pubKeySize);
        }
        else if (decodedCsr.keyOID == ED448k)
        {
                wc_ed448_init(&outputCert->ownKey.key.ed448);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize Ed448 key: %d", ret);

                outputCert->ownKey.type = ED448k;
                outputCert->ownKey.certKeyType = ED448_TYPE;
                outputCert->ownKey.init = true;

                ret = wc_Ed448PublicKeyDecode(decodedCsr.publicKey,
                                              &index,
                                              &outputCert->ownKey.key.ed448,
                                              decodedCsr.pubKeySize);
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED,
                          "Unsupported key type in CSR: %d",
                          decodedCsr.keyOID);

        if (ret < 0)
                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to decode public key: %d", ret);

        /* Init the certificate structure */
        wc_InitCert(&outputCert->cert);

        /* Copy the subject data */
        if (decodedCsr.subjectC)
                strncpy(outputCert->cert.subject.country, decodedCsr.subjectC, decodedCsr.subjectCLen);
        if (decodedCsr.subjectST)
                strncpy(outputCert->cert.subject.state, decodedCsr.subjectST, decodedCsr.subjectSTLen);
        if (decodedCsr.subjectL)
                strncpy(outputCert->cert.subject.locality, decodedCsr.subjectL, decodedCsr.subjectLLen);
        if (decodedCsr.subjectO)
                strncpy(outputCert->cert.subject.org, decodedCsr.subjectO, decodedCsr.subjectOLen);
        if (decodedCsr.subjectOU)
                strncpy(outputCert->cert.subject.unit, decodedCsr.subjectOU, decodedCsr.subjectOULen);
        if (decodedCsr.subjectSN)
                strncpy(outputCert->cert.subject.sur, decodedCsr.subjectSN, decodedCsr.subjectSNLen);
        if (decodedCsr.subjectSND)
                strncpy(outputCert->cert.subject.serialDev,
                        decodedCsr.subjectSND,
                        decodedCsr.subjectSNDLen);
        if (decodedCsr.subjectCN)
                strncpy(outputCert->cert.subject.commonName,
                        decodedCsr.subjectCN,
                        decodedCsr.subjectCNLen);
        if (decodedCsr.subjectEmail)
                strncpy(outputCert->cert.subject.email,
                        decodedCsr.subjectEmail,
                        decodedCsr.subjectEmailLen);

        /* Copy the altNames */
        if (decodedCsr.altNames)
        {
                /* Copy the altNames from the CSR to the new certificate. This uses WolfSSL internal API */
                ret = FlattenAltNames(outputCert->cert.altNames,
                                      sizeof(outputCert->cert.altNames),
                                      decodedCsr.altNames);
                if (ret >= 0)
                {
                        outputCert->cert.altNamesSz = ret;
                }
                else
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to copy altNames: %d", ret);
        }

#ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Copy the SubjectAltPublicKeyInfoExtension */
        if (decodedCsr.extSapkiSet && decodedCsr.sapkiDer != NULL)
        {
                /* Allocate buffer for the alternative public key */
                outputCert->altPubKeyDer = (uint8_t*) malloc(decodedCsr.sapkiLen);
                if (outputCert->altPubKeyDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                  "Failed to allocate memory for alternative public key");

                /* Copy the alternative public key */
                memcpy(outputCert->altPubKeyDer, decodedCsr.sapkiDer, decodedCsr.sapkiLen);

                /* Write the alternative public key as a non-critical extension */
                ret = wc_SetCustomExtension(&outputCert->cert,
                                            0,
                                            SubjectAltPublicKeyInfoExtension,
                                            outputCert->altPubKeyDer,
                                            decodedCsr.sapkiLen);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_EXT_ERROR,
                                  "Failed to copy alternative public key from CSR: %d",
                                  ret);
        }
#endif

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        wc_FreeDer(&der);
        if (decodedCsrInit)
                wc_FreeDecodedCert(&decodedCsr);

        return ret;
}

/* Set issuer data of the new OutputCert `outputCert` using data from IssuerCert `issuerCert`
 * and issuer private key `issuerKey`.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int outputCert_setIssuerData(OutputCert* outputCert, IssuerCert* issuerCert, PrivateKey* issuerKey)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if (outputCert == NULL || issuerKey == NULL) /* issuerCert may be NULL */
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Set primary signature type */
        outputCert->cert.sigType = getSigAlgForKey(&issuerKey->primaryKey);
        if (outputCert->cert.sigType <= 0)
                ERROR_OUT(outputCert->cert.sigType, "Failed to get signature algorithm for issuer key");

#ifdef WOLFSSL_DUAL_ALG_CERTS
        /* If we issue a hybrid certificate, write the signature algorithm of the issuer */
        if (issuerKey->alternativeKey.init == true)
        {
                /* Get OID of signature algorithm */
                outputCert->altSigAlg = getSigAlgForKey(&issuerKey->alternativeKey);
                if (outputCert->altSigAlg <= 0)
                        ERROR_OUT(outputCert->altSigAlg,
                                  "Failed to get alternative signature algorithm for issuer key");

                /* Get size of encoded signature algorithm */
                ret = SetAlgoID(outputCert->altSigAlg, NULL, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                  "Failed to get size of alternative signature algorithm: %d",
                                  ret);

                /* Allocate memory */
                outputCert->altSigAlgDer = (uint8_t*) malloc(ret);
                if (outputCert->altSigAlgDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                  "Failed to allocate memory for alternative signature algorithm");

                /* Encode signature algorithm */
                ret = SetAlgoID(outputCert->altSigAlg, outputCert->altSigAlgDer, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR,
                                  "Failed to encode alternative signature algorithm: %d",
                                  ret);

                /* Write encoded signature algorithm as a non-critical extension */
                ret = wc_SetCustomExtension(&outputCert->cert,
                                            0,
                                            AltSignatureAlgorithmExtension,
                                            outputCert->altSigAlgDer,
                                            ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_EXT_ERROR,
                                  "Failed to write alternative signature algorithm: %d",
                                  ret);
        }
#endif

        /* Set the Subject Key Identifier to our own key */
        ret = wc_SetSubjectKeyIdFromPublicKey_ex(&outputCert->cert,
                                                 outputCert->ownKey.certKeyType,
                                                 &outputCert->ownKey.key);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to set Subject Key Identifier");

        if (issuerCert != NULL && issuerCert->init)
        {
                /* Set the issuer */
                ret = wc_SetIssuerBuffer(&outputCert->cert, issuerCert->buffer, issuerCert->size);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to set issuer: %d", ret);

                /* Set the Authority Key Identifier to the one of the issuer key */
                ret = wc_SetAuthKeyIdFromPublicKey_ex(&outputCert->cert,
                                                      issuerKey->primaryKey.certKeyType,
                                                      &issuerKey->primaryKey.key);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR,
                                  "Failed to set Authority Key Identifier: %d",
                                  ret);
        }
        else
        {
                /* Set the Authority Key Identifier to our own key */
                ret = wc_SetAuthKeyIdFromPublicKey_ex(&outputCert->cert,
                                                      outputCert->ownKey.certKeyType,
                                                      &outputCert->ownKey.key);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR,
                                  "Failed to set Authority Key Identifier: %d",
                                  ret);
        }

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        return ret;
}

static inline uint8_t itob(int number)
{
        return (uint8_t) number + 0x30;
}

/* write time to output, format */
static void SetTime(struct tm* date, uint8_t* output, int* output_size)
{
        int i = 0;

        output[i++] = itob((date->tm_year % 10000) / 1000);
        output[i++] = itob((date->tm_year % 1000) / 100);
        output[i++] = itob((date->tm_year % 100) / 10);
        output[i++] = itob(date->tm_year % 10);

        output[i++] = itob(date->tm_mon / 10);
        output[i++] = itob(date->tm_mon % 10);

        output[i++] = itob(date->tm_mday / 10);
        output[i++] = itob(date->tm_mday % 10);

        output[i++] = itob(date->tm_hour / 10);
        output[i++] = itob(date->tm_hour % 10);

        output[i++] = itob(date->tm_min / 10);
        output[i++] = itob(date->tm_min % 10);

        output[i++] = itob(date->tm_sec / 10);
        output[i++] = itob(date->tm_sec % 10);

        output[i++] = 'Z'; /* Zulu profile */

        *output_size = i;
}

static int SetValidity(uint8_t* before, int* before_size, uint8_t* after, int* after_size, int daysValid)
{
        int ret = 0;
        time_t now;
        time_t then;
        struct tm* tmpTime;
        struct tm* expandedTime;
        struct tm localTime;
#if defined(NEED_TMP_TIME)
        /* for use with gmtime_r */
        struct tm tmpTimeStorage;
        tmpTime = &tmpTimeStorage;
#else
        tmpTime = NULL;
#endif
        (void) tmpTime;

        now = wc_Time(0);

        /* subtract 1 day of seconds for more compliance */
        then = now - 86400;
        expandedTime = XGMTIME(&then, tmpTime);
        if (ret == 0)
        {
                localTime = *expandedTime;

                /* adjust */
                localTime.tm_year += 1900;
                localTime.tm_mon += 1;

                SetTime(&localTime, before, before_size);

                /* add daysValid of seconds */
                then = now + (daysValid * (time_t) 86400);
                expandedTime = XGMTIME(&then, tmpTime);
        }
        if (ret == 0)
        {
                localTime = *expandedTime;

                /* adjust */
                localTime.tm_year += 1900;
                localTime.tm_mon += 1;

                SetTime(&localTime, after, after_size);
        }

        return ret;
}

/* Set the validity period to `days` days of the new OutputCert `outputCert`.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int outputCert_setValidity(OutputCert* outputCert, int days)
{
        if (outputCert != NULL)
        {
                outputCert->cert.daysValid = days;

                int ret = SetValidity(outputCert->cert.beforeDate + 2,
                                      &outputCert->cert.beforeDateSz,
                                      outputCert->cert.afterDate + 2,
                                      &outputCert->cert.afterDateSz,
                                      days);
                if (ret != 0)
                        return KRITIS3M_PKI_CERT_ERROR;
                else
                        return KRITIS3M_PKI_SUCCESS;
        }
        else
                return KRITIS3M_PKI_ARGUMENT_ERROR;
}

/* Configure the new OutputCert to be a CA certificate, capable of signing new certificates. */
int outputCert_configureAsCA(OutputCert* outputCert)
{
        if (outputCert == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        outputCert->cert.isCA = 1;

        /* Limit key usage to only sign new certificates */
        int ret = wc_SetKeyUsage(&outputCert->cert, "keyCertSign,cRLSign");
        if (ret != 0)
                return KRITIS3M_PKI_CERT_ERROR;

        return KRITIS3M_PKI_SUCCESS;
}

/* Configure the new OutputCert to be an entity certificate for authentication. */
int outputCert_configureAsEntity(OutputCert* outputCert)
{
        if (outputCert == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        outputCert->cert.isCA = 0;

        /* Limit key usage to only sign messages in TLS handshake */
        int ret = wc_SetKeyUsage(&outputCert->cert, "digitalSignature");
        if (ret != 0)
                return KRITIS3M_PKI_CERT_ERROR;

        ret = wc_SetExtKeyUsage(&outputCert->cert, "serverAuth,clientAuth");
        if (ret != 0)
                return KRITIS3M_PKI_CERT_ERROR;

        return KRITIS3M_PKI_SUCCESS;
}

/* Finalize the new OutputCert by signing it with the issuer private key. Store the final PEM
 * encoded output in the buffer `buffer`. On function entry, `buffer_size` must contain the
 * size of the provided output buffer. After successful completion, `buffer_size` will contain
 * the size of the written output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int outputCert_finalize(OutputCert* outputCert, PrivateKey* issuerKey, uint8_t* buffer, size_t* buffer_size)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        WC_RNG rng;
        DecodedCert decodedCert;
        bool decodedCertInit = false;

        if (outputCert == NULL || issuerKey == NULL || buffer == NULL || buffer_size == NULL)
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Allocate temporary buffers */
        uint8_t* derBuffer = (uint8_t*) malloc(LARGE_TEMP_SZ);
        size_t derSize = LARGE_TEMP_SZ;

        if (derBuffer == NULL)
                return KRITIS3M_PKI_MEMORY_ERROR;

        /* Init RNG */
        ret = wc_InitRng(&rng);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CERT_SIGN_ERROR, "Failed to initialize RNG: %d", ret);

#ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Check if have to create the alternative signature */
        if (issuerKey->alternativeKey.init == true)
        {
                /* Store the original signature type. We have to set that to zero here in order
                 * to generate the PreTBS certificate with wc_MakeCert_ex(). */
                int sigType = outputCert->cert.sigType;
                outputCert->cert.sigType = 0;

                /* Generate the PreTBS */
                ret = wc_MakeCert_ex(&outputCert->cert,
                                     derBuffer,
                                     LARGE_TEMP_SZ,
                                     outputCert->ownKey.certKeyType,
                                     &outputCert->ownKey.key,
                                     &rng);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR,
                                  "Failed to generate temporary certificate: %d",
                                  ret);
                derSize = ret;

                /* Allocate buffer for the alternative signature */
                outputCert->altSigValDer = (uint8_t*) malloc(LARGE_TEMP_SZ);
                if (outputCert->altSigValDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR,
                                  "Failed to allocate memory for alternative signature");

                /* Generate the alternative signature. */
                ret = wc_MakeSigWithBitStr(outputCert->altSigValDer,
                                           LARGE_TEMP_SZ,
                                           outputCert->altSigAlg,
                                           derBuffer,
                                           derSize,
                                           issuerKey->alternativeKey.certKeyType,
                                           &issuerKey->alternativeKey.key,
                                           &rng);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_SIGN_ERROR,
                                  "Failed to generate alternative signature: %d",
                                  ret);

                /* Store the alternative signature in the new certificate */
                ret = wc_SetCustomExtension(&outputCert->cert,
                                            0,
                                            AltSignatureValueExtension,
                                            outputCert->altSigValDer,
                                            ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_EXT_ERROR,
                                  "Failed to write alternative signature: %d",
                                  ret);

                /* Restore the original signature type */
                outputCert->cert.sigType = sigType;
        }
#endif

        /* Finally, generate the final certificate. */
        ret = wc_MakeCert_ex(&outputCert->cert,
                             derBuffer,
                             LARGE_TEMP_SZ,
                             outputCert->ownKey.certKeyType,
                             &outputCert->ownKey.key,
                             &rng);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to generate certificate: %d", ret);

        /* Sign final certificate. */
        ret = wc_SignCert_ex(outputCert->cert.bodySz,
                             outputCert->cert.sigType,
                             derBuffer,
                             LARGE_TEMP_SZ,
                             issuerKey->primaryKey.certKeyType,
                             &issuerKey->primaryKey.key,
                             &rng);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CERT_SIGN_ERROR, "Failed to sign certificate: %d", ret);

        derSize = ret;

        /* Convert the new certificate to PEM */
        ret = wc_DerToPem(derBuffer, derSize, buffer, *buffer_size, CERT_TYPE);
        if (ret > 0)
                *buffer_size = ret;
        else
                ERROR_OUT(KRITIS3M_PKI_PEM_ENCODE_ERROR, "Failed to convert DER to PEM: %d", ret);

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        if (decodedCertInit)
                FreeDecodedCert(&decodedCert);
        if (derBuffer != NULL)
                free(derBuffer);
        wc_FreeRng(&rng);

        return ret;
}

/* Free the memory of given OutputCert */
void outputCert_free(OutputCert* outputCert)
{
        if (outputCert != NULL)
        {
                freeSinglePrivateKey(&outputCert->ownKey);

                if (outputCert->altPubKeyDer != NULL)
                        free(outputCert->altPubKeyDer);
                if (outputCert->altSigAlgDer != NULL)
                        free(outputCert->altSigAlgDer);
                if (outputCert->altSigValDer != NULL)
                        free(outputCert->altSigValDer);

                free(outputCert);
        }
}
