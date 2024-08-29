#include "kritis3m_pki_server.h"
#include "kritis3m_pki_priv.h"



/* File global variable for the PKCS#11 token containing the issuer key */
static Pkcs11Token issuerToken;
static bool issuerTokenInitialized = false;


/* Initialize the PKCS#11 token for the issuer key. Use the token found at `slot_id`.
 * If `-1` is supplied as `slot_id`, the first found token is used automatically. The
 * `pin` for the token is optional.
 *
 * Return value is the `device_id` for the initialized token in case of success
 * (positive integer > 0), negative error code otherwise.
 */
int kritis3m_pki_init_issuer_token(int slot_id, uint8_t const* pin, size_t pin_size)
{
        /* Initialize the token */
        int ret = initPkcs11Token(&issuerToken, slot_id, pin, pin_size, PKCS11_ISSUER_TOKEN_DEVICE_ID);
        if (ret != KRITIS3M_PKI_SUCCESS)
                return ret;

        issuerTokenInitialized = true;

        return PKCS11_ISSUER_TOKEN_DEVICE_ID;
}


/* Close the PKCS#11 token for the issuer key. */
int kritis3m_pki_close_issuer_token(void)
{
        if (issuerTokenInitialized == true)
        {
                wc_Pkcs11Token_Final(&issuerToken);
                issuerTokenInitialized = false;
        }

        return KRITIS3M_PKI_SUCCESS;
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
int issuerCert_initFromBuffer(IssuerCert* cert, uint8_t const* buffer, size_t buffer_size,
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
        ret = importPublicKey(&issuerKey->primaryKey, decodedCert.publicKey,
                              decodedCert.pubKeySize, decodedCert.keyOID);
        if (ret != 0)
                ERROR_OUT(ret, "Failed to import public key from issuer cert: %d", ret);


        if (decodedCert.extSapkiSet)
        {
                if (issuerKey->alternativeKey.init == false)
                {
                        /* Initialize the key */
                        ret = initPrivateKey(&issuerKey->alternativeKey, decodedCert.sapkiOID);
                        if (ret != 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize alternative private key: %d", ret);

                        issuerKey->alternativeKey.init = true;
                }

                /* Import the alternative public key from the certificate and check if the
                 * the public key belongs to the private key */
                ret = importPublicKey(&issuerKey->alternativeKey, decodedCert.sapkiDer,
                                decodedCert.sapkiLen, decodedCert.sapkiOID);
                if (ret != 0)
                        ERROR_OUT(ret, "Failed to import alternative public key from issuer cert: %d", ret);
        }

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
        FreeDer(&der);
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
        int index = 0;
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

                outputCert->ownKey.certKeyType = RSA_TYPE;
                ret = wc_RsaPublicKeyDecode(decodedCsr.publicKey, &index,
                                            &outputCert->ownKey.key.rsa,
                                            decodedCsr.pubKeySize);
        }
        else if (decodedCsr.keyOID == ECDSAk)
        {
                ret = wc_ecc_init(&outputCert->ownKey.key.ecc);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize ECC key: %d", ret);

                outputCert->ownKey.certKeyType = ECC_TYPE;
                ret = wc_EccPublicKeyDecode(decodedCsr.publicKey, &index,
                                            &outputCert->ownKey.key.ecc,
                                            decodedCsr.pubKeySize);
        }
        else if ((decodedCsr.keyOID == DILITHIUM_LEVEL2k) ||
                 (decodedCsr.keyOID == DILITHIUM_LEVEL3k) ||
                 (decodedCsr.keyOID == DILITHIUM_LEVEL5k))
        {
                wc_dilithium_init(&outputCert->ownKey.key.dilithium);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize Dilithium key: %d", ret);

                switch (decodedCsr.keyOID)
                {
                case DILITHIUM_LEVEL2k:
                        outputCert->ownKey.certKeyType = DILITHIUM_LEVEL2_TYPE;
                        ret = wc_dilithium_set_level(&outputCert->ownKey.key.dilithium, 2);
                        break;
                case DILITHIUM_LEVEL3k:
                        outputCert->ownKey.certKeyType = DILITHIUM_LEVEL3_TYPE;
                        ret = wc_dilithium_set_level(&outputCert->ownKey.key.dilithium, 3);
                        break;
                case DILITHIUM_LEVEL5k:
                        outputCert->ownKey.certKeyType = DILITHIUM_LEVEL5_TYPE;
                        ret = wc_dilithium_set_level(&outputCert->ownKey.key.dilithium, 5);
                        break;
                default:
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported Dilithium key type: %d", decodedCsr.keyOID);
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to set Dilithium level: %d", ret);

                ret = wc_Dilithium_PublicKeyDecode(decodedCsr.publicKey, &index,
                                &outputCert->ownKey.key.dilithium, decodedCsr.pubKeySize);
        }
        else if ((decodedCsr.keyOID == FALCON_LEVEL1k) || (decodedCsr.keyOID == FALCON_LEVEL5k))
        {
                wc_falcon_init(&outputCert->ownKey.key.falcon);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize Falcon key: %d", ret);

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
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported Falcon key type: %d", decodedCsr.keyOID);
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to set Falcon level: %d", ret);

                ret = wc_Falcon_PublicKeyDecode(decodedCsr.publicKey, &index,
                                &outputCert->ownKey.key.falcon, decodedCsr.pubKeySize);
        }
        else if (decodedCsr.keyOID == ED25519k)
        {
                wc_ed25519_init(&outputCert->ownKey.key.ed25519);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize Ed25519 key: %d", ret);

                outputCert->ownKey.certKeyType = ED25519_TYPE;
                ret = wc_Ed25519PublicKeyDecode(decodedCsr.publicKey, &index,
                                                &outputCert->ownKey.key.ed25519,
                                                decodedCsr.pubKeySize);
        }
        else if (decodedCsr.keyOID == ED448k)
        {
                wc_ed448_init(&outputCert->ownKey.key.ed448);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to initialize Ed448 key: %d", ret);

                outputCert->ownKey.certKeyType = ED448_TYPE;
                ret = wc_Ed448PublicKeyDecode(decodedCsr.publicKey, &index,
                                                &outputCert->ownKey.key.ed448,
                                                decodedCsr.pubKeySize);
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED, "Unsupported key type in CSR: %d", decodedCsr.keyOID);

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
                strncpy(outputCert->cert.subject.serialDev, decodedCsr.subjectSND, decodedCsr.subjectSNDLen);
        if (decodedCsr.subjectCN)
                strncpy(outputCert->cert.subject.commonName, decodedCsr.subjectCN, decodedCsr.subjectCNLen);
        if (decodedCsr.subjectEmail)
                strncpy(outputCert->cert.subject.email, decodedCsr.subjectEmail, decodedCsr.subjectEmailLen);

        /* Copy the altNames */
        if (decodedCsr.altNames)
        {
                /* Copy the altNames from the CSR to the new certificate. This uses WolfSSL internal API */
                ret = FlattenAltNames(outputCert->cert.altNames, sizeof(outputCert->cert.altNames),
                                      decodedCsr.altNames);
                if (ret >= 0)
                {
                        outputCert->cert.altNamesSz = ret;
                }
                else
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to copy altNames: %d", ret);
        }

        /* Copy the SubjectAltPublicKeyInfoExtension */
        if (decodedCsr.extSapkiSet && decodedCsr.sapkiDer != NULL)
        {
                /* Allocate buffer for the alternative public key */
                outputCert->altPubKeyDer = (uint8_t*) malloc(decodedCsr.sapkiLen);
                if (outputCert->altPubKeyDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for alternative public key");

                /* Copy the alternative public key */
                memcpy(outputCert->altPubKeyDer, decodedCsr.sapkiDer, decodedCsr.sapkiLen);

                /* Write the alternative public key as a non-critical extension */
                ret = wc_SetCustomExtension(&outputCert->cert, 0,
                                            SubjectAltPublicKeyInfoExtension,
                                            outputCert->altPubKeyDer,
                                            decodedCsr.sapkiLen);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_EXT_ERROR, "Failed to copy alternative public key from CSR: %d", ret);
        }

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

        /* If we issue a hybrid certificate, write the signature algorithm of the issuer */
        if (issuerKey->alternativeKey.init == true)
        {
                /* Get OID of signature algorithm */
                outputCert->altSigAlg = getSigAlgForKey(&issuerKey->alternativeKey);
                if (outputCert->altSigAlg <= 0)
                        ERROR_OUT(outputCert->altSigAlg, "Failed to get alternative signature algorithm for issuer key");

                /* Get size of encoded signature algorithm */
                ret = SetAlgoID(outputCert->altSigAlg, NULL, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to get size of alternative signature algorithm: %d", ret);

                /* Allocate memory */
                outputCert->altSigAlgDer = (uint8_t*) malloc(ret);
                if (outputCert->altSigAlgDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for alternative signature algorithm");

                /* Encode signature algorithm */
                ret = SetAlgoID(outputCert->altSigAlg, outputCert->altSigAlgDer, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR, "Failed to encode alternative signature algorithm: %d", ret);

                /* Write encoded signature algorithm as a non-critical extension */
                ret = wc_SetCustomExtension(&outputCert->cert, 0,
                                            AltSignatureAlgorithmExtension,
                                            outputCert->altSigAlgDer, ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_EXT_ERROR, "Failed to write alternative signature algorithm: %d", ret);
        }

        /* Set the Subject Key Identifier to our own key */
        ret = wc_SetSubjectKeyIdFromPublicKey_ex(&outputCert->cert, outputCert->ownKey.certKeyType,
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
                ret = wc_SetAuthKeyIdFromPublicKey_ex(&outputCert->cert, issuerKey->primaryKey.certKeyType,
                                                      &issuerKey->primaryKey.key);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to set Authority Key Identifier: %d", ret);
        }
        else
        {
                /* Set the Authority Key Identifier to our own key */
                ret = wc_SetAuthKeyIdFromPublicKey_ex(&outputCert->cert, outputCert->ownKey.certKeyType,
                                                      &outputCert->ownKey.key);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to set Authority Key Identifier: %d", ret);
        }

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        return ret;
}


/* Set the validity period to `days` days of the new OutputCert `outputCert`.
 */
void outputCert_setValidity(OutputCert* outputCert, int days)
{
        if (outputCert != NULL)
                outputCert->cert.daysValid = days;
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

        /* Check if have to create the alternative signature */
        if (issuerKey->alternativeKey.init == true)
        {
                /* Generate a temporary cert to generate the TBS from it */
                ret = wc_MakeCert_ex(&outputCert->cert, derBuffer, LARGE_TEMP_SZ,
                                     outputCert->ownKey.certKeyType,
                                     &outputCert->ownKey.key, &rng);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to generate temporary certificate: %d", ret);

                /* Sign temporary cert. Only needed so wc_ParseCert() doesn't fail down below. */
                ret = wc_SignCert_ex(outputCert->cert.bodySz, outputCert->cert.sigType,
                                     derBuffer, LARGE_TEMP_SZ, issuerKey->primaryKey.certKeyType,
                                     &issuerKey->primaryKey.key, &rng);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_SIGN_ERROR, "Failed to sign temporary certificate: %d", ret);

                derSize = ret;

                /* Extract the TBS data for signing with alternative key */
                InitDecodedCert(&decodedCert, derBuffer, derSize, 0);
                ret = ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
                decodedCertInit = true;
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to parse temporary certificate: %d", ret);

                /* Set the validity dates of the decoded cert for the new cert. This is
                 * necessary as we have to make sure that the signed preTBS data is exactly
                 * the same as the data that lands in the final cert. */
                memcpy(outputCert->cert.beforeDate, decodedCert.beforeDate, decodedCert.beforeDateLen);
                outputCert->cert.beforeDateSz = decodedCert.beforeDateLen;
                memcpy(outputCert->cert.afterDate, decodedCert.afterDate, decodedCert.afterDateLen);
                outputCert->cert.afterDateSz = decodedCert.afterDateLen;

                ret = wc_GeneratePreTBS(&decodedCert, derBuffer, LARGE_TEMP_SZ);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to generate preTBS data: %d", ret);

                derSize = ret;

                /* Allocate buffer for the alternative signature */
                outputCert->altSigValDer = (uint8_t*) malloc(LARGE_TEMP_SZ);
                if (outputCert->altSigValDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR, "Failed to allocate memory for alternative signature");

                /* Generate the alternative signature. */
                ret = wc_MakeSigWithBitStr(outputCert->altSigValDer, LARGE_TEMP_SZ,
                                           outputCert->altSigAlg, derBuffer,
                                           derSize, issuerKey->alternativeKey.certKeyType,
                                           &issuerKey->alternativeKey.key, &rng);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_SIGN_ERROR, "Failed to generate alternative signature: %d", ret);

                /* Store the alternative signature in the new certificate */
                ret = wc_SetCustomExtension(&outputCert->cert, 0,
                                            AltSignatureValueExtension,
                                            outputCert->altSigValDer, ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_EXT_ERROR, "Failed to write alternative signature: %d", ret);
        }

        /* Finally, generate the final certificate. */
        ret = wc_MakeCert_ex(&outputCert->cert, derBuffer, LARGE_TEMP_SZ,
                             outputCert->ownKey.certKeyType,
                             &outputCert->ownKey.key, &rng);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CERT_ERROR, "Failed to generate certificate: %d", ret);

        /* Sign final certificate. */
        ret = wc_SignCert_ex(outputCert->cert.bodySz, outputCert->cert.sigType,
                             derBuffer, LARGE_TEMP_SZ, issuerKey->primaryKey.certKeyType,
                             &issuerKey->primaryKey.key, &rng);
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

