#include "kritis3m_pki_server.h"
#include "kritis3m_pki_priv.h"


#define LARGE_TEMP_SZ 12288
#define TEMP_SZ 256


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
 * with `buffer_size` bytes.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int issuerCert_initFromBuffer(IssuerCert* cert, uint8_t const* buffer, size_t buffer_size)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        DerBuffer* der = NULL;
        EncryptedInfo info;

        memset(&info, 0, sizeof(EncryptedInfo));

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer object. */
        ret = PemToDer(buffer, buffer_size, CERT_TYPE, &der, NULL, &info, NULL);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PEM_DECODE_ERROR);

        /* Allocate buffer for the decoded certificate */
        cert->buffer = (uint8_t*) malloc(der->length);
        if (cert->buffer == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

        /* Replace PEM data with DER data as we don't need the PEM anymore. As DER
         * encoded data is always smaller than PEM, we are sure that the buffer can
         * hold the DER data safely. */
        memcpy(cert->buffer, der->buffer, der->length);
        cert->size = der->length;

        cert->init = true;
        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        FreeDer(&der);

        return ret;

}


/* Free the memory of given IssuerCert */
void issuerCert_free(IssuerCert* cert)
{
        if (cert->init && cert->buffer != NULL)
        {
                free(cert->buffer);
        }

        free(cert);
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
        DecodedCert decodedCert;
        bool decodedCertInit = false;

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer object. */
        ret = PemToDer(buffer, buffer_size, CERTREQ_TYPE, &der, NULL, NULL, NULL);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_PEM_DECODE_ERROR);

        /* Decode the parsed CSR to access its internal fields for the final certificate */
        InitDecodedCert(&decodedCert, der->buffer, der->length, NULL);
        ret = ParseCert(&decodedCert, CERTREQ_TYPE, VERIFY, NULL);
        decodedCertInit = true;
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR);

        /* Decode the primary public key */
        if (decodedCert.keyOID == RSAk)
        {
                ret = wc_InitRsaKey(&outputCert->ownKey.key.rsa, NULL);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                outputCert->ownKey.certKeyType = RSA_TYPE;
                ret = wc_RsaPublicKeyDecode(decodedCert.publicKey, &index,
                                            &outputCert->ownKey.key.rsa,
                                            decodedCert.pubKeySize);
        }
        else if (decodedCert.keyOID == ECDSAk)
        {
                ret = wc_ecc_init(&outputCert->ownKey.key.ecc);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                outputCert->ownKey.certKeyType = ECC_TYPE;
                ret = wc_EccPublicKeyDecode(decodedCert.publicKey, &index,
                                            &outputCert->ownKey.key.ecc,
                                            decodedCert.pubKeySize);
        }
        else if ((decodedCert.keyOID == DILITHIUM_LEVEL2k) ||
                 (decodedCert.keyOID == DILITHIUM_LEVEL3k) ||
                 (decodedCert.keyOID == DILITHIUM_LEVEL5k))
        {
                wc_dilithium_init(&outputCert->ownKey.key.dilithium);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                switch (decodedCert.keyOID)
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
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                ret = wc_Dilithium_PublicKeyDecode(decodedCert.publicKey, &index,
                                &outputCert->ownKey.key.dilithium, decodedCert.pubKeySize);
        }
        else if ((decodedCert.keyOID == FALCON_LEVEL1k) || (decodedCert.keyOID == FALCON_LEVEL5k))
        {
                wc_falcon_init(&outputCert->ownKey.key.falcon);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                switch (decodedCert.keyOID)
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
                        ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);
                }
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                ret = wc_Falcon_PublicKeyDecode(decodedCert.publicKey, &index,
                                &outputCert->ownKey.key.falcon, decodedCert.pubKeySize);
        }
        else
                ERROR_OUT(KRITIS3M_PKI_KEY_UNSUPPORTED);


        /* Init the certificate structure */
        wc_InitCert(&outputCert->cert);

        /* Copy the subject data */
        if (decodedCert.subjectC)
                strncpy(outputCert->cert.subject.country, decodedCert.subjectC, decodedCert.subjectCLen);
        if (decodedCert.subjectST)
                strncpy(outputCert->cert.subject.state, decodedCert.subjectST, decodedCert.subjectSTLen);
        if (decodedCert.subjectL)
                strncpy(outputCert->cert.subject.locality, decodedCert.subjectL, decodedCert.subjectLLen);
        if (decodedCert.subjectO)
                strncpy(outputCert->cert.subject.org, decodedCert.subjectO, decodedCert.subjectOLen);
        if (decodedCert.subjectOU)
                strncpy(outputCert->cert.subject.unit, decodedCert.subjectOU, decodedCert.subjectOULen);
        if (decodedCert.subjectSN)
                strncpy(outputCert->cert.subject.sur, decodedCert.subjectSN, decodedCert.subjectSNLen);
        if (decodedCert.subjectSND)
                strncpy(outputCert->cert.subject.serialDev, decodedCert.subjectSND, decodedCert.subjectSNDLen);
        if (decodedCert.subjectCN)
                strncpy(outputCert->cert.subject.commonName, decodedCert.subjectCN, decodedCert.subjectCNLen);
        if (decodedCert.subjectEmail)
                strncpy(outputCert->cert.subject.email, decodedCert.subjectEmail, decodedCert.subjectEmailLen);

        /* Copy the SubjectAltPublicKeyInfoExtension */
        if (decodedCert.extSapkiSet && decodedCert.sapkiDer != NULL)
        {
                /* Allocate buffer for the alternative public key */
                outputCert->altPubKeyDer = (uint8_t*) malloc(decodedCert.sapkiLen);
                if (outputCert->altPubKeyDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                /* Copy the alternative public key */
                memcpy(outputCert->altPubKeyDer, decodedCert.sapkiDer, decodedCert.sapkiLen);

                /* Write the alternative public key as a non-critical extension */
                ret = wc_SetCustomExtension(&outputCert->cert, 0,
                                            SubjectAltPublicKeyInfoExtension,
                                            outputCert->altPubKeyDer,
                                            decodedCert.sapkiLen);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_EXT_ERROR);
        }

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        FreeDer(&der);
        if (decodedCertInit)
                FreeDecodedCert(&decodedCert);

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

        /* Set primary signature type */
        outputCert->cert.sigType = getSigAlgForKey(&issuerKey->primaryKey);
        if (outputCert->cert.sigType <= 0)
                ERROR_OUT(outputCert->cert.sigType);

        /* If we issue a hybrid certificate, write the signature algorithm of the issuer */
        if (issuerKey->alternativeKey.init == true)
        {
                /* Get OID of signature algorithm */
                outputCert->altSigAlg = getSigAlgForKey(&issuerKey->alternativeKey);
                if (outputCert->altSigAlg <= 0)
                        ERROR_OUT(outputCert->altSigAlg);

                /* Get size of encoded signature algorithm */
                ret = SetAlgoID(outputCert->altSigAlg, NULL, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Allocate memory */
                outputCert->altSigAlgDer = (uint8_t*) malloc(ret);
                if (outputCert->altSigAlgDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                /* Encode signature algorithm */
                ret = SetAlgoID(outputCert->altSigAlg, outputCert->altSigAlgDer, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Write encoded signature algorithm as a non-critical extension */
                ret = wc_SetCustomExtension(&outputCert->cert, 0,
                                            AltSignatureAlgorithmExtension,
                                            outputCert->altSigAlgDer, ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_EXT_ERROR);
        }

        /* Set the Subject Key Identifier to our own key */
        ret = wc_SetSubjectKeyIdFromPublicKey_ex(&outputCert->cert, outputCert->ownKey.certKeyType,
                                                 &outputCert->ownKey.key);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CERT_ERROR);

        if (issuerCert->init)
        {
                /* Set the issuer */
                ret = wc_SetIssuerBuffer(&outputCert->cert, issuerCert->buffer, issuerCert->size);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR);

                /* Set the Authority Key Identifier to the one of the issuer key */
                ret = wc_SetAuthKeyIdFromPublicKey_ex(&outputCert->cert, issuerKey->primaryKey.certKeyType,
                                                      &issuerKey->primaryKey.key);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR);
        }
        else
        {
                /* Set the Authority Key Identifier to our own key */
                ret = wc_SetAuthKeyIdFromPublicKey_ex(&outputCert->cert, outputCert->ownKey.certKeyType,
                                                      &outputCert->ownKey.key);
                if (ret != 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR);
        }

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        return ret;
}


/* Set the validity period to `days` days of the new OutputCert `outputCert`.
 */
void outputCert_setValidity(OutputCert* outputCert, int days)
{
        outputCert->cert.daysValid = days;
}


/* Configure the new OutputCert to be a CA certificate, capable of signing new certificates. */
int outputCert_configureAsCA(OutputCert* outputCert)
{
        outputCert->cert.isCA = 1;

        /* Limit key usage to only sign new certificates */
        int ret = wc_SetKeyUsage(&outputCert->cert, "keyCertSign");
        if (ret != 0)
                return KRITIS3M_PKI_CERT_ERROR;

        return KRITIS3M_PKI_SUCCESS;
}


/* Configure the new OutputCert to be an entity certificate for authentication. */
int outputCert_configureAsEntity(OutputCert* outputCert)
{
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

        /* Allocate temporary buffers */
        uint8_t* derBuffer = (uint8_t*) malloc(LARGE_TEMP_SZ);
        size_t derSize = LARGE_TEMP_SZ;

        if (derBuffer == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

        /* Init RNG */
        ret = wc_InitRng(&rng);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CERT_SIGN_ERROR);

        /* Check if have to create the alternative signature */
        if (issuerKey->alternativeKey.init == true)
        {
                /* Generate a temporary cert to generate the TBS from it */
                ret = wc_MakeCert_ex(&outputCert->cert, derBuffer, LARGE_TEMP_SZ,
                                     outputCert->ownKey.certKeyType,
                                     &outputCert->ownKey.key, &rng);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR);

                /* Sign temporary cert. Only needed so wc_ParseCert() doesn't fail down below. */
                ret = wc_SignCert_ex(outputCert->cert.bodySz, outputCert->cert.sigType,
                                     derBuffer, LARGE_TEMP_SZ, issuerKey->primaryKey.certKeyType,
                                     &issuerKey->primaryKey.key, &rng);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_SIGN_ERROR);

                derSize = ret;

                /* Extract the TBS data for signing with alternative key */
                InitDecodedCert(&decodedCert, derBuffer, derSize, 0);
                ret = ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
                decodedCertInit = true;
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR);

                /* Set the validity dates of the decoded cert for the new cert. This is
                 * necessary as we have to make sure that the signed preTBS data is exactly
                 * the same as the data that lands in the final cert. */
                memcpy(outputCert->cert.beforeDate, decodedCert.beforeDate, decodedCert.beforeDateLen);
                outputCert->cert.beforeDateSz = decodedCert.beforeDateLen;
                memcpy(outputCert->cert.afterDate, decodedCert.afterDate, decodedCert.afterDateLen);
                outputCert->cert.afterDateSz = decodedCert.afterDateLen;

                ret = wc_GeneratePreTBS(&decodedCert, derBuffer, LARGE_TEMP_SZ);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_ERROR);

                derSize = ret;

                /* Allocate buffer for the alternative signature */
                outputCert->altSigValDer = (uint8_t*) malloc(LARGE_TEMP_SZ);
                if (outputCert->altSigValDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                /* Generate the alternative signature. */
                ret = wc_MakeSigWithBitStr(outputCert->altSigValDer, LARGE_TEMP_SZ,
                                           outputCert->altSigAlg, derBuffer,
                                           derSize, issuerKey->alternativeKey.certKeyType,
                                           &issuerKey->alternativeKey.key, &rng);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CERT_SIGN_ERROR);

                /* Store the alternative signature in the new certificate */
                ret = wc_SetCustomExtension(&outputCert->cert, 0,
                                            AltSignatureValueExtension,
                                            outputCert->altSigValDer, ret);
                if (ret < 0)
                {
                        printf("unable to set custom extension for alternative signature\n");
                        return -1;
                }
        }

        /* Finally, generate the final certificate. */
        ret = wc_MakeCert_ex(&outputCert->cert, derBuffer, LARGE_TEMP_SZ,
                             outputCert->ownKey.certKeyType,
                             &outputCert->ownKey.key, &rng);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CERT_ERROR);

        /* Sign final certificate. */
        ret = wc_SignCert_ex(outputCert->cert.bodySz, outputCert->cert.sigType,
                             derBuffer, LARGE_TEMP_SZ, issuerKey->primaryKey.certKeyType,
                             &issuerKey->primaryKey.key, &rng);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CERT_SIGN_ERROR);

        derSize = ret;

        /* Convert the new certificate to PEM */
        ret = wc_DerToPem(derBuffer, derSize, buffer, *buffer_size, CERT_TYPE);
        if (ret > 0)
                *buffer_size = ret;
        else
                ERROR_OUT(KRITIS3M_PKI_PEM_ENCODE_ERROR);

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
        freeSinglePrivateKey(&outputCert->ownKey);

        if (outputCert->altPubKeyDer != NULL)
                free(outputCert->altPubKeyDer);
        if (outputCert->altSigAlgDer != NULL)
                free(outputCert->altSigAlgDer);
        if (outputCert->altSigValDer != NULL)
                free(outputCert->altSigValDer);

        free(outputCert);
}

