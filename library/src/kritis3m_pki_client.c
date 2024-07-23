#include "kritis3m_pki_client.h"
#include "kritis3m_pki_priv.h"


#define SUBJECT_COUNTRY "DE"
#define SUBJECT_STATE "Bayern"
#define SUBJECT_LOCALITY "Regensburg"
#define SUBJECT_ORG "LaS3"
#define SUBJECT_UNIT "KRITIS3M"
#define SUBJECT_EMAIL "las3@oth-regensburg.de"


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


/* Initialize the SigningRequest with given metadata.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int signingRequest_init(SigningRequest* request, SigningRequestMetadata const* metadata)
{
        int ret = KRITIS3M_PKI_SUCCESS;
        DNS_entry* altNameEncoded = NULL;

        if (request == NULL || metadata == NULL)
                ERROR_OUT(KRITIS3M_PKI_ARGUMENT_ERROR);

        /* Initialize the certificate request structure */
        ret = wc_InitCert(&request->req);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR);

        /* Set metadata */
        if (metadata->CN != NULL)
                strncpy(request->req.subject.commonName, metadata->CN, CTC_NAME_SIZE);
        else
                strncpy(request->req.subject.commonName, "KRITIS3M PKI Cert", CTC_NAME_SIZE);

        strncpy(request->req.subject.country, SUBJECT_COUNTRY, CTC_NAME_SIZE);
        // strncpy(request->req.subject.state, SUBJECT_STATE, CTC_NAME_SIZE);
        // strncpy(request->req.subject.locality, SUBJECT_LOCALITY, CTC_NAME_SIZE);
        if (metadata->O != NULL)
                strncpy(request->req.subject.org, metadata->O, CTC_NAME_SIZE);
        else
                strncpy(request->req.subject.org, SUBJECT_ORG, CTC_NAME_SIZE);

        if (metadata->OU != NULL)
                strncpy(request->req.subject.unit, metadata->OU, CTC_NAME_SIZE);
        else
                strncpy(request->req.subject.unit, SUBJECT_UNIT, CTC_NAME_SIZE);
        // strncpy(request->req.subject.email, SUBJECT_EMAIL, CTC_NAME_SIZE);

        /* Allocate DNS Entry object. */
        if (metadata->altName != NULL)
        {
                altNameEncoded = AltNameNew(request->req.heap);
                if (altNameEncoded == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                altNameEncoded->len = strlen(metadata->altName);
                altNameEncoded->type = ASN_DNS_TYPE;
                altNameEncoded->next = NULL;

                /* Allocate DNS Entry name - length of string plus 1 for NUL. */
                altNameEncoded->name = (char*) XMALLOC((size_t)altNameEncoded->len + 1,
                                                request->req.heap,
                                                DYNAMIC_TYPE_ALTNAME);
                if (altNameEncoded->name == NULL)
                {
                        /* Manually free to prevent double free of altNameEncoded->name in
                         * FreeAltNames(). */
                        XFREE(altNameEncoded, request->req.heap, DYNAMIC_TYPE_ALTNAME);
                        altNameEncoded = NULL;
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);
                }
                strcpy(altNameEncoded->name, metadata->altName);

                /* Store the alt name encoded in the CSR. This uses WolfSSL internal API */
                ret = FlattenAltNames(request->req.altNames, sizeof(request->req.altNames),
                                      altNameEncoded);
                if (ret >= 0)
                {
                        request->req.altNamesSz = ret;
                }
                else
                        ERROR_OUT(KRITIS3M_PKI_CSR_ERROR);
        }

        ret = KRITIS3M_PKI_SUCCESS;

cleanup:
        if (altNameEncoded != NULL)
                FreeAltNames(altNameEncoded, request->req.heap);

        return ret;
}


static int encodeAltKeyData(SigningRequest* request, SinglePrivateKey* key)
{
        int ret = KRITIS3M_PKI_SUCCESS;

        if (request == NULL || key == NULL)
                ERROR_OUT(KRITIS3M_PKI_ARGUMENT_ERROR);

        if (key->init == true)
        {
                /* Export the alternatvie public key for placement in the CSR */
                if (key->type == RSAk)
                {
                        /* Get output size */
                        ret = wc_RsaKeyToPublicDer(&key->key.rsa, NULL, 0);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                        /* Export public key */
                        ret = wc_RsaKeyToPublicDer(&key->key.rsa, request->altPubKeyDer,
                                                   (word32)ret);
                }
                else if (key->type == ECDSAk)
                {
                        /* Get output size */
                        ret = wc_EccPublicKeyToDer(&key->key.ecc, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                        ret = wc_EccPublicKeyToDer(&key->key.ecc, request->altPubKeyDer,
                                                   (word32)ret, 1);
                }
                else if ((key->type == DILITHIUM_LEVEL2k) || (key->type == DILITHIUM_LEVEL3k) ||
                        (key->type == DILITHIUM_LEVEL5k))
                {
                        /* Get output size */
                        ret = wc_Dilithium_PublicKeyToDer(&key->key.dilithium, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                        /* Export public key */
                        ret = wc_Dilithium_PublicKeyToDer(&key->key.dilithium, request->altPubKeyDer,
                                                          (word32)ret, 1);
                }
                else if ((key->type == FALCON_LEVEL1k) || (key->type == FALCON_LEVEL5k))
                {
                        /* Get output size */
                        ret = wc_Falcon_PublicKeyToDer(&key->key.falcon, NULL, 0, 1);
                        if (ret <= 0)
                                ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                        /* Allocate buffer */
                        request->altPubKeyDer = (uint8_t*) malloc(ret);
                        if (request->altPubKeyDer == NULL)
                                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                        /* Export public key */
                        ret = wc_Falcon_PublicKeyToDer(&key->key.falcon, request->altPubKeyDer,
                                                       (word32)ret, 1);
                }

                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Store public key in CSR */
                ret = wc_SetCustomExtension(&request->req, 0,
                                            SubjectAltPublicKeyInfoExtension,
                                            request->altPubKeyDer, ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_EXT_ERROR);

                /* Get OID of signature algorithm */
                request->altSigAlg = getSigAlgForKey(key);
                if (request->altSigAlg <= 0)
                        ERROR_OUT(request->altSigAlg);

                /* Get size of encoded signature algorithm */
                ret = SetAlgoID(request->altSigAlg, NULL, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Allocate memory */
                request->altSigAlgDer = (uint8_t*) malloc(ret);
                if (request->altSigAlgDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                /* Encode signature algorithm */
                ret = SetAlgoID(request->altSigAlg, request->altSigAlgDer, oidSigType, 0);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_KEY_ERROR);

                /* Store signature algorithm in CSR */
                ret = wc_SetCustomExtension(&request->req, 0,
                                            AltSignatureAlgorithmExtension,
                                            request->altSigAlgDer, ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_EXT_ERROR);
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
                ERROR_OUT(KRITIS3M_PKI_ARGUMENT_ERROR);

        /* Allocate temporary buffers */
        uint8_t* derBuffer = (uint8_t*) malloc(LARGE_TEMP_SZ);
        size_t derSize = LARGE_TEMP_SZ;

        if (derBuffer == NULL)
                ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

        /* Init RNG */
        ret = wc_InitRng(&rng);
        if (ret != 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR);

        /* Set primary signature type */
        request->req.sigType = getSigAlgForKey(&key->primaryKey);
        if (request->req.sigType <= 0)
                ERROR_OUT(request->req.sigType);

        /* Check if have to create an alternative signature */
        if (key->alternativeKey.init == true)
        {
                /* Encode the alternative public key and signature algorithm */
                ret = encodeAltKeyData(request, &key->alternativeKey);
                if (ret < 0)
                        ERROR_OUT(ret);

                /* Generate a temporary CSR to generate the TBS from it */
                ret = wc_MakeCertReq_ex(&request->req, derBuffer, LARGE_TEMP_SZ,
                                        key->primaryKey.certKeyType, &key->primaryKey.key);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_ERROR);

                /* Sign temporary CSR. Only needed so wc_ParseCert() doesn't fail down below. */
                ret = wc_SignCert_ex(request->req.bodySz, request->req.sigType,
                                derBuffer, LARGE_TEMP_SZ, key->primaryKey.certKeyType,
                                &key->primaryKey.key, &rng);
                if (ret <= 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_SIGN_ERROR);

                derSize = ret;

                /* Extract the TBS data for signing with alternative key */
                InitDecodedCert(&decodedCert, derBuffer, derSize, 0);
                ret = ParseCert(&decodedCert, CERTREQ_TYPE, NO_VERIFY, NULL);
                decodedCertInit = true;
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_ERROR);

                ret = wc_GeneratePreTBS(&decodedCert, derBuffer, LARGE_TEMP_SZ);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_ERROR);

                derSize = ret;

                /* Allocate buffer for alternative signature */
                request->altSigValDer = (uint8_t*) malloc(LARGE_TEMP_SZ);
                if (request->altSigValDer == NULL)
                        ERROR_OUT(KRITIS3M_PKI_MEMORY_ERROR);

                /* Generate the alternative signature. */
                ret = wc_MakeSigWithBitStr(request->altSigValDer, LARGE_TEMP_SZ,
                                           request->altSigAlg, derBuffer,
                                           derSize, key->alternativeKey.certKeyType,
                                           &key->alternativeKey.key, &rng);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_SIGN_ERROR);

                /* Store the alternative signature in the new certificate */
                ret = wc_SetCustomExtension(&request->req, 0,
                                            AltSignatureValueExtension,
                                            request->altSigValDer,
                                            ret);
                if (ret < 0)
                        ERROR_OUT(KRITIS3M_PKI_CSR_EXT_ERROR);
        }

        /* Generate the final CSR */
        ret = wc_MakeCertReq_ex(&request->req, derBuffer, LARGE_TEMP_SZ,
                                key->primaryKey.certKeyType, &key->primaryKey.key);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_ERROR);

        /* Sign the CSR */
        ret = wc_SignCert_ex(request->req.bodySz, request->req.sigType,
                             derBuffer, LARGE_TEMP_SZ, key->primaryKey.certKeyType,
                             &key->primaryKey.key, &rng);
        if (ret <= 0)
                ERROR_OUT(KRITIS3M_PKI_CSR_SIGN_ERROR);

        derSize = ret;

        /* Convert the CSR to PEM */
        ret = wc_DerToPem(derBuffer, derSize, buffer, *buffer_size, CERTREQ_TYPE);
        if (ret > 0)
                *buffer_size = ret;
        else
                ERROR_OUT(KRITIS3M_PKI_PEM_ENCODE_ERROR);

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
