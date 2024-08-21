
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "cli_common.h"
#include "kritis3m_pki_client.h"
#include "kritis3m_pki_server.h"

#include "kritis3m_pki_cli_parsing.h"

#include "logging.h"


LOG_MODULE_CREATE(kritis3m_pki);


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); ret = 1; goto exit; }


int main(int argc, char** argv)
{
        int ret = 0;

        static const size_t bufferSize = 32 * 1024;
        size_t bytesInBuffer = bufferSize;
        uint8_t* buffer = NULL;

        application_config app_config = {0};
        pki_paths paths = {0};
        pki_keygen_algorithm keygen_algos = {0};
        pki_metadata metadata = {0};
        pki_secure_element secure_element = {0};

        PrivateKey* issuerKey = NULL;
        IssuerCert* issuerCert = NULL;
        PrivateKey* entityKey = NULL;
        SigningRequest* request = NULL;
        OutputCert* outputCert = NULL;


        /* Parse the command line arguments */
        ret = parse_cli_arguments(&app_config, &paths, &keygen_algos, &metadata,
                                  &secure_element, argc, argv);
        LOG_LVL_SET(app_config.log_level);
        if (ret != 0)
                ERROR_OUT("unable to parse command line arguments");


        /* Create a buffer to read the file contents */
        buffer = (uint8_t*) malloc(bufferSize);
        if (buffer == NULL)
                ERROR_OUT("unable to allocate buffer");

        /* Check if we want to use a secure element */
        if (secure_element.middlewarePath != NULL)
        {
                LOG_INFO("Initializing PKCS#11 library using middleware from \"%s\"", secure_element.middlewarePath);

                ret = kritis3m_pki_init_pkcs11(secure_element.middlewarePath);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to initialize PKCS#11 middleware: %s (%d)", kritis3m_pki_error_message(ret), ret);
        }

        /* Load the entity key */
        entityKey = privateKey_new();
        if (entityKey == NULL)
                ERROR_OUT("unable to allocate memory for entity key");

        if (paths.entityKeyPath != NULL)
        {
                /* Check if an external private key should be used */
                if (strncmp(paths.entityKeyPath, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        LOG_INFO("Referencing external entity key with label \"%s\"",
                                 paths.entityKeyPath + PKCS11_LABEL_IDENTIFIER_LEN);

                        /* Initialize the related PKCS#11 token */
                        secure_element.entityTokenDeviceId = kritis3m_pki_init_entity_token(secure_element.slotEntityKey,
                                                                                            NULL, 0);
                        if (secure_element.entityTokenDeviceId < KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to initialize entity token: %s (%d)",
                                          kritis3m_pki_error_message(secure_element.entityTokenDeviceId),
                                          secure_element.entityTokenDeviceId);

                        /* Set the external reference */
                        ret = privateKey_setExternalRef(entityKey, secure_element.entityTokenDeviceId,
                                                        paths.entityKeyPath + PKCS11_LABEL_IDENTIFIER_LEN);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to set external reference for entity key: %s (%d)",
                                          kritis3m_pki_error_message(ret), ret);
                }
                else
                {
                        LOG_INFO("Loading entity key from \"%s\"", paths.entityKeyPath);

                        /* Read file */
                        bytesInBuffer = bufferSize;
                        ret = readFile(paths.entityKeyPath, buffer, &bytesInBuffer);
                        if (ret < 0)
                                ERROR_OUT("unable to read entity key file from \"%s\"", paths.entityKeyPath);

                        /* Load key */
                        ret = privateKey_loadKeyFromBuffer(entityKey, buffer, bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to parse entity key: %s (%d)", kritis3m_pki_error_message(ret), ret);
                }

                /* Load an alternative entity key */
                if (paths.entityAltKeyPath != NULL)
                {
                        /* Check if an external alternative private key should be used */
                        if (strncmp(paths.entityAltKeyPath, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                        {
                                LOG_INFO("Referencing external entity alt key with label \"%s\"",
                                         paths.entityAltKeyPath + PKCS11_LABEL_IDENTIFIER_LEN);

                                /* Check if the token is not yet initialized */
                                if (secure_element.entityTokenDeviceId < 0)
                                {
                                        /* Initialize the related PKCS#11 token */
                                        secure_element.entityTokenDeviceId = kritis3m_pki_init_entity_token(secure_element.slotEntityKey,
                                                                                                            NULL, 0);
                                        if (secure_element.entityTokenDeviceId < KRITIS3M_PKI_SUCCESS)
                                                ERROR_OUT("unable to initialize entity token: %s (%d)",
                                                          kritis3m_pki_error_message(secure_element.entityTokenDeviceId),
                                                          secure_element.entityTokenDeviceId);
                                }

                                /* Set the external reference */
                                ret = privateKey_setAltExternalRef(entityKey, secure_element.entityTokenDeviceId,
                                                                   paths.entityKeyPath + PKCS11_LABEL_IDENTIFIER_LEN);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to set external reference for entity alt key: %s (%d)",
                                                  kritis3m_pki_error_message(ret), ret);
                        }
                        else
                        {
                                LOG_INFO("Loading entity alternative key from \"%s\"", paths.entityAltKeyPath);

                                /* Read file */
                                bytesInBuffer = bufferSize;
                                ret = readFile(paths.entityAltKeyPath, buffer, &bytesInBuffer);
                                if (ret < 0)
                                        ERROR_OUT("unable to read entity alt key file from \"%s\"", paths.entityAltKeyPath);

                                /* Load key */
                                ret = privateKey_loadAltKeyFromBuffer(entityKey, buffer, bytesInBuffer);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to parse entity alt key: %s (%d)", kritis3m_pki_error_message(ret), ret);
                        }
                }
        }

        /* Check if we want to generate a new key */
        if (keygen_algos.keyAlg != NULL)
        {
                LOG_INFO("Generating a new %s key", keygen_algos.keyAlg);

                /* Generate the key */
                ret = privateKey_generateKey(entityKey, keygen_algos.keyAlg);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to generate key: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Write the key to file if requested */
                if (paths.entityKeyOutputPath != NULL)
                {
                        LOG_INFO("Writing key to \"%s\"", paths.entityKeyOutputPath);

                        bytesInBuffer = bufferSize;
                        ret = privateKey_writeKeyToBuffer(entityKey, buffer, &bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to write key to buffer: %s (%d)", kritis3m_pki_error_message(ret), ret);

                        ret = writeFile(paths.entityKeyOutputPath, buffer, bytesInBuffer, false);
                        if (ret < 0)
                                ERROR_OUT("unable to write key to \"%s\"", paths.entityKeyOutputPath);
                }
                else
                {
                        if (paths.entityKeyPath == NULL)
                        {
                                ERROR_OUT("No key output path specified and no external key referenced. The new key is lost, aborting.");
                        }
                }
        }
        /* Check if we need an alternative key */
        if (keygen_algos.altKeyAlg != NULL)
        {
                LOG_INFO("Generating a new %s entity key", keygen_algos.altKeyAlg);

                /* Generate the key */
                ret = privateKey_generateAltKey(entityKey, keygen_algos.altKeyAlg);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to generate alt key: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Write the key to file if requested */
                if ((paths.entityAltKeyOutputPath != NULL) || (paths.entityKeyOutputPath != NULL))
                {
                        char const* destination = paths.entityAltKeyOutputPath;
                        bool appendAltKey = false;
                        if (destination == NULL)
                        {
                                destination = paths.entityKeyOutputPath;
                                appendAltKey = true;
                        }

                        LOG_INFO("Writing key to \"%s\"", destination);

                        bytesInBuffer = bufferSize;
                        ret = privateKey_writeAltKeyToBuffer(entityKey, buffer, &bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to write alt key to buffer: %s (%d)",
                                          kritis3m_pki_error_message(ret), ret);

                        ret = writeFile(destination, buffer, bytesInBuffer, appendAltKey);
                        if (ret < 0)
                                ERROR_OUT("unable to write alt key to \"%s\"", destination);
                }
        }

        /* Load the issuer key */
        issuerKey = privateKey_new();
        if (issuerKey == NULL)
                ERROR_OUT("unable to allocate memory for issuer key");

        if (paths.issuerKeyPath != NULL)
        {
                /* Check if an external private key should be used */
                if (strncmp(paths.issuerKeyPath, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        LOG_INFO("Referencing external issuer key with label \"%s\"",
                                 paths.issuerKeyPath + PKCS11_LABEL_IDENTIFIER_LEN);

                        /* Initialize the related PKCS#11 token */
                        secure_element.issuerTokenDeviceId = kritis3m_pki_init_issuer_token(secure_element.slotIssuerKey,
                                                                                            NULL, 0);
                        if (secure_element.issuerTokenDeviceId < KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to initialize issuer token: %s (%d)",
                                          kritis3m_pki_error_message(secure_element.issuerTokenDeviceId),
                                          secure_element.issuerTokenDeviceId);

                        /* Set the external reference */
                        ret = privateKey_setExternalRef(issuerKey, secure_element.issuerTokenDeviceId,
                                                        paths.issuerKeyPath + PKCS11_LABEL_IDENTIFIER_LEN);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to set external reference for issuer key: %s (%d)",
                                          kritis3m_pki_error_message(ret), ret);
                }
                else
                {
                        LOG_INFO("Loading issuer key from \"%s\"", paths.issuerKeyPath);

                        /* Read file */
                        bytesInBuffer = bufferSize;
                        ret = readFile(paths.issuerKeyPath, buffer, &bytesInBuffer);
                        if (ret < 0)
                                ERROR_OUT("unable to read issuer key file from \"%s\"", paths.issuerKeyPath);

                        /* Load key */
                        ret = privateKey_loadKeyFromBuffer(issuerKey, buffer, bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to parse issuer key: %s (%d)", kritis3m_pki_error_message(ret), ret);
                }

                /* Load an alternative issuer key */
                if (paths.issuerAltKeyPath != NULL)
                {
                        /* Check if an external alternative private key should be used */
                        if (strncmp(paths.issuerAltKeyPath, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                        {
                                LOG_INFO("Referencing external issuer alt key with label \"%s\"",
                                         paths.issuerAltKeyPath + PKCS11_LABEL_IDENTIFIER_LEN);

                                /* Check if the token is not yet initialized */
                                if (secure_element.issuerTokenDeviceId < 0)
                                {
                                        /* Initialize the related PKCS#11 token */
                                        secure_element.issuerTokenDeviceId = kritis3m_pki_init_issuer_token(secure_element.slotIssuerKey,
                                                                                                            NULL, 0);
                                        if (secure_element.issuerTokenDeviceId < KRITIS3M_PKI_SUCCESS)
                                                ERROR_OUT("unable to initialize issuer token: %s (%d)",
                                                          kritis3m_pki_error_message(secure_element.issuerTokenDeviceId),
                                                          secure_element.issuerTokenDeviceId);
                                }

                                /* Set the external reference */
                                ret = privateKey_setAltExternalRef(issuerKey, secure_element.issuerTokenDeviceId,
                                                                   paths.issuerAltKeyPath + PKCS11_LABEL_IDENTIFIER_LEN);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to set external reference for issuer alt key: %s (%d)",
                                                  kritis3m_pki_error_message(ret), ret);
                        }
                        else
                        {
                                LOG_INFO("Loading alternative issuer key from \"%s\"", paths.issuerAltKeyPath);

                                /* Read file */
                                bytesInBuffer = bufferSize;
                                ret = readFile(paths.issuerAltKeyPath, buffer, &bytesInBuffer);
                                if (ret < 0)
                                        ERROR_OUT("unable to read issuer alt key file from \"%s\"", paths.issuerAltKeyPath);

                                /* Load key */
                                ret = privateKey_loadAltKeyFromBuffer(issuerKey, buffer, bytesInBuffer);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to parse issuer alt key: %s (%d)",
                                                  kritis3m_pki_error_message(ret), ret);
                        }
                }
        }

        /* Load the issuer certificate */
        if (paths.issuerCertPath != NULL)
        {
                LOG_INFO("Loading issuer cert from \"%s\"", paths.issuerCertPath);

                issuerCert = issuerCert_new();
                if (issuerCert == NULL)
                        ERROR_OUT("unable to allocate memory for issuer cert");

                /* Read file */
                bytesInBuffer = bufferSize;
                ret = readFile(paths.issuerCertPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read issuer cert file from \"%s\"", paths.issuerCertPath);

                /* Load cert */
                ret = issuerCert_initFromBuffer(issuerCert, buffer, bytesInBuffer, issuerKey);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse issuer cert: %s (%d)",
                                  kritis3m_pki_error_message(ret), ret);
        }

        /* Check if we have to generate a new CSR of if the user provided one */
        if (paths.csrInputPath == NULL)
        {
                LOG_INFO("Generating a new CSR");

                /* We have to create a new CSR */
                request = signingRequest_new();

                SigningRequestMetadata csr_metadata = {
                        .CN = metadata.commonName,
                        .O = metadata.orgName,
                        .OU = metadata.orgUnit,
                        .altNamesDNS = metadata.altNamesDNS,
                        .altNamesURI = metadata.altNamesURI,
                        .altNamesIP = metadata.altNamesIP,
                };

                /* Create the CSR */
                ret = signingRequest_init(request, &csr_metadata);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to create CSR: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Finalize the CSR */
                bytesInBuffer = bufferSize;
                ret = signingRequest_finalize(request, entityKey, buffer, &bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to finalize CSR: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Write the CSR to file if requested */
                if (paths.csrOutputFilePath != NULL)
                {
                        LOG_INFO("Writing CSR to \"%s\"", paths.csrOutputFilePath);

                        ret = writeFile(paths.csrOutputFilePath, buffer, bytesInBuffer, false);
                        if (ret < 0)
                                ERROR_OUT("unable to write CSR to \"%s\"", paths.csrOutputFilePath);
                }
        }
        else
        {
                LOG_INFO("Loading CSR from \"%s\"", paths.issuerKeyPath);

                /* Load the existing CSR */
                bytesInBuffer = bufferSize;
                ret = readFile(paths.csrInputPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read CSR file from \"%s\"", paths.csrInputPath);

        }

        /* Check if we have to create an actual certificate */
        if (paths.certOutputFilePath != NULL)
        {
                LOG_INFO("Generating a new certifiate");

                outputCert = outputCert_new();

                /* Create the new certificate from the CSR. */
                ret = outputCert_initFromCsr(outputCert, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse CSR: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Set the issuer data */
                ret = outputCert_setIssuerData(outputCert, issuerCert, issuerKey);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to set issuer data: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Set the validity period */
                outputCert_setValidity(outputCert, metadata.validity);

                if (metadata.enableCA)
                {
                        LOG_INFO("Certificate is a CA cert");

                        /* Cert is a CA certificate */
                        ret = outputCert_configureAsCA(outputCert);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to configure new cert as CA: %s (%d)", kritis3m_pki_error_message(ret), ret);
                }
                else
                {
                        LOG_INFO("Certificate is an entity cert");

                        /* Cert is an entity certificate */
                        ret = outputCert_configureAsEntity(outputCert);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to configure new cert as entity: %s (%d)", kritis3m_pki_error_message(ret), ret);
                }

                /* Finalize the certificate. */
                bytesInBuffer = bufferSize;
                ret = outputCert_finalize(outputCert, issuerKey, buffer, &bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to finalize new cert: %s (%d)", kritis3m_pki_error_message(ret), ret);

                LOG_INFO("Writing certificate to \"%s\"", paths.certOutputFilePath);

                /* Write the new cert to file */
                ret = writeFile(paths.certOutputFilePath, buffer, bytesInBuffer, false);
                if (ret < 0)
                        ERROR_OUT("unable to write output cert to \"%s\"", paths.certOutputFilePath);
        }

        ret = KRITIS3M_PKI_SUCCESS;

exit:
        kritis3m_pki_close_entity_token();
        kritis3m_pki_close_issuer_token();

        privateKey_free(issuerKey);
        privateKey_free(entityKey);

        issuerCert_free(issuerCert);

        signingRequest_free(request);

        outputCert_free(outputCert);

        if (buffer != NULL)
                free(buffer);

        return ret;
}

