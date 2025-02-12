
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "kritis3m_pki_client.h"
#include "kritis3m_pki_server.h"

#include "kritis3m_pki_cli_parsing.h"

#include "file_io.h"
#include "logging.h"

LOG_MODULE_CREATE(kritis3m_pki);

#define ERROR_OUT(...)                                                                             \
        {                                                                                          \
                LOG_ERROR(__VA_ARGS__);                                                            \
                ret = 1;                                                                           \
                goto exit;                                                                         \
        }

#define RESET_BUFFER()                                                                             \
        {                                                                                          \
                free(buffer);                                                                      \
                buffer = NULL;                                                                     \
                bytesInBuffer = 0;                                                                 \
        }

static void pki_lib_log_callback(int32_t level, char const* message)
{
        switch (level)
        {
        case KRITIS3M_PKI_LOG_LEVEL_ERR:
                LOG_ERROR("%s", message);
                break;
        case KRITIS3M_PKI_LOG_LEVEL_WRN:
                LOG_WARN("%s", message);
                break;
        case KRITIS3M_PKI_LOG_LEVEL_INF:
                LOG_INFO("%s", message);
                break;
        case KRITIS3M_PKI_LOG_LEVEL_DBG:
                LOG_DEBUG("%s", message);
                break;
        default:
                LOG_ERROR("unknown log level %d: %s", level, message);
                break;
        }
}

int main(int argc, char** argv)
{
        int ret = 0;

        static const size_t outputBufferSize = 32 * 1024;
        size_t bytesInBuffer = 0;
        uint8_t* buffer = NULL;

        application_config app_config = {0};
        pki_paths paths = {0};
        pki_generation_info gen_info = {0};
        pki_metadata metadata = {0};
        pki_pkcs11 pkcs11 = {0};

        PrivateKey* issuerKey = NULL;
        InputCert* issuerCert = NULL;
        PrivateKey* entityKey = NULL;
        SigningRequest* request = NULL;
        OutputCert* outputCert = NULL;

        /* Parse the command line arguments */
        ret = parse_cli_arguments(&app_config, &paths, &gen_info, &metadata, &pkcs11, argc, argv);
        LOG_LVL_SET(app_config.log_level);
        if (ret != 0)
                ERROR_OUT("unable to parse command line arguments");

        /* Initialize the PKI libraries */
        kritis3m_pki_configuration pki_lib_config = {
                .logging_enabled = true,
                .log_level = LOG_LVL_GET(),
                .log_callback = pki_lib_log_callback,
        };
        ret = kritis3m_pki_init(&pki_lib_config);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to initialize PKI libraries: %s (%d)",
                          kritis3m_pki_error_message(ret),
                          ret);

        /* Load the entity key */
        entityKey = privateKey_new();
        if (entityKey == NULL)
                ERROR_OUT("unable to allocate memory for entity key");

        if (paths.entityKeyPath != NULL)
        {
                /* Check if we have to read a file */
                if (strncmp(paths.entityKeyPath, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) ==
                    0)
                {
                        /* Duplicate string */
                        buffer = (uint8_t*) duplicate_string(paths.entityKeyPath);
                        if (buffer == NULL)
                                ERROR_OUT("unable to duplicate PKCS#11 label");
                }
                else
                {
                        LOG_INFO("Loading entity key from \"%s\"", paths.entityKeyPath);

                        /* Read file */
                        ret = read_file(paths.entityKeyPath, &buffer, &bytesInBuffer);
                        if (ret < 0)
                                ERROR_OUT("unable to read entity key file from \"%s\"",
                                          paths.entityKeyPath);
                }

                /* Check if an external private key should be used */
                if (strncmp((char*) buffer, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        char* label = strtok((char*) buffer, PKCS11_LABEL_TERMINATOR);
                        label += PKCS11_LABEL_IDENTIFIER_LEN;

                        LOG_INFO("Referencing external entity key with label \"%s\"", label);

                        /* Initialize the related PKCS#11 token */
                        pkcs11.entityModule
                                .deviceId = kritis3m_pki_init_entity_token(pkcs11.entityModule.path,
                                                                           pkcs11.entityModule.slot,
                                                                           (uint8_t const*) pkcs11
                                                                                   .entityModule.pin,
                                                                           pkcs11.entityModule.pinLen);
                        if (pkcs11.entityModule.deviceId < KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to initialize entity token: %s (%d)",
                                          kritis3m_pki_error_message(pkcs11.entityModule.deviceId),
                                          pkcs11.entityModule.deviceId);

                        /* Set the external reference */
                        ret = privateKey_setExternalRef(entityKey, pkcs11.entityModule.deviceId, label);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to set external reference for entity key: %s "
                                          "(%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);

                        /* Check if an alternative key label is also present */
                        label = strtok(NULL, PKCS11_LABEL_TERMINATOR);
                        if ((label != NULL) &&
                            (strncmp(label, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0))
                        {
                                label += PKCS11_LABEL_IDENTIFIER_LEN;
                                LOG_INFO("Referencing external entity alt key with label \"%s\"",
                                         label);

                                /* Set the external reference */
                                ret = privateKey_setAltExternalRef(entityKey,
                                                                   pkcs11.entityModule.deviceId,
                                                                   label);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to set external reference for entity alt "
                                                  "key: %s (%d)",
                                                  kritis3m_pki_error_message(ret),
                                                  ret);
                        }
                }
                else
                {
                        /* Load key */
                        ret = privateKey_loadKeyFromBuffer(entityKey, buffer, bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to parse entity key: %s (%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);
                }

                RESET_BUFFER();

                /* Load an alternative entity key */
                if (paths.entityAltKeyPath != NULL)
                {
                        /* Check if we have to read a file */
                        if (strncmp(paths.entityAltKeyPath,
                                    PKCS11_LABEL_IDENTIFIER,
                                    PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                        {
                                /* Duplicate string */
                                buffer = (uint8_t*) duplicate_string(paths.entityAltKeyPath);
                                if (buffer == NULL)
                                        ERROR_OUT("unable to duplicate PKCS#11 label");
                        }
                        else
                        {
                                LOG_INFO("Loading entity alternative key from \"%s\"",
                                         paths.entityAltKeyPath);

                                /* Read file */
                                ret = read_file(paths.entityAltKeyPath, &buffer, &bytesInBuffer);
                                if (ret < 0)
                                        ERROR_OUT("unable to read entity alt key file from \"%s\"",
                                                  paths.entityAltKeyPath);
                        }

                        /* Check if an external alternative private key should be used */
                        if (strncmp((char*) buffer,
                                    PKCS11_LABEL_IDENTIFIER,
                                    PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                        {
                                char* label = strtok((char*) buffer, PKCS11_LABEL_TERMINATOR);
                                label += PKCS11_LABEL_IDENTIFIER_LEN;

                                LOG_INFO("Referencing external entity alt key with label \"%s\"",
                                         label);

                                /* Check if the token is not yet initialized */
                                if (pkcs11.entityModule.deviceId < 0)
                                {
                                        /* Initialize the related PKCS#11 token */
                                        pkcs11.entityModule
                                                .deviceId = kritis3m_pki_init_entity_token(pkcs11.entityModule
                                                                                                   .path,
                                                                                           pkcs11.entityModule
                                                                                                   .slot,
                                                                                           (uint8_t const*) pkcs11
                                                                                                   .entityModule
                                                                                                   .pin,
                                                                                           pkcs11.entityModule
                                                                                                   .pinLen);
                                        if (pkcs11.entityModule.deviceId < KRITIS3M_PKI_SUCCESS)
                                                ERROR_OUT("unable to initialize entity token: %s "
                                                          "(%d)",
                                                          kritis3m_pki_error_message(
                                                                  pkcs11.entityModule.deviceId),
                                                          pkcs11.entityModule.deviceId);
                                }

                                /* Set the external reference */
                                ret = privateKey_setAltExternalRef(entityKey,
                                                                   pkcs11.entityModule.deviceId,
                                                                   label);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to set external reference for entity alt "
                                                  "key: %s (%d)",
                                                  kritis3m_pki_error_message(ret),
                                                  ret);
                        }
                        else
                        {
                                /* Load key */
                                ret = privateKey_loadAltKeyFromBuffer(entityKey, buffer, bytesInBuffer);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to parse entity alt key: %s (%d)",
                                                  kritis3m_pki_error_message(ret),
                                                  ret);
                        }

                        RESET_BUFFER();
                }
        }

        /* Check if we want to generate a new key */
        if (gen_info.keyGenAlg != NULL)
        {
                LOG_INFO("Generating a new %s key", gen_info.keyGenAlg);

                /* Generate the key */
                ret = privateKey_generateKey(entityKey, gen_info.keyGenAlg);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to generate key: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Write the key to file if requested */
                if (paths.entityKeyOutputPath != NULL)
                {
                        LOG_INFO("Writing key to \"%s\"", paths.entityKeyOutputPath);

                        /* Allocate memory */
                        bytesInBuffer = outputBufferSize;
                        buffer = (uint8_t*) malloc(outputBufferSize);
                        if (buffer == NULL)
                                ERROR_OUT("unable to allocate output buffer");

                        /* Export PEM key */
                        ret = privateKey_writeKeyToBuffer(entityKey, buffer, &bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to write key to buffer: %s (%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);

                        ret = write_file(paths.entityKeyOutputPath, buffer, bytesInBuffer, false);
                        if (ret < 0)
                                ERROR_OUT("unable to write key to \"%s\"", paths.entityKeyOutputPath);

                        RESET_BUFFER();
                }
                else
                {
                        if (paths.entityKeyPath == NULL)
                        {
                                ERROR_OUT("No key output path specified and no external key "
                                          "referenced. The new key is lost, aborting.");
                        }
                }
        }
        /* Check if we need an alternative key */
        if (gen_info.altKeyGenAlg != NULL)
        {
                LOG_INFO("Generating a new %s entity key", gen_info.altKeyGenAlg);

                /* Generate the key */
                ret = privateKey_generateAltKey(entityKey, gen_info.altKeyGenAlg);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to generate alt key: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                /* Write the key to file if requested */
                if ((paths.entityAltKeyOutputPath != NULL) || (paths.entityKeyOutputPath != NULL))
                {
                        /* Allocate memory */
                        bytesInBuffer = outputBufferSize;
                        buffer = (uint8_t*) malloc(outputBufferSize);
                        if (buffer == NULL)
                                ERROR_OUT("unable to allocate output buffer");

                        /* Export PEM key */
                        ret = privateKey_writeAltKeyToBuffer(entityKey, buffer, &bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to write alt key to buffer: %s (%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);

                        if (paths.entityAltKeyOutputPath != NULL)
                        {
                                LOG_INFO("Writing alt key to \"%s\"", paths.entityAltKeyOutputPath);

                                ret = write_file(paths.entityAltKeyOutputPath, buffer, bytesInBuffer, false);
                                if (ret < 0)
                                        ERROR_OUT("unable to write alt key to \"%s\"",
                                                  paths.entityAltKeyOutputPath);
                        }
                        if (paths.entityKeyOutputPath != NULL)
                        {
                                LOG_INFO("Appending alt key to \"%s\"", paths.entityKeyOutputPath);

                                ret = write_file(paths.entityKeyOutputPath, buffer, bytesInBuffer, true);
                                if (ret < 0)
                                        ERROR_OUT("unable to write alt key to \"%s\"",
                                                  paths.entityKeyOutputPath);
                        }

                        RESET_BUFFER();
                }
        }

        /* Load the issuer key */
        issuerKey = privateKey_new();
        if (issuerKey == NULL)
                ERROR_OUT("unable to allocate memory for issuer key");

        if (paths.issuerKeyPath != NULL)
        {
                /* Check if we have to read a file */
                if (strncmp(paths.issuerKeyPath, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) ==
                    0)
                {
                        /* Duplicate string */
                        buffer = (uint8_t*) duplicate_string(paths.issuerKeyPath);
                        if (buffer == NULL)
                                ERROR_OUT("unable to duplicate PKCS#11 label");
                }
                else
                {
                        LOG_INFO("Loading issuer key from \"%s\"", paths.issuerKeyPath);

                        /* Read file */
                        ret = read_file(paths.issuerKeyPath, &buffer, &bytesInBuffer);
                        if (ret < 0)
                                ERROR_OUT("unable to read issuer key file from \"%s\"",
                                          paths.issuerKeyPath);
                }

                /* Check if an external private key should be used */
                if (strncmp((char*) buffer, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        char* label = strtok((char*) buffer, PKCS11_LABEL_TERMINATOR);
                        label += PKCS11_LABEL_IDENTIFIER_LEN;

                        LOG_INFO("Referencing external issuer key with label \"%s\"", label);

                        /* Initialize the related PKCS#11 token */
                        pkcs11.issuerModule
                                .deviceId = kritis3m_pki_init_issuer_token(pkcs11.issuerModule.path,
                                                                           pkcs11.issuerModule.slot,
                                                                           (uint8_t const*) pkcs11
                                                                                   .issuerModule.pin,
                                                                           pkcs11.issuerModule.pinLen);
                        if (pkcs11.issuerModule.deviceId < KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to initialize issuer token: %s (%d)",
                                          kritis3m_pki_error_message(pkcs11.issuerModule.deviceId),
                                          pkcs11.issuerModule.deviceId);

                        /* Set the external reference */
                        ret = privateKey_setExternalRef(issuerKey, pkcs11.issuerModule.deviceId, label);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to set external reference for issuer key: %s "
                                          "(%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);

                        /* Check if an alternative key label is also present */
                        label = strtok(NULL, PKCS11_LABEL_TERMINATOR);
                        if ((label != NULL) &&
                            (strncmp(label, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0))
                        {
                                label += PKCS11_LABEL_IDENTIFIER_LEN;
                                LOG_INFO("Referencing external issuer alt key with label \"%s\"",
                                         label);

                                /* Set the external reference */
                                ret = privateKey_setAltExternalRef(issuerKey,
                                                                   pkcs11.issuerModule.deviceId,
                                                                   label);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to set external reference for issuer alt "
                                                  "key: %s (%d)",
                                                  kritis3m_pki_error_message(ret),
                                                  ret);
                        }
                }
                else
                {
                        /* Load key */
                        ret = privateKey_loadKeyFromBuffer(issuerKey, buffer, bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to parse issuer key: %s (%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);
                }

                RESET_BUFFER();

                /* Load an alternative issuer key */
                if (paths.issuerAltKeyPath != NULL)
                {
                        /* Check if we have to read a file */
                        if (strncmp(paths.issuerAltKeyPath,
                                    PKCS11_LABEL_IDENTIFIER,
                                    PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                        {
                                /* Duplicate string */
                                buffer = (uint8_t*) duplicate_string(paths.issuerAltKeyPath);
                                if (buffer == NULL)
                                        ERROR_OUT("unable to duplicate PKCS#11 label");
                        }
                        else
                        {
                                LOG_INFO("Loading alternative issuer key from \"%s\"",
                                         paths.issuerAltKeyPath);

                                /* Read file */
                                ret = read_file(paths.issuerAltKeyPath, &buffer, &bytesInBuffer);
                                if (ret < 0)
                                        ERROR_OUT("unable to read issuer alt key file from \"%s\"",
                                                  paths.issuerAltKeyPath);
                        }

                        /* Check if an external alternative private key should be used */
                        if (strncmp((char*) buffer,
                                    PKCS11_LABEL_IDENTIFIER,
                                    PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                        {
                                char* label = strtok((char*) buffer, PKCS11_LABEL_TERMINATOR);
                                label += PKCS11_LABEL_IDENTIFIER_LEN;

                                LOG_INFO("Referencing external issuer alt key with label \"%s\"",
                                         label);

                                /* Check if the token is not yet initialized */
                                if (pkcs11.issuerModule.deviceId < 0)
                                {
                                        /* Initialize the related PKCS#11 token */
                                        pkcs11.issuerModule
                                                .deviceId = kritis3m_pki_init_issuer_token(pkcs11.issuerModule
                                                                                                   .path,
                                                                                           pkcs11.issuerModule
                                                                                                   .slot,
                                                                                           (uint8_t const*) pkcs11
                                                                                                   .issuerModule
                                                                                                   .pin,
                                                                                           pkcs11.issuerModule
                                                                                                   .pinLen);
                                        if (pkcs11.issuerModule.deviceId < KRITIS3M_PKI_SUCCESS)
                                                ERROR_OUT("unable to initialize issuer token: %s "
                                                          "(%d)",
                                                          kritis3m_pki_error_message(
                                                                  pkcs11.issuerModule.deviceId),
                                                          pkcs11.issuerModule.deviceId);
                                }

                                /* Set the external reference */
                                ret = privateKey_setAltExternalRef(issuerKey,
                                                                   pkcs11.issuerModule.deviceId,
                                                                   label);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to set external reference for issuer alt "
                                                  "key: %s (%d)",
                                                  kritis3m_pki_error_message(ret),
                                                  ret);
                        }
                        else
                        {
                                /* Load key */
                                ret = privateKey_loadAltKeyFromBuffer(issuerKey, buffer, bytesInBuffer);
                                if (ret != KRITIS3M_PKI_SUCCESS)
                                        ERROR_OUT("unable to parse issuer alt key: %s (%d)",
                                                  kritis3m_pki_error_message(ret),
                                                  ret);
                        }

                        RESET_BUFFER();
                }
        }
        else if (gen_info.selfSignCert)
        {
                LOG_INFO("Generating a new self-signed certificate");

                /* Copy the entitiyKey to the issuerKey */
                ret = privateKey_copyKey(issuerKey, entityKey);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to copy entity key to issuer key: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);
        }

        /* Load the issuer certificate */
        if (paths.issuerCertPath != NULL)
        {
                LOG_INFO("Loading issuer cert from \"%s\"", paths.issuerCertPath);

                issuerCert = inputCert_new();
                if (issuerCert == NULL)
                        ERROR_OUT("unable to allocate memory for issuer cert");

                /* Read file */
                ret = read_file(paths.issuerCertPath, &buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read issuer cert file from \"%s\"", paths.issuerCertPath);

                /* Load cert */
                ret = inputCert_initFromBuffer(issuerCert, buffer, bytesInBuffer, issuerKey);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse issuer cert: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                RESET_BUFFER();
        }

        /* Check if we have to generate a new CSR of if the user provided one */
        if ((paths.csrInputPath == NULL) &&
            ((paths.certOutputFilePath != NULL) || (paths.csrOutputFilePath != NULL)))
        {
                LOG_INFO("Generating a new CSR");

                /* We have to create a new CSR */
                request = signingRequest_new();

                /* Create the CSR */
                ret = signingRequest_init(request, &metadata.certMetadata);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to create CSR: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Allocate memory */
                bytesInBuffer = outputBufferSize;
                buffer = (uint8_t*) malloc(outputBufferSize);
                if (buffer == NULL)
                        ERROR_OUT("unable to allocate output buffer");

                /* Finalize the CSR */
                ret = signingRequest_finalize(request, entityKey, buffer, &bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to finalize CSR: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Write the CSR to file if requested */
                if (paths.csrOutputFilePath != NULL)
                {
                        LOG_INFO("Writing CSR to \"%s\"", paths.csrOutputFilePath);

                        ret = write_file(paths.csrOutputFilePath, buffer, bytesInBuffer, false);
                        if (ret < 0)
                                ERROR_OUT("unable to write CSR to \"%s\"", paths.csrOutputFilePath);
                }
        }
        else if (paths.csrInputPath != NULL)
        {
                LOG_INFO("Loading CSR from \"%s\"", paths.csrInputPath);

                /* Load the existing CSR */
                ret = read_file(paths.csrInputPath, &buffer, &bytesInBuffer);
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

                RESET_BUFFER();

                /* Set the issuer data */
                ret = outputCert_setIssuerData(outputCert, issuerCert, issuerKey);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to set issuer data: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                /* Set the validity period */
                outputCert_setValidity(outputCert, metadata.validity);

                if (metadata.enableCA)
                {
                        LOG_INFO("Certificate is a CA cert");

                        /* Cert is a CA certificate */
                        ret = outputCert_configureAsCA(outputCert);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to configure new cert as CA: %s (%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);
                }
                else if (metadata.humanCert)
                {
                        LOG_INFO("Certificate is a human entity cert");

                        /* Cert is a human entity certificate */
                        ret = outputCert_configureAsHumanEntity(outputCert);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to configure new cert as human entity: %s (%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);
                }
                else
                {
                        LOG_INFO("Certificate is a machine entity cert");

                        /* Cert is a machine entity certificate */
                        ret = outputCert_configureAsMachineEntity(outputCert);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to configure new cert as machine entity: %s (%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);
                }

                /* Allocate memory */
                bytesInBuffer = outputBufferSize;
                buffer = (uint8_t*) malloc(outputBufferSize);
                if (buffer == NULL)
                        ERROR_OUT("unable to allocate output buffer");

                /* Finalize the certificate. */
                ret = outputCert_finalize(outputCert, issuerKey, buffer, &bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to finalize new cert: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                LOG_INFO("Writing certificate to \"%s\"", paths.certOutputFilePath);

                /* Write the new cert to file */
                ret = write_file(paths.certOutputFilePath, buffer, bytesInBuffer, false);
                if (ret < 0)
                        ERROR_OUT("unable to write output cert to \"%s\"", paths.certOutputFilePath);

                RESET_BUFFER();
        }

        ret = KRITIS3M_PKI_SUCCESS;

exit:
        kritis3m_pki_close_entity_token();
        kritis3m_pki_close_issuer_token();

        privateKey_free(issuerKey);
        privateKey_free(entityKey);

        inputCert_free(issuerCert);

        signingRequest_free(request);

        outputCert_free(outputCert);

        if (buffer != NULL)
                free(buffer);

        kritis3m_pki_shutdown();

        return ret;
}
