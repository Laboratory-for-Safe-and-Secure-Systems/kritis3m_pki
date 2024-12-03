#ifndef KRITIS3M_PKI_CLI_PARSING_H
#define KRITIS3M_PKI_CLI_PARSING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "kritis3m_pki_common.h"
#include "kritis3m_pki_client.h"



typedef struct
{
        int32_t log_level;
}
application_config;


typedef struct
{
        char const* issuerKeyPath;
        char const* issuerAltKeyPath;

        char const* issuerCertPath;

        char const* entityKeyPath;
        char const* entityAltKeyPath;

        char const* csrInputPath;

        char const* entityKeyOutputPath;
        char const* entityAltKeyOutputPath;

        char const* certOutputFilePath;
        char const* csrOutputFilePath;
}
pki_paths;


typedef struct
{
        char const* keyGenAlg;
        char const* altKeyGenAlg;

        bool selfSignCert;
}
pki_generation_info;


typedef struct
{
        bool enableCA;

        SigningRequestMetadata certMetadata;

        int validity;
}
pki_metadata;


typedef struct
{
        struct
        {
                char const* path;
                int slot;
                char const* pin;
                int pinLen;

                int deviceId;
        }
        issuerModule;

        struct
        {
                char const* path;
                int slot;
                char const* pin;
                int pinLen;

                int deviceId;
        }
        entityModule;
}
pki_pkcs11;


/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config, pki_paths* paths, pki_generation_info* generation_info,
                        pki_metadata* metadata, pki_pkcs11* pkcs11, size_t argc, char** argv);



#endif /* KRITIS3M_PKI_CLI_PARSING_H */
