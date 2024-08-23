#ifndef KRITIS3M_PKI_CLI_PARSING_H
#define KRITIS3M_PKI_CLI_PARSING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


#define PKCS11_LABEL_IDENTIFIER "pkcs11:"
#define PKCS11_LABEL_IDENTIFIER_LEN 7


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

        char const* commonName;
        char const* orgName;
        char const* orgUnit;
        char const* altNamesDNS;
        char const* altNamesURI;
        char const* altNamesIP;

        int validity;
}
pki_metadata;


typedef struct
{
        char const* middlewarePath;

        int slotIssuerKey;
        int issuerTokenDeviceId;

        int slotEntityKey;
        int entityTokenDeviceId;
}
pki_secure_element;


/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config, pki_paths* paths, pki_generation_info* generation_info,
                        pki_metadata* metadata, pki_secure_element* secure_element, size_t argc, char** argv);



#endif /* KRITIS3M_PKI_CLI_PARSING_H */
