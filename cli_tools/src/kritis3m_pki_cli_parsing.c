#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>

#include "logging.h"

#include "kritis3m_pki_cli_parsing.h"

LOG_MODULE_CREATE(cli_parsing);


static const struct option cli_options[] =
{
        { "issuer_key",         required_argument, 0, 0x01 },
        { "issuer_alt_key",     required_argument, 0, 0x02 },
        { "issuer_cert",        required_argument, 0, 0x03 },
        { "entity_key",         required_argument, 0, 0x04 },
        { "entity_alt_key",     required_argument, 0, 0x05 },
        { "cert_out",           required_argument, 0, 0x06 },
        { "CA_cert",            no_argument,       0, 0x07 },
        { "common_name",        required_argument, 0, 0x08 },
        { "org",                required_argument, 0, 0x09 },
        { "unit",               required_argument, 0, 0x0A },
        { "validity",           required_argument, 0, 0x0B },
        { "alt_names_DNS",      required_argument, 0, 0x0C },
        { "alt_names_URI",      required_argument, 0, 0x0D },
        { "alt_names_IP",       required_argument, 0, 0x0E },
        { "csr_in",             required_argument, 0, 0x0F },
        { "csr_out",            required_argument, 0, 0x10 },
        { "gen_key",            required_argument, 0, 0x11 },
        { "gen_alt_key",        required_argument, 0, 0x12 },
        { "key_out",            required_argument, 0, 0x13 },
        { "alt_key_out",        required_argument, 0, 0x14 },
        { "middleware",         required_argument, 0, 0x15 },
        { "slot_issuer_key",    required_argument, 0, 0x16 },
        { "slot_entity_key",    required_argument, 0, 0x17 },
        { "self_signed_cert",   no_argument,       0, 0x18 },
        { "verbose",            no_argument,       0, 'v'  },
        { "debug",              no_argument,       0, 'd'  },
        { "help",               no_argument,       0, 'h'  },
        { NULL, 0, NULL, 0}
};


static void set_defaults(application_config* app_config, pki_paths* paths, pki_generation_info* generation_info,
                         pki_metadata* metadata, pki_secure_element* secure_element);
static void print_help(char const* name);


/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config, pki_paths* paths, pki_generation_info* generation_info,
                        pki_metadata* metadata, pki_secure_element* secure_element, size_t argc, char** argv)
{
        if ((app_config == NULL) || (paths == NULL) || (generation_info == NULL) ||
            (metadata == NULL) || (secure_element == NULL))
        {
                LOG_ERROR("mandatory argument missing for parse_cli_arguments()");
                return -1;
        }
        else if (argc < 2)
        {
                print_help(argv[0]);
                return 1;
        }

        /* Set default values */
        set_defaults(app_config, paths, generation_info, metadata, secure_element);

        /* Parse CLI args */
        int index = 0;
        while (true)
        {
                int result = getopt_long(argc, argv, "vdh", cli_options, &index);

                if (result == -1)
                        break; /* end of list */

                switch (result)
                {
                        case 0x01: /* issuer_key */
                                paths->issuerKeyPath = optarg;
                                break;
                        case 0x02: /* issuer_alt_key */
                                paths->issuerAltKeyPath = optarg;
                                break;
                        case 0x03: /* issuer_cert */
                                paths->issuerCertPath = optarg;
                                break;
                        case 0x04: /* entity_key */
                                paths->entityKeyPath = optarg;
                                break;
                        case 0x05: /* entity_alt_key */
                                paths->entityAltKeyPath = optarg;
                                break;
                        case 0x06: /* cert_out */
                                paths->certOutputFilePath = optarg;
                                break;
                        case 0x07: /* CA_cert */
                                metadata->enableCA = true;
                                break;
                        case 0x08: /* common_name */
                                metadata->certMetadata.commonName = optarg;
                                break;
                        case 0x09: /* org */
                                metadata->certMetadata.org = optarg;
                                break;
                        case 0x0A: /* unit */
                                metadata->certMetadata.unit = optarg;
                                break;
                        case 0x0B: /* validity */
                                metadata->validity = strtol(optarg, NULL, 10);
                                break;
                        case 0x0C: /* alt_names_DNS */
                                metadata->certMetadata.altNamesDNS = optarg;
                                break;
                        case 0x0D: /* alt_names_URI */
                                metadata->certMetadata.altNamesURI = optarg;
                                break;
                        case 0x0E: /* alt_names_IP */
                                metadata->certMetadata.altNamesIP = optarg;
                                break;
                        case 0x0F: /* csr_in */
                                paths->csrInputPath = optarg;
                                break;
                        case 0x10: /* csr_out */
                                paths->csrOutputFilePath = optarg;
                                break;
                        case 0x11: /* gen_key */
                                generation_info->keyGenAlg = optarg;
                                break;
                        case 0x12: /* gen_alt_key */
                                generation_info->altKeyGenAlg = optarg;
                                break;
                        case 0x13: /* key_out */
                                paths->entityKeyOutputPath = optarg;
                                break;
                        case 0x14: /* alt_key_out */
                                paths->entityAltKeyOutputPath = optarg;
                                break;
                        case 0x15: /* middleware */
                                secure_element->middlewarePath = optarg;
                                break;
                        case 0x16: /* slot_issuer_key */
                                secure_element->slotIssuerKey = strtol(optarg, NULL, 10);
                                break;
                        case 0x17: /* slot_entity_key */
                                secure_element->slotEntityKey = strtol(optarg, NULL, 10);
                                break;
                        case 0x18: /* self_signed_cert */
                                generation_info->selfSignCert = true;
                                break;
                        case 'v':
                                app_config->log_level = LOG_LVL_INFO;
                                LOG_LVL_SET(LOG_LVL_INFO);
                                break;
                        case 'd':
                                app_config->log_level = LOG_LVL_DEBUG;
                                LOG_LVL_SET(LOG_LVL_DEBUG);
                                break;
                        case 'h':
                                print_help(argv[0]);
                                exit(0);
                                break;
                        default:
                                fprintf(stderr, "unknown option: %c\n", result);
                                print_help(argv[0]);
                                exit(-1);
                }
        }

        return 0;
}


static void set_defaults(application_config* app_config, pki_paths* paths, pki_generation_info* generation_info,
                         pki_metadata* metadata, pki_secure_element* secure_element)
{
        /* Application config */
        app_config->log_level = LOG_LVL_WARN;

        /* Paths */
        paths->issuerKeyPath = NULL;
        paths->issuerAltKeyPath = NULL;
        paths->issuerCertPath = NULL;
        paths->entityKeyPath = NULL;
        paths->entityAltKeyPath = NULL;
        paths->entityKeyOutputPath = NULL;
        paths->entityAltKeyOutputPath = NULL;
        paths->certOutputFilePath = NULL;
        paths->csrOutputFilePath = NULL;
        paths->csrInputPath = NULL;

        /* Generation information */
        generation_info->keyGenAlg = NULL;
        generation_info->altKeyGenAlg = NULL;
        generation_info->selfSignCert = false;

        /* Metadata */
        metadata->enableCA = false;
        metadata->certMetadata.commonName = NULL;
        metadata->certMetadata.org = NULL;
        metadata->certMetadata.unit = NULL;
        metadata->certMetadata.altNamesDNS = NULL;
        metadata->certMetadata.altNamesURI = NULL;
        metadata->certMetadata.altNamesIP = NULL;
        metadata->validity = 365;

        /* Secure Element */
        secure_element->middlewarePath = NULL;
        secure_element->slotIssuerKey = -1;
        secure_element->issuerTokenDeviceId = -1;
        secure_element->slotEntityKey = -1;
        secure_element->entityTokenDeviceId = -1;
}


static void print_help(char const* name)
{
        printf("Usage: %s [OPTIONS]\n", name);
        printf("\nKey input:\n");
        printf("  --issuer_key <file>           Path to the primary issuer key in PEM format\n");
        printf("  --issuer_alt_key <file>       Path to the alternative issuer key in PEM format (generate hybrid cert)\n");
        printf("  --entity_key <file>           Path to the primary entity key in PEM format (same as issuerKey for self-signed cert)\n");
        printf("  --entity_alt_key <file>       Path to the alternative entity key in PEM format (same as issuerAltKey for self-signed cert)\n");

        printf("\nCertificate/CSR input:\n");
        printf("  --issuer_cert <file>          Path to the issuer certificate in PEM format\n");
        printf("  --csr_in <file>               Path to a CSR in PEM format\n");

        printf("\nKey generation:\n");
        printf("  Currently supported algorithms: rsa2048, rsa3072, rsa4096\n");
        printf("                                  secp256, secp384, secp521\n");
        printf("                                  ed25519, ed448\n");
        printf("                                  mldsa44, mldsa65, mldsa87\n");
        printf("  --gen_key <alogrithm>         Algorithm for key generation (see list above)\n");
        printf("  --gen_alt_key <alogrithm>     Algorithm for alternative key generation (see list above)\n");

        printf("\nOutput:\n");
        printf("  --cert_out <file>             Path to the root certificate output file (PEM)\n");
        printf("  --csr_out <file>              Path to the CSR output file (PEM)\n");
        printf("  --key_out <file>              Path to the primary key output file (PEM)\n");
        printf("  --alt_key_out <file>          Path to the alternative key output file (PEM)\n");

        printf("\nMetadata:\n");
        printf("  --common_name <string>        Common Name (CN) for the certificate/CSR\n");
        printf("  --org <string>                Organization (O) for the certificate/CSR\n");
        printf("  --unit <string>               Organizational Unit (OU) for the certificate/CSR\n");
        printf("  --alt_names_DNS <string>      SAN DNS entries for the certificate/CSR (separated by ; and wrappend in \")\n");
        printf("  --alt_names_URI <string>      SAN URI entries for the certificate/CSR (separated by ; and wrappend in \")\n");
        printf("  --alt_names_IP <string>       SAN IP address entries for the certificate/CSR (separated by ; and wrappend in \")\n");
        printf("  --validity <days>             Validity period in days (default: 365)\n");
        printf("  --CA_cert                     Create a cert that can sign new certs (deafault is entity cert/CSR)\n");
        printf("  --self_signed_cert            Create a self-signed certificate (default: false)\n");

        printf("\nSecure Element:\n");
        printf("  When using a secure element for key storage, you have to supply the PKCS#11 key labels using the arguments\n");
        printf("  \"--issuerKey\", \"--issuerAltKey\", \"--entityKey\" and \"--entityAltKey\" prepending the string\n");
        printf("  \"%s\" followed by the key label.\n", PKCS11_LABEL_IDENTIFIER);
        printf("  --middleware <file>           Path to the secure element middleware\r\n");
        printf("  --slot_issuer_key <id>        Slot id of the secure element containing the issuer keys (default is first available)\r\n");
        printf("  --slot_entity_key <id>        Slot id of the secure element containing the entity keys (default is first available)\r\n");

        printf("\nGeneral:\n");
        printf("  --verbose                     Enable verbose output\n");
        printf("  --debug                       Enable debug output\n");
        printf("  --help                        Print this help\n");
}

