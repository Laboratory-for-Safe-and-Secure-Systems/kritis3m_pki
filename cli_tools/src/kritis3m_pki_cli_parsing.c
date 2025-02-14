#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logging.h"

#include "kritis3m_pki_cli_parsing.h"

LOG_MODULE_CREATE(cli_parsing);

static const struct option cli_options[] = {
        {"issuer_key", required_argument, 0, 0x01},
        {"issuer_alt_key", required_argument, 0, 0x02},
        {"issuer_cert", required_argument, 0, 0x03},
        {"entity_key", required_argument, 0, 0x04},
        {"entity_alt_key", required_argument, 0, 0x05},
        {"cert_out", required_argument, 0, 0x06},
        {"CA_cert", no_argument, 0, 0x07},
        {"common_name", required_argument, 0, 0x08},
        {"org", required_argument, 0, 0x09},
        {"unit", required_argument, 0, 0x0A},
        {"validity", required_argument, 0, 0x0B},
        {"alt_names_DNS", required_argument, 0, 0x0C},
        {"alt_names_URI", required_argument, 0, 0x0D},
        {"alt_names_IP", required_argument, 0, 0x0E},
        {"csr_in", required_argument, 0, 0x0F},
        {"csr_out", required_argument, 0, 0x10},
        {"gen_key", required_argument, 0, 0x11},
        {"gen_alt_key", required_argument, 0, 0x12},
        {"key_out", required_argument, 0, 0x13},
        {"alt_key_out", required_argument, 0, 0x14},
        {"p11_issuer_module", required_argument, 0, 0x15},
        {"p11_issuer_slot", required_argument, 0, 0x16},
        {"p11_issuer_pin", required_argument, 0, 0x17},
        {"p11_entity_module", required_argument, 0, 0x18},
        {"p11_entity_slot", required_argument, 0, 0x19},
        {"p11_entity_pin", required_argument, 0, 0x1A},
        {"self_signed_cert", no_argument, 0, 0x1B},
        {"country", required_argument, 0, 0x1C},
        {"state", required_argument, 0, 0x1D},
        {"email", required_argument, 0, 0x1E},
        {"alt_names_email", required_argument, 0, 0x1F},
        {"human_cert", no_argument, 0, 0x20},
        {"verbose", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {NULL, 0, NULL, 0},
};

static void set_defaults(application_config* app_config,
                         pki_paths* paths,
                         pki_generation_info* generation_info,
                         pki_metadata* metadata,
                         pki_pkcs11* pkcs11);
static void print_help(char const* name);

/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config,
                        pki_paths* paths,
                        pki_generation_info* generation_info,
                        pki_metadata* metadata,
                        pki_pkcs11* pkcs11,
                        size_t argc,
                        char** argv)
{
        if ((app_config == NULL) || (paths == NULL) || (generation_info == NULL) ||
            (metadata == NULL) || (pkcs11 == NULL))
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
        set_defaults(app_config, paths, generation_info, metadata, pkcs11);

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
                case 0x15: /* p11_issuer_module */
                        pkcs11->issuerModule.path = optarg;
                        break;
                case 0x16: /* p11_issuer_slot */
                        pkcs11->issuerModule.slot = strtol(optarg, NULL, 10);
                        break;
                case 0x17: /* p11_issuer_pin */
                        pkcs11->issuerModule.pin = optarg;
                        pkcs11->issuerModule.pinLen = strlen(optarg);
                        break;
                case 0x18: /* p11_entity_module */
                        pkcs11->entityModule.path = optarg;
                        break;
                case 0x19: /* p11_entity_slot */
                        pkcs11->entityModule.slot = strtol(optarg, NULL, 10);
                        break;
                case 0x1A: /* p11_entity_pin */
                        pkcs11->entityModule.pin = optarg;
                        pkcs11->entityModule.pinLen = strlen(optarg);
                        break;
                case 0x1B: /* self_signed_cert */
                        generation_info->selfSignCert = true;
                        break;
                case 0x1C: /* country */
                        metadata->certMetadata.country = optarg;
                        break;
                case 0x1D: /* state */
                        metadata->certMetadata.state = optarg;
                        break;
                case 0x1E: /* email */
                        metadata->certMetadata.email = optarg;
                        break;
                case 0x1F: /* alt_names_email */
                        metadata->certMetadata.altNamesEmail = optarg;
                        break;
                case 0x20: /* human_cert */
                        metadata->humanCert = true;
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

static void set_defaults(application_config* app_config,
                         pki_paths* paths,
                         pki_generation_info* generation_info,
                         pki_metadata* metadata,
                         pki_pkcs11* pkcs11)
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
        metadata->humanCert = false;
        metadata->certMetadata.commonName = NULL;
        metadata->certMetadata.country = NULL;
        metadata->certMetadata.state = NULL;
        metadata->certMetadata.org = NULL;
        metadata->certMetadata.unit = NULL;
        metadata->certMetadata.email = NULL;
        metadata->certMetadata.altNamesDNS = NULL;
        metadata->certMetadata.altNamesURI = NULL;
        metadata->certMetadata.altNamesIP = NULL;
        metadata->certMetadata.altNamesEmail = NULL;
        metadata->validity = 365;

        /* PKCS#11 */
        pkcs11->issuerModule.path = NULL;
        pkcs11->issuerModule.slot = -1;
        pkcs11->issuerModule.pin = NULL;
        pkcs11->issuerModule.pinLen = 0;
        pkcs11->issuerModule.deviceId = -1;

        pkcs11->entityModule.path = NULL;
        pkcs11->entityModule.slot = -1;
        pkcs11->entityModule.pin = NULL;
        pkcs11->entityModule.pinLen = 0;
        pkcs11->entityModule.deviceId = -1;
}

static void print_help(char const* name)
{
        /* clang-format off */
        printf("Usage: %s [OPTIONS]\n", name);
        printf("\nKey input:\n");
        printf("  --issuer_key <file>         Path to the primary issuer key (PEM)\n");
        printf("  --issuer_alt_key <file>     Path to the alternative issuer key (PEM; generate hybrid cert)\n");
        printf("  --entity_key <file>         Path to the primary entity key (PEM; same as issuer_key for self-signed cert)\n");
        printf("  --entity_alt_key <file>     Path to the alternative entity key (PEM; same as issuer_alt_key for self-signed cert)\n");

        printf("\nCertificate/CSR input:\n");
        printf("  --issuer_cert <file>        Path to the issuer certificate (PEM)\n");
        printf("  --csr_in <file>             Path to a CSR (PEM)\n");

        printf("\nKey generation:\n");
        printf("  Currently supported algorithms: rsa2048, rsa3072, rsa4096\n");
        printf("                                  secp256, secp384, secp521\n");
        printf("                                  ed25519, ed448\n");
        printf("                                  mldsa44, mldsa65, mldsa87\n");
        printf("                                  falcon512, falcon1024\n");
        printf("  --gen_key <alogrithm>       Algorithm for key generation (see list above)\n");
        printf("  --gen_alt_key <alogrithm>   Algorithm for alternative key generation (see list above)\n");

        printf("\nOutput:\n");
        printf("  --cert_out <file>           Path to the root certificate output file (PEM)\n");
        printf("  --csr_out <file>            Path to the CSR output file (PEM)\n");
        printf("  --key_out <file>            Path to the primary key output file (PEM)\n");
        printf("  --alt_key_out <file>        Path to the alternative key output file (PEM)\n");

        printf("\nMetadata:\n");
        printf("  --common_name <string>      Common Name (CN) for the certificate/CSR\n");
        printf("  --country <string>          Country (C) for the certificate/CSR\n");
        printf("  --state <string>            State (ST) for the certificate/CSR\n");
        printf("  --org <string>              Organization (O) for the certificate/CSR\n");
        printf("  --unit <string>             Organizational Unit (OU) for the certificate/CSR\n");
        printf("  --email <string>            Email address for the user certificate/CSR\n");
        printf("  --alt_names_DNS <string>    SAN DNS entries for the certificate/CSR (separated by ; and wrappend in \")\n");
        printf("  --alt_names_URI <string>    SAN URI entries for the certificate/CSR (separated by ; and wrappend in \")\n");
        printf("  --alt_names_IP <string>     SAN IP entries for the certificate/CSR (separated by ; and wrappend in \")\n");
        printf("  --alt_names_email <string>  SAN Email entries for the certificate/CSR (separated by ; and wrappend in \")\n");
        printf("  --validity <days>           Validity period in days (default: 365)\n");
        printf("  --CA_cert                   Create a cert that can sign new certs (deafault is entity cert/CSR)\n");
        printf("  --self_signed_cert          Create a self-signed certificate (default: false)\n");
        printf("  --human_cert                Certificate identifies a human person instead of a machine (default: off)\n");

        printf("\nSecure Element:\n");
        printf("  When using a secure element for key storage, you have to supply the PKCS#11 key labels using the arguments\n");
        printf("  \"--issuerKey\", \"--issuerAltKey\", \"--entityKey\" and \"--entityAltKey\" prepending the string\n");
        printf("  \"%s\" followed by the key label.\n", PKCS11_LABEL_IDENTIFIER);
        printf("  You can specify different PKCS#11 modules for the issuer and entity keys. For each, an individual slot\n");
        printf("  number and User PIN can be specified. If no slot is given, the first available slot is used.\n");
        printf("  --p11_issuer_module <path>  Path to the PKCS#11 module containing the issuer key\r\n");
        printf("  --p11_issuer_slot <id>      Slot id of the PKCS#11 module for the issuer key\r\n");
        printf("  --p11_issuer_pin <pin>      PIN for the PKCS#11 module containing the issuer key\r\n");
        printf("  --p11_entity_module <path>  Path to the PKCS#11 module containing the entity key\r\n");
        printf("  --p11_entity_slot <id>      Slot id of the PKCS#11 module for the entity key\r\n");
        printf("  --p11_entity_pin <pin>      PIN for the PKCS#11 module containing the entity key\r\n");

        printf("\nGeneral:\n");
        printf("  --verbose                   Enable verbose output\n");
        printf("  --debug                     Enable debug output\n");
        printf("  --help                      Print this help\n");
        /* clang-format on */
}
