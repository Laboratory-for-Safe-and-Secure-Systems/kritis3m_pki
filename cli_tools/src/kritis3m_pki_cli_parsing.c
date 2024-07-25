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
        { "issuerKey",          required_argument, 0, 'a' },
        { "issuerAltKey",       required_argument, 0, 'b' },
        { "issuerCert",         required_argument, 0, 'c' },
        { "entityKey",          required_argument, 0, 'd' },
        { "entityAltKey",       required_argument, 0, 'e' },
        { "certOut",            required_argument, 0, 'f' },
        { "enableCA",           no_argument,       0, 'g' },
        { "CN",                 required_argument, 0, 'i' },
        { "O",                  required_argument, 0, 'o' },
        { "OU",                 required_argument, 0, 'p' },
        { "validity",           required_argument, 0, 'j' },
        { "altName",            required_argument, 0, 'k' },
        { "csrIn",              required_argument, 0, 'l' },
        { "csrOut",             required_argument, 0, 'm' },
        { "genKey",             required_argument, 0, 'n' },
        { "genAltKey",          required_argument, 0, 'q' },
        { "keyOut",             required_argument, 0, 'r' },
        { "altKeyOut",          required_argument, 0, 's' },
        { "middleware",         required_argument, 0, 't' },
        { "slotIssuerKey",      required_argument, 0, 'u' },
        { "slotEntityKey",      required_argument, 0, 'w' },
        { "verbose",            no_argument,       0, 'v' },
        { "help",               no_argument,       0, 'h' },
        { NULL, 0, NULL, 0}
};


static void set_defaults(application_config* app_config, pki_paths* paths, pki_keygen_algorithm* keygen_algos,
                         pki_metadata* metadata, pki_secure_element* secure_element);
static void print_help(char const* name);


/* Parse the provided argv array and store the information in the provided config variables.
 *
 * Returns 0 on success, +1 in case the help was printed and -1 on failure (error is printed on console).
 */
int parse_cli_arguments(application_config* app_config, pki_paths* paths, pki_keygen_algorithm* keygen_algos,
                        pki_metadata* metadata, pki_secure_element* secure_element, size_t argc, char** argv)
{
        if ((app_config == NULL) || (paths == NULL) || (keygen_algos == NULL) ||
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
        set_defaults(app_config, paths, keygen_algos, metadata, secure_element);

        /* Parse CLI args */
        int index = 0;
        while (true)
        {
                int result = getopt_long(argc, argv, "a:b:c:d:e:f:gi:j:k:l:m:o:p:n:q:r:s:t:u:w:vh", cli_options, &index);

                if (result == -1)
                        break; /* end of list */

                switch (result)
                {
                        case 'a':
                                paths->issuerKeyPath = optarg;
                                break;
                        case 'b':
                                paths->issuerAltKeyPath = optarg;
                                break;
                        case 'c':
                                paths->issuerCertPath = optarg;
                                break;
                        case 'd':
                                paths->entityKeyPath = optarg;
                                break;
                        case 'e':
                                paths->entityAltKeyPath = optarg;
                                break;
                        case 'f':
                                paths->certOutputFilePath = optarg;
                                break;
                        case 'g':
                                metadata->enableCA = true;
                                break;
                        case 'i':
                                metadata->commonName = optarg;
                                break;
                        case 'o':
                                metadata->orgName = optarg;
                                break;
                        case 'p':
                                metadata->orgUnit = optarg;
                                break;
                        case 'j':
                                metadata->validity = strtol(optarg, NULL, 10);
                                break;
                        case 'k':
                                metadata->altName = optarg;
                                break;
                        case 'l':
                                paths->csrInputPath = optarg;
                                break;
                        case 'm':
                                paths->csrOutputFilePath = optarg;
                                break;
                        case 'n':
                                keygen_algos->keyAlg = optarg;
                                break;
                        case 'q':
                                keygen_algos->altKeyAlg = optarg;
                                break;
                        case 'r':
                                paths->entityKeyOutputPath = optarg;
                                break;
                        case 's':
                                paths->entityAltKeyOutputPath = optarg;
                                break;
                        case 't':
                                secure_element->middlewarePath = optarg;
                                break;
                        case 'u':
                                secure_element->slotIssuerKey = strtol(optarg, NULL, 10);
                                break;
                        case 'w':
                                secure_element->slotEntityKey = strtol(optarg, NULL, 10);
                                break;
                        case 'v':
                                app_config->log_level = LOG_LVL_INFO;
                                LOG_LVL_SET(LOG_LVL_INFO);
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


static void set_defaults(application_config* app_config, pki_paths* paths, pki_keygen_algorithm* keygen_algos,
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

        /* Algorithm type for key generation */
        keygen_algos->keyAlg = NULL;
        keygen_algos->altKeyAlg = NULL;

        /* Metadata */
        metadata->enableCA = false;
        metadata->commonName = NULL;
        metadata->orgName = NULL;
        metadata->orgUnit = NULL;
        metadata->altName = NULL;
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
        printf("Arguments:\n");
        printf("\nKey input:\n");
        printf("  --issuerKey <file>      Path to the primary issuer key in PEM format\n");
        printf("  --issuerAltKey <file>   Path to the alternative issuer key in PEM format (generate hybrid cert)\n");
        printf("  --entityKey <file>      Path to the primary entity key in PEM format (same as issuerKey for self-signed cert)\n");
        printf("  --entityAltKey <file>   Path to the alternative entity key in PEM format (same as issuerAltKey for self-signed cert)\n");

        printf("\nCertificate/CSR input:\n");
        printf("  --issuerCert <file>     Path to the issuer certificate in PEM format\n");
        printf("  --csrIn <file>          Path to a CSR in PEM format\n");

        printf("\nKey generation:\n");
        printf("  Currently supported algorithms: rsa2048, rsa3072, rsa4096, ecc256, ecc384, ecc521, mldsa44, mldsa65, mldsa87\n");
        printf("  --genKey <alogrithm>    Algorithm for key generation (see list below)\n");
        printf("  --genAltKey <alogrithm> Algorithm for alternative key generation (see list below)\n");

        printf("\nOutput:\n");
        printf("  --certOut <file>        Path to the root certificate output file (PEM)\n");
        printf("  --csrOut <file>         Path to the CSR output file (PEM)\n");
        printf("  --keyOut <file>         Path to the primary key output file (PEM)\n");
        printf("  --altKeyOut <file>      Path to the alternative key output file (PEM)\n");

        printf("\nMetadata:\n");
        printf("  --CN <string>           Common Name (CN) for the certificate/CSR\n");
        printf("  --O <string>            Organization (O) for the certificate/CSR\n");
        printf("  --OU <string>           Organizational Unit (OU) for the certificate/CSR\n");
        printf("  --altName <string>      Alternative name (SAN) for the certificate/CSR (only one supported atm)\n");
        printf("  --validity <days>       Validity period in days (default: 365)\n");
        printf("  --enableCA              Create a cert that can sign new certs (deafault is entity cert/CSR)\n");

        printf("\nSecure Element:\n");
        printf("  When using a secure element for key storage, you have to supply the PKCS#11 key labels using the arguments\n");
        printf("  \"--issuerKey\", \"--issuerAltKey\", \"--entityKey\" and \"--entityAltKey\" prepending the string\n");
        printf("  \"%s\" followed by the key label.\n", PKCS11_LABEL_IDENTIFIER);
        printf("  --middleware <file>     Path to the secure element middleware\r\n");
        printf("  --slotIssuerKey <id>    Slot id of the secure element containing the issuer keys (default is first available)\r\n");
        printf("  --slotEntityKey <id>    Slot id of the secure element containing the entity keys (default is first available)\r\n");

        printf("\nGeneral:\n");
        printf("  --verbose               Enable verbose output\n");
        printf("  --help                  Print this help\n");
}

