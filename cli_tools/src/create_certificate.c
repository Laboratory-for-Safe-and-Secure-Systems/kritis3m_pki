
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "cli_common.h"
#include "kritis3m_pki_client.h"
#include "kritis3m_pki_server.h"

#include "logging.h"


LOG_MODULE_CREATE(kritis3m_pki);

#define SUBJECT_COUNTRY "DE"
#define SUBJECT_STATE "Bayern"
#define SUBJECT_LOCALITY "Regensburg"
#define SUBJECT_ORG "LaS3"
#define SUBJECT_UNIT "KRITIS3M"
#define SUBJECT_EMAIL "las3@oth-regensburg.de"


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); ret = -1; goto exit; }


static const struct option cli_options[] =
{
        { "issuerKey",          required_argument, 0, 'a' },
        { "issuerAltKey",       required_argument, 0, 'b' },
        { "issuerCert",         required_argument, 0, 'c' },
        { "ownKey",             required_argument, 0, 'd' },
        { "ownAltKey",          required_argument, 0, 'e' },
        { "certOut",            required_argument, 0, 'f' },
        { "enableCA",           no_argument,       0, 'g' },
        { "CN",                 required_argument, 0, 'i' },
        { "O",                  required_argument, 0, 'o' },
        { "OU",                 required_argument, 0, 'p' },
        { "validity",           required_argument, 0, 'j' },
        { "altName",            required_argument, 0, 'k' },
        { "csrIn",              required_argument, 0, 'l' },
        { "csrOut",             required_argument, 0, 'm' },
        { "verbose",            no_argument,       0, 'v' },
        { "help",               no_argument,       0, 'h' },
        { NULL, 0, NULL, 0}
};


void print_help(char *prog_name)
{
        printf("Usage: %s [OPTIONS]\n", prog_name);
        printf("Arguments:\n");
        printf("\n  Key input:\n");
        printf("  --issuerKey <file>    Path to the primary issuer key in PEM format\n");
        printf("  --issuerAltKey <file> Path to the alternative issuer key in PEM format (generate hybrid cert)\n");
        printf("  --ownKey <file>       Path to the primary own key in PEM format (same as issuerKey for self-signed certificate)\n");
        printf("  --ownAltKey <file>    Path to the alternative own key in PEM format (same as issuerAltKey for self-signed certificate)\n");

        printf("\n  Certificate/CSR input:\n");
        printf("  --issuerCert <file>   Path to the issuer certificate in PEM format\n");
        printf("  --csrIn <file>        Path to a CSR in PEM format\n");

        printf("\n  Output:\n");
        printf("  --certOut <file>      Path to the root certificate output file (PEM)\n");
        printf("  --csrOut <file>       Path to the CSR output file (PEM)\n");

        printf("\n  Options:\n");
        printf("  --CN <string>         Common Name (CN) for the certificate/CSR\n");
        printf("  --O <string>          Organization (O) for the certificate/CSR\n");
        printf("  --OU <string>         Organizational Unit (OU) for the certificate/CSR\n");
        printf("  --altName <string>    Alternative name (SAN) for the certificate/CSR (only one supported at the moment)\n");
        printf("  --validity <days>     Validity period in days (default: 365)\n");
        printf("  --enableCA            Create a CA certificate that can sign new certificates (deafault is entity cert/CSR)\n\n");
        printf("  --verbose             Enable verbose output\n");
        printf("  --help                Print this help\n");
}


int main(int argc, char** argv)
{
        int ret = 0;
        int index = 0;

        char const* issuerKeyPath = NULL;
        char const* issuerAltKeyPath = NULL;
        char const* issuerCertPath = NULL;
        char const* ownKeyPath = NULL;
        char const* ownAltKeyPath = NULL;
        char const* certOutputFilePath = NULL;
        char const* csrOutputFilePath = NULL;
        char const* csrInputPath = NULL;

        bool enableCA = false;
        char const* commonName = NULL;
        char const* orgName = NULL;
        char const* orgUnit = NULL;
        char const* altName = NULL;
        int validity = 365;

        PrivateKey* issuerKey = NULL;
        IssuerCert* issuerCert = NULL;
        PrivateKey* ownKey = NULL;
        SigningRequest* request = NULL;
        OutputCert* outputCert = NULL;

        /* Parse CLI args */
        if (argc < 2)
        {
                print_help(argv[0]);
                ERROR_OUT("no arguments provided");
        }

        while (true)
        {
                int result = getopt_long(argc, argv, "a:b:c:d:e:f:gi:j:k:l:m:o:p:vh", cli_options, &index);

                if (result == -1)
                        break; /* end of list */

                switch (result)
                {
                        case 'a':
                                issuerKeyPath = optarg;
                                break;
                        case 'b':
                                issuerAltKeyPath = optarg;
                                break;
                        case 'c':
                                issuerCertPath = optarg;
                                break;
                        case 'd':
                                ownKeyPath = optarg;
                                break;
                        case 'e':
                                ownAltKeyPath = optarg;
                                break;
                        case 'f':
                                certOutputFilePath = optarg;
                                break;
                        case 'g':
                                enableCA = true;
                                break;
                        case 'i':
                                commonName = optarg;
                                break;
                        case 'o':
                                orgName = optarg;
                                break;
                        case 'p':
                                orgUnit = optarg;
                                break;
                        case 'j':
                                validity = strtol(optarg, NULL, 10);
                                break;
                        case 'k':
                                altName = optarg;
                                break;
                        case 'l':
                                csrInputPath = optarg;
                                break;
                        case 'm':
                                csrOutputFilePath = optarg;
                                break;
                        case 'v':
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

        /* Create a buffer to read the file contents */
        static const size_t bufferSize = 32 * 1024;
        size_t bytesInBuffer = bufferSize;
        uint8_t* buffer = (uint8_t*) malloc(bufferSize);
        if (buffer == NULL)
                ERROR_OUT("unable to allocate buffer");

        /* Load the issuer key */
        if (issuerKeyPath != NULL)
        {
                LOG_INFO("Loading issuer key from %s", issuerKeyPath);

                issuerKey = privateKey_new();

                /* Read file */
                ret = readFile(issuerKeyPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read issuer key file from %s", issuerKeyPath);

                /* Load key */
                ret = privateKey_loadKeyFromBuffer(issuerKey, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse issuer key: %d", ret);

                /* Load an alternative issuer key */
                if (issuerAltKeyPath != NULL)
                {
                        LOG_INFO("Loading alternative issuer key from %s", issuerAltKeyPath);

                        /* Read file */
                        bytesInBuffer = bufferSize;
                        ret = readFile(issuerAltKeyPath, buffer, &bytesInBuffer);
                        if (ret < 0)
                                ERROR_OUT("unable to read issuer alt key file from %s", issuerAltKeyPath);

                        /* Load key */
                        ret = privateKey_loadAltKeyFromBuffer(issuerKey, buffer, bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to parse issuer alt key: %d", ret);
                }
        }

        /* Load the own key */
        if (ownKeyPath != NULL)
        {
                LOG_INFO("Loading own key from %s", ownKeyPath);

                ownKey = privateKey_new();

                /* Read file */
                bytesInBuffer = bufferSize;
                ret = readFile(ownKeyPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read own key file from %s", ownKeyPath);

                /* Load key */
                ret = privateKey_loadKeyFromBuffer(ownKey, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse own key: %d", ret);

                /* Load an alternative own key */
                if (ownAltKeyPath != NULL)
                {
                        LOG_INFO("Loading own alternative key from %s", ownAltKeyPath);

                        /* Read file */
                        bytesInBuffer = bufferSize;
                        ret = readFile(ownAltKeyPath, buffer, &bytesInBuffer);
                        if (ret < 0)
                                ERROR_OUT("unable to read own alt key file from %s", ownAltKeyPath);

                        /* Load key */
                        ret = privateKey_loadAltKeyFromBuffer(ownKey, buffer, bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to parse own alt key: %d", ret);
                }
        }

        /* Load the issuer certificate */
        if (issuerCertPath != NULL)
        {
                LOG_INFO("Loading issuer cert from %s", issuerKeyPath);

                issuerCert = issuerCert_new();

                /* Read file */
                bytesInBuffer = bufferSize;
                ret = readFile(issuerCertPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read issuer cert file from %s", issuerCertPath);

                /* Load cert */
                ret = issuerCert_initFromBuffer(issuerCert, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse issuer cert: %d", ret);
        }

        /* Check if we have to generate a new CSR of if the user provided one */
        if (csrInputPath == NULL)
        {
                LOG_INFO("Generating a new CSR", issuerKeyPath);

                /* We have to create a new CSR */
                request = signingRequest_new();

                SigningRequestMetadata metadata = {
                        .CN = commonName,
                        .O = orgName,
                        .OU = orgUnit,
                        .altName = altName
                };

                /* Create the CSR */
                ret = signingRequest_init(request, &metadata);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to create CSR: %d", ret);

                /* Finalize the CSR */
                bytesInBuffer = bufferSize;
                ret = signingRequest_finalize(request, ownKey, buffer, &bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to finalize CSR: %d", ret);

                /* Write the CSR to file if requested */
                if (csrOutputFilePath != NULL)
                {
                        LOG_INFO("Writing CSR to %s", csrOutputFilePath);

                        ret = writeFile(csrOutputFilePath, buffer, bytesInBuffer);
                        if (ret < 0)
                                ERROR_OUT("unable to write CSR to %s", csrOutputFilePath);
                }
        }
        else
        {
                LOG_INFO("Loading CSR from %s", issuerKeyPath);

                /* Load the existing CSR */
                bytesInBuffer = bufferSize;
                ret = readFile(csrInputPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read CSR file from %s", csrInputPath);

        }

        /* Check if we have to create an actual certificate */
        if (certOutputFilePath != NULL)
        {
                LOG_INFO("Generating a new certifiate");

                outputCert = outputCert_new();

                /* Create the new certificate from the CSR. */
                ret = outputCert_initFromCsr(outputCert, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse CSR: %d", ret);

                /* Set the issuer data */
                ret = outputCert_setIssuerData(outputCert, issuerCert, issuerKey);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to set issuer data: %d", ret);

                /* Set the validity period */
                outputCert_setValidity(outputCert, validity);

                if (enableCA)
                {
                        LOG_INFO("Certificate is a CA cert");

                        /* Cert is a CA certificate */
                        ret = outputCert_configureAsCA(outputCert);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to configure new cert as CA: %d", ret);
                }
                else
                {
                        LOG_INFO("Certificate is an entity cert");

                        /* Cert is an entity certificate */
                        ret = outputCert_configureAsEntity(outputCert);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to configure new cert as entity: %d", ret);
                }

                /* Finalize the certificate. */
                bytesInBuffer = bufferSize;
                ret = outputCert_finalize(outputCert, issuerKey, buffer, &bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to finalize new cert: %d", ret);

                LOG_INFO("Writing certificate to %s", certOutputFilePath);

                /* Write the new cert to file */
                ret = writeFile(certOutputFilePath, buffer, bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to write output cert to %s", certOutputFilePath);
        }

        ret = KRITIS3M_PKI_SUCCESS;

exit:
        privateKey_free(issuerKey);
        privateKey_free(ownKey);

        issuerCert_free(issuerCert);

        signingRequest_free(request);

        outputCert_free(outputCert);

        return ret;
}

