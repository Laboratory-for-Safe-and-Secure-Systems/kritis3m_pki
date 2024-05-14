
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "cli_common.h"
#include "kritis3m_pki_client.h"
#include "kritis3m_pki_server.h"


#define SUBJECT_COUNTRY "DE"
#define SUBJECT_STATE "Bayern"
#define SUBJECT_LOCALITY "Regensburg"
#define SUBJECT_ORG "LaS3"
#define SUBJECT_UNIT "KRITIS3M"
#define SUBJECT_EMAIL "las3@oth-regensburg.de"


#define ERROR_OUT(msg...) { fprintf(stderr, msg); ret = -1; goto exit; }


static const struct option cli_options[] =
{
        { "issuerKey",          required_argument, 0, 'a' },
        { "issuerAltKey",       required_argument, 0, 'b' },
        { "issuerCert",         required_argument, 0, 'c' },
        { "ownKey",             required_argument, 0, 'd' },
        { "ownAltKey",          required_argument, 0, 'e' },
        { "output",             required_argument, 0, 'f' },
        { "enableCA",           no_argument,       0, 'g' },
        { "CN",                 required_argument, 0, 'i' },
        { "help",               no_argument,       0, 'h' },
        { NULL, 0, NULL, 0}
};


void print_help(char *prog_name)
{
        printf("Usage: %s [OPTIONS]\n", prog_name);
        printf("Required arguments:\n");
        printf("  --issuerKey <file>    Path to the primary issuer key in PEM format\n");
        printf("  --ownKey <file>       Path to the primary own key in PEM format (same as issuerKey for self-signed certificate)\n");
        printf("  --output <file>       Path to the root certificate output file (PEM)\n");
        printf("  --CN <string>         Common Name (CN) for the certificate\n");
        printf("\nOptional arguments:\n");
        printf("  --issuerAltKey <file> Path to the alternative issuer key in PEM format (generate hybrid cert)\n");
        printf("  --issuerCert <file>   Path to the issuer certificate in PEM format\n");
        printf("  --ownAltKey <file>    Path to the alternative own key in PEM format (same as issuerAltKey for self-signed certificate)\n");
        printf("  --enableCA            Set CA flag in certificate\n");
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
        char const* outputFilePath = NULL;

        PrivateKey* issuerKey = privateKey_new();
        IssuerCert* issuerCert = issuerCert_new();
        PrivateKey* ownKey = privateKey_new();
        SigningRequest* request = signingRequest_new();
        OutputCert* outputCert = outputCert_new();

        bool enableCA = false;
        char const* commonName = NULL;

        /* Parse CLI args */
        while (true)
        {
                int result = getopt_long(argc, argv, "a:b:c:d:e:f:g:i:h", cli_options, &index);

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
                                outputFilePath = optarg;
                                break;
                        case 'g':
                                enableCA = true;
                                break;
                        case 'i':
                                commonName = optarg;
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

        /* Check if all required arguments are present */
        if ((issuerKeyPath == NULL) || (ownKeyPath == NULL) || (outputFilePath == NULL) || (commonName == NULL))
        {
                fprintf(stderr, "missing required arguments\n");
                print_help(argv[0]);
                exit(-1);
        }

        /* Further sanity check arguments */
        if (strcmp(issuerKeyPath, ownKeyPath) != 0 && issuerCertPath == NULL)
        {
                fprintf(stderr, "we need the issuer certificate to derive a cert from it\n");
                print_help(argv[0]);
                exit(-1);
        }
        else if (strcmp(issuerKeyPath, ownKeyPath) == 0)
        {
                if ((issuerAltKeyPath != NULL && ownAltKeyPath == NULL) ||
                        (issuerAltKeyPath == NULL && ownAltKeyPath != NULL))
                {
                        fprintf(stderr, "we need the alternative key for both issuerAltKey and ownAltKey to generate a hybrid self-signed certificate\n");
                        print_help(argv[0]);
                        exit(-1);
                }
        }

        /* Create a buffer to read the file contents */
        static const size_t bufferSize = 32 * 1024;
        size_t bytesInBuffer = bufferSize;
        uint8_t* buffer = (uint8_t*) malloc(bufferSize);
        if (buffer == NULL)
                ERROR_OUT("unable to allocate buffer\n");

        /* Load the primary issuer key */
        ret = readFile(issuerKeyPath, buffer, &bytesInBuffer);
        if (ret < 0)
                ERROR_OUT("unable to read issuer key file from %s\n", issuerKeyPath);

        ret = privateKey_loadKeyFromBuffer(issuerKey, buffer, bytesInBuffer);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to parse issuer key: %d\n", ret);

        /* Load the primary own key */
        bytesInBuffer = bufferSize;
        ret = readFile(ownKeyPath, buffer, &bytesInBuffer);
        if (ret < 0)
                ERROR_OUT("unable to read own key file from %s\n", ownKeyPath);

        ret = privateKey_loadKeyFromBuffer(ownKey, buffer, bytesInBuffer);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to parse own key: %d\n", ret);

        /* Load the alternative issuer key */
        if (issuerAltKeyPath != NULL)
        {
                bytesInBuffer = bufferSize;
                ret = readFile(issuerAltKeyPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read issuer alt key file from %s\n", issuerAltKeyPath);

                ret = privateKey_loadAltKeyFromBuffer(issuerKey, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse issuer alt key: %d\n", ret);
        }

        /* Load the alternative own key */
        if (ownAltKeyPath != NULL)
        {
                bytesInBuffer = bufferSize;
                ret = readFile(ownAltKeyPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read own alt key file from %s\n", ownAltKeyPath);

                ret = privateKey_loadAltKeyFromBuffer(ownKey, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse own alt key: %d\n", ret);
        }

        /* Load the issuer certificate */
        if (issuerCertPath != NULL)
        {
                bytesInBuffer = bufferSize;
                ret = readFile(issuerCertPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read issuer cert file from %s\n", issuerCertPath);

                ret = issuerCert_initFromBuffer(issuerCert, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse issuer cert: %d\n", ret);
        }

        /* Create the CSR */
        ret = signingRequest_init(request, commonName);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to create CSR: %d\n", ret);

        bytesInBuffer = bufferSize;
        ret = signingRequest_finalize(request, ownKey, buffer, &bytesInBuffer);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to finalize CSR: %d\n", ret);

        /* Create the new certificate from the CSR. */
        ret = outputCert_initFromCsr(outputCert, buffer, bytesInBuffer);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to parse CSR: %d\n", ret);

        /* Set the issuer data */
        ret = outputCert_setIssuerData(outputCert, issuerCert, issuerKey);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to set issuer data: %d\n", ret);

        /* Set the validity period */
        outputCert_setValidity(outputCert, 365*2); /* 2 years */

        if (enableCA)
        {
                /* Cert is a CA certificate */
                ret = outputCert_configureAsCA(outputCert);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to configure new cert as CA: %d\n", ret);
        }
        else
        {
                /* Cert is an entity certificate */
                ret = outputCert_configureAsEntity(outputCert);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to configure new cert as entity: %d\n", ret);
        }

        /* Finalize the certificate. */
        bytesInBuffer = bufferSize;
        ret = outputCert_finalize(outputCert, issuerKey, buffer, &bytesInBuffer);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to finalize new cert: %d\n", ret);

        /* Write the new cert to file */
        ret = writeFile(outputFilePath, buffer, bytesInBuffer);
        if (ret < 0)
                ERROR_OUT("unable to write output cert to %s\n", outputFilePath);
        if (ret == 0)
                printf("SUCCESS!\n\n");

exit:

        privateKey_free(issuerKey);
        privateKey_free(ownKey);

        signingRequest_free(request);

        outputCert_free(outputCert);

        if (ret != 0)
                printf("Failure code was %d\n", ret);

        return ret;
}

