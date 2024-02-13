
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "common.h"

#if !defined(WOLFSSL_DUAL_ALG_CERTS) || !defined(HAVE_LIBOQS)
#error "DUAL_ALG_CERTS and HAVE_LIBOQS must be enabled"
#endif



#define SUBJECT_COUNTRY "DE"
#define SUBJECT_STATE "Bayern"
#define SUBJECT_LOCALITY "Regensburg"
#define SUBJECT_ORG "LaS3"
#define SUBJECT_UNIT "KRITIS3M"
#define SUBJECT_EMAIL "las3@oth-regensburg.de"


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

        PrivateKey issuerKey;
        PrivateKey issuerAltKey;
        IssuerCert issuerCert;
        PrivateKey ownKey;
        PrivateKey ownAltKey;
        AltKeyData altKeyData;
        OutputCert outputCert;

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

        /* Load the primary issuer key */
        ret = loadPrivateKey(issuerKeyPath, &issuerKey);
        if (ret != 0)
                goto exit;

        /* Load the primary own key */
        ret = loadPrivateKey(ownKeyPath, &ownKey);
        if (ret != 0)
                goto exit;

        /* Load the alternative issuer key */
        if (issuerAltKeyPath != NULL)
        {
                ret = loadPrivateKey(issuerAltKeyPath, &issuerAltKey);
                if (ret != 0)
                        goto exit;
        }
        else 
        {
                issuerAltKey.init = false;
        }

        /* Load the alternative own key */
        if (ownAltKeyPath != NULL)
        {
                ret = loadPrivateKey(ownAltKeyPath, &ownAltKey);
                if (ret != 0)
                        goto exit;
        }
        else 
        {
                ownAltKey.init = false;
        }

        /* Load the issuer certificate */
        if (issuerCertPath != NULL)
        {
                ret = loadIssuerCert(issuerCertPath, &issuerCert);
                if (ret != 0)
                        goto exit;
        }
        else
        {
                issuerCert.init = false;
        }

        /* Generate the certificate info for the alternative data */
        ret = genAltCertInfo(&altKeyData, &issuerAltKey, &ownAltKey);
        if (ret != 0)
                goto exit;

        /* Create a new certificate. */
        ret = prepareOutputCert(&outputCert, &issuerKey, &altKeyData);
        if (ret != 0)
                goto exit;

        /* Set metadata */
        strncpy(outputCert.cert.subject.commonName, commonName, CTC_NAME_SIZE);
        strncpy(outputCert.cert.subject.country, SUBJECT_COUNTRY, CTC_NAME_SIZE);
        // strncpy(outputCert.cert.subject.state, SUBJECT_STATE, CTC_NAME_SIZE);
        // strncpy(outputCert.cert.subject.locality, SUBJECT_LOCALITY, CTC_NAME_SIZE);
        strncpy(outputCert.cert.subject.org, SUBJECT_ORG, CTC_NAME_SIZE);
        strncpy(outputCert.cert.subject.unit, SUBJECT_UNIT, CTC_NAME_SIZE);
        // strncpy(outputCert.cert.subject.email, SUBJECT_EMAIL, CTC_NAME_SIZE);

        outputCert.cert.daysValid = 365*2; /* 2 years */

        if (enableCA)
                outputCert.cert.isCA = 1;
        else
                outputCert.cert.isCA = 0;
        
        if (issuerCert.init)
        {
                 /* Set the issuer */
                ret = wc_SetIssuerBuffer(&outputCert.cert, issuerCert.buffer, issuerCert.size);
                if (ret != 0)
                        goto exit;
        }

        /* Finalize the certificate. */
        ret = finalizeOutputCert(&outputCert, &issuerKey, &issuerAltKey,
                                 &ownKey, &altKeyData);
        if (ret != 0)
                goto exit;

        /* Write the new cert to file */
        ret = storeOutputCert(outputFilePath, &outputCert);

        if (ret == 0)
                printf("SUCCESS!\n");

exit:

        freePrivateKey(&issuerKey);
        freePrivateKey(&issuerAltKey);
        freePrivateKey(&ownKey);
        freePrivateKey(&ownAltKey);

        freeOutputCert(&outputCert);

        if (ret != 0)
                printf("Failure code was %d\n", ret);

        return ret;
}

