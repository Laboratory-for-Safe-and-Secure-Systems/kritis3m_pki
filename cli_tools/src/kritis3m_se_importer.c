
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "cli_common.h"
#include "kritis3m_pki_client.h"

#include "logging.h"


LOG_MODULE_CREATE(kritis3m_se_importer);


#define ERROR_OUT(...) { LOG_ERROR(__VA_ARGS__); ret = 1; goto exit; }


static const struct option cli_options[] =
{
        { "key",         required_argument, 0, 'a' },
        { "keyLabel",    required_argument, 0, 'b' },
        { "altKey",      required_argument, 0, 'c' },
        { "altKeyLabel", required_argument, 0, 'd' },
        { "middleware",  required_argument, 0, 'e' },
        { "slot",        required_argument, 0, 'f' },
        { "verbose",     no_argument,       0, 'v' },
        { "help",        no_argument,       0, 'h' },
        { NULL, 0, NULL, 0}
};


void print_help(char *prog_name)
{
        printf("Usage: %s [OPTIONS]\r\n", prog_name);
        printf("Arguments:\n");
        printf("\nKey file input:\r\n");
        printf("  --key <file>             Path to the primary key in PEM format\r\n");
        printf("  --altKey <file>          Path to the alternative key in PEM format\r\n");

        printf("\nPKCS#11 key labels:\r\n");
        printf("  --keyLabel <label>       Label of the primary key in PKCS#11\r\n");
        printf("  --altKeyLabel <label>    Label of the alternative key in PKCS#11\r\n");

        printf("\nSecure Element:\r\n");
        printf("  --middleware <file>      Path to the secure element middleware\r\n");
        printf("  --slot <id>              Slot id of the secure element containing the issuer keys (default is first available)\r\n");

        printf("\nGeneral:\r\n");
        printf("  --verbose               Enable verbose output\r\n");
        printf("  --help                  Print this help\r\n");
}


int main(int argc, char** argv)
{
        int ret = 0;
        int index = 0;

        /* Paths */
        char const* keyPath = NULL;
        char const* altKeyPath = NULL;

        /* PKCS#11 labels */
        char const* keyLabel = NULL;
        char const* altKeyLabel = NULL;

        /* Secure Element */
        char const* middlewarePath = NULL;
        int slot = -1;
        int tokenDeviceId = -1;


        static const size_t bufferSize = 32 * 1024;
        size_t bytesInBuffer = bufferSize;
        uint8_t* buffer = NULL;

        PrivateKey* key = NULL;


        /* Parse CLI args */
        if (argc < 2)
        {
                print_help(argv[0]);
                ERROR_OUT("no arguments provided");
        }

        while (true)
        {
                int result = getopt_long(argc, argv, "a:b:c:d:e:f:vh", cli_options, &index);

                if (result == -1)
                        break; /* end of list */

                switch (result)
                {
                        case 'a':
                                keyPath = optarg;
                                break;
                        case 'b':
                                keyLabel = optarg;
                                break;
                        case 'c':
                                altKeyPath = optarg;
                                break;
                        case 'd':
                                altKeyLabel = optarg;
                                break;
                        case 'e':
                                middlewarePath = optarg;
                                break;
                        case 'f':
                                slot = strtol(optarg, NULL, 10);
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
        buffer = (uint8_t*) malloc(bufferSize);
        if (buffer == NULL)
                ERROR_OUT("unable to allocate buffer");

        /* Initialize the PKCS#11 support */
        if (middlewarePath != NULL)
        {
                LOG_INFO("Initializing PKCS#11 library using middleware from \"%s\"", middlewarePath);

                ret = kritis3m_pki_init_pkcs11(middlewarePath);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to initialize PKCS#11 middleware: %s (%d)", kritis3m_pki_error_message(ret), ret);
        }
        else
                ERROR_OUT("No PKCS#11 middleware provided");

        /* Initialize the PKCS#11 token */
        tokenDeviceId = kritis3m_pki_init_entity_token(slot, NULL, 0);
        if (tokenDeviceId < KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to initialize token: %s (%d)", kritis3m_pki_error_message(tokenDeviceId), tokenDeviceId);

        /* Prepare the key */
        key = privateKey_new();
        if (key == NULL)
                ERROR_OUT("unable to allocate memory for key");

        /* Set the external references */
        if (keyLabel != NULL)
        {
                LOG_INFO("Using key label \"%s\"", keyLabel);

                ret = privateKey_setExternalRef(key, tokenDeviceId, keyLabel);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to set external reference for key: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Check if an alternative key gets its own label */
                if (altKeyLabel != NULL)
                {
                        LOG_INFO("Using alternative key label \"%s\"", altKeyLabel);

                        ret = privateKey_setAltExternalRef(key, tokenDeviceId, altKeyLabel);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to set external reference for alt key: %s (%d)", kritis3m_pki_error_message(ret), ret);
                }
        }
        else
                ERROR_OUT("No PKCS#11 label for the key provided");

        if (keyPath != NULL)
        {
                LOG_INFO("Loading key from \"%s\"", keyPath);

                /* Read file */
                bytesInBuffer = bufferSize;
                ret = readFile(keyPath, buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read key file from \"%s\"", keyPath);

                /* Load key */
                ret = privateKey_loadKeyFromBuffer(key, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to parse key: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Load an alternative key */
                if (altKeyPath != NULL)
                {
                        LOG_INFO("Loading alternative key from \"%s\"", altKeyPath);

                        /* Read file */
                        bytesInBuffer = bufferSize;
                        ret = readFile(altKeyPath, buffer, &bytesInBuffer);
                        if (ret < 0)
                                ERROR_OUT("unable to read alt key file from \"%s\"", altKeyPath);

                        /* Load key */
                        ret = privateKey_loadAltKeyFromBuffer(key, buffer, bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to parse alt key: %s (%d)", kritis3m_pki_error_message(ret), ret);
                }
        }
        else
                ERROR_OUT("No key provided");

        /* Import the key into the secure element */
        ret = kritis3m_pki_entity_token_import_key(key);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to import key: %s (%d)", kritis3m_pki_error_message(ret), ret);

        LOG_INFO("Key successfully imported");

exit:
        kritis3m_pki_close_entity_token();

        privateKey_free(key);

        if (buffer != NULL)
                free(buffer);

        return ret;
}

