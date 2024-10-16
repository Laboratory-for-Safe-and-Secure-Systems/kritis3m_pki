
#include <stdio.h>
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
        { "key",            required_argument, 0, 0x01 },
        { "key_label",      required_argument, 0, 0x02 },
        { "alt_key",        required_argument, 0, 0x03 },
        { "alt_key_label",  required_argument, 0, 0x04 },
        { "module_path",     required_argument, 0, 0x05 },
        { "slot",           required_argument, 0, 0x06 },
        { "pin",            required_argument, 0, 0x07 },
        { "verbose",        no_argument,       0, 'v'  },
        { "debug",          no_argument,       0, 'd'  },
        { "help",           no_argument,       0, 'h'  },
        { NULL, 0, NULL, 0}
};


void print_help(char *prog_name)
{
        printf("Usage: %s [OPTIONS]\r\n", prog_name);
        printf("\nKey file input:\r\n");
        printf("  --key <file>                  Path to the primary key in PEM format\r\n");
        printf("  --alt_key <file>              Path to the alternative key in PEM format\r\n");

        printf("\nPKCS#11 key labels:\r\n");
        printf("  --key_label <label>           Label of the primary key in PKCS#11\r\n");
        printf("  --alt_key_label <label>       Label of the alternative key in PKCS#11\r\n");

        printf("\nSecure Element:\r\n");
        printf("  --module_path <file>          Path to the PKCS#11 module library\r\n");
        printf("  --slot <id>                   Slot id of the secure element containing the issuer keys (default is first available)\r\n");
        printf("  --pin <pin>                   PIN for the secure element\r\n");

        printf("\nGeneral:\r\n");
        printf("  --verbose                     Enable verbose output\r\n");
        printf("  --debug                       Enable debug output\r\n");
        printf("  --help                        Print this help\r\n");
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
        int index = 0;

        /* Paths */
        char const* keyPath = NULL;
        char const* altKeyPath = NULL;

        /* PKCS#11 labels */
        char const* keyLabel = NULL;
        char const* altKeyLabel = NULL;

        /* PKCS#11 */
        char const* modulePath = NULL;
        char const* pin = NULL;
        int pinSize = 0;
        int slot = -1;
        int deviceId = -1;


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
                int result = getopt_long(argc, argv, "vdh", cli_options, &index);

                if (result == -1)
                        break; /* end of list */

                switch (result)
                {
                        case 0x01: /* key */
                                keyPath = optarg;
                                break;
                        case 0x02: /* key_label */
                                keyLabel = optarg;
                                break;
                        case 0x03: /* alt_key */
                                altKeyPath = optarg;
                                break;
                        case 0x04: /* alt_key_label */
                                altKeyLabel = optarg;
                                break;
                        case 0x05: /* module_path */
                                modulePath = optarg;
                                break;
                        case 0x06: /* slot */
                                slot = strtol(optarg, NULL, 10);
                                break;
                        case 0x07: /* pin */
                                pin = optarg;
                                pinSize = strlen(pin);
                                break;
                        case 'v':
                                LOG_LVL_SET(LOG_LVL_INFO);
                                break;
                        case 'd':
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

        /* Create a buffer to read the file contents */
        buffer = (uint8_t*) malloc(bufferSize);
        if (buffer == NULL)
                ERROR_OUT("unable to allocate buffer");

        /* Initialize the PKI libraries */
        kritis3m_pki_configuration pki_lib_config = {
                .logging_enabled = true,
                .log_level = LOG_LVL_GET(),
                .log_callback = pki_lib_log_callback,
        };
        ret = kritis3m_pki_init(&pki_lib_config);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to initialize PKI libraries: %s (%d)", kritis3m_pki_error_message(ret), ret);


        /* Initialize the PKCS#11 module */
        deviceId = kritis3m_pki_init_entity_token(modulePath, slot, (uint8_t const*)pin, pinSize);
        if (deviceId < KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to initialize token: %s (%d)", kritis3m_pki_error_message(deviceId), deviceId);

        /* Prepare the key */
        key = privateKey_new();
        if (key == NULL)
                ERROR_OUT("unable to allocate memory for key");

        /* Set the external references */
        if (keyLabel != NULL)
        {
                LOG_INFO("Using key label \"%s\"", keyLabel);

                ret = privateKey_setExternalRef(key, deviceId, keyLabel);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to set external reference for key: %s (%d)", kritis3m_pki_error_message(ret), ret);

                /* Check if an alternative key gets its own label */
                if (altKeyLabel != NULL)
                {
                        LOG_INFO("Using alternative key label \"%s\"", altKeyLabel);

                        ret = privateKey_setAltExternalRef(key, deviceId, altKeyLabel);
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

