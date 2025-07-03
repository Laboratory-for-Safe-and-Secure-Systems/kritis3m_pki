
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "kritis3m_pki_client.h"

#include "file_io.h"
#include "logging.h"

LOG_MODULE_CREATE(kritis3m_se_importer);

#define ERROR_OUT(...)                                                                             \
        {                                                                                          \
                LOG_ERROR(__VA_ARGS__);                                                            \
                ret = 1;                                                                           \
                goto exit;                                                                         \
        }

#define RESET_BUFFER()                                                                             \
        {                                                                                          \
                free(buffer);                                                                      \
                buffer = NULL;                                                                     \
                bytesInBuffer = 0;                                                                 \
        }

#define RESET_INPUT_CERT()                                                                         \
        {                                                                                          \
                inputCert_free(cert);                                                              \
                cert = NULL;                                                                       \
        }

static const struct option cli_options[] = {
        {"key", required_argument, 0, 0x01},
        {"key_label", required_argument, 0, 0x02},
        {"alt_key", required_argument, 0, 0x03},
        {"alt_key_label", required_argument, 0, 0x04},
        {"module_path", required_argument, 0, 0x05},
        {"slot", required_argument, 0, 0x06},
        {"pin", required_argument, 0, 0x07},
        {"entity_cert", required_argument, 0, 0x08},
        {"entity_cert_label", required_argument, 0, 0x09},
        {"intermediate_cert", required_argument, 0, 0x0A},
        {"intermediate_cert_label", required_argument, 0, 0x0B},
        {"root_cert", required_argument, 0, 0x0C},
        {"root_cert_label", required_argument, 0, 0x0D},
        {"pre_shared_key", required_argument, 0, 0x0E},
        {"pre_shared_key_label", required_argument, 0, 0x0F},
        {"verbose", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {NULL, 0, NULL, 0},
};

void print_help(char* prog_name)
{
        printf("Usage: %s [OPTIONS]\r\n", prog_name);
        printf("\nFile input:\r\n");
        printf("  --key <file>                      Path to the primary key (PEM)\r\n");
        printf("  --alt_key <file>                  Path to the alternative key (PEM)\r\n");
        printf("  --entity_cert <file>              Path to the entity cert (PEM)\r\n");
        printf("  --intermediate_cert <file>        Path to the intermediate cert (PEM)\r\n");
        printf("  --root_cert <file>                Path to the root cert (PEM)\r\n");

        printf("\nPre-shared key:\r\n");
        printf("  --pre_shared_key key              Pre-shared key to use (Base64 encoded)\r\n");

        printf("\nPKCS#11 labels:\r\n");
        printf("  --key_label <label>               Label of the primary key\r\n");
        printf("  --alt_key_label <label>           Label of the alternative key\r\n");
        printf("  --entity_cert_label <file>        Label of the entity certificate\r\n");
        printf("  --intermediate_cert_label <file>  Label of the intermediate certificate\r\n");
        printf("  --root_cert_label <file>          Label of the intermediate certificate\r\n");
        printf("  --pre_shared_key_label <label>    Label of the pre-shared key\r\n");

        printf("\nPKCS#11 token:\r\n");
        printf("  --module_path <file>              Path to the PKCS#11 module library\r\n");
        printf("  --slot <id>                       Slot id of the PKCS#11 token (default is first "
               "available)\r\n");
        printf("  --pin <pin>                       PIN for the PKCS#11 token\r\n");

        printf("\nGeneral:\r\n");
        printf("  --verbose                         Enable verbose output\r\n");
        printf("  --debug                           Enable debug output\r\n");
        printf("  --help                            Print this help\r\n");
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
        char const* entityCertPath = NULL;
        char const* intermediateCertPath = NULL;
        char const* rootCertPath = NULL;

        char const* preSharedKey = NULL;

        /* PKCS#11 labels */
        char const* keyLabel = NULL;
        char const* altKeyLabel = NULL;
        char const* entityCertLabel = NULL;
        char const* intermediateCertLabel = NULL;
        char const* rootCertLabel = NULL;
        char const* preSharedKeyLabel = NULL;

        /* PKCS#11 */
        char const* modulePath = NULL;
        char const* pin = NULL;
        int pinSize = 0;
        int slot = -1;
        int deviceId = -1;

        size_t bytesInBuffer = 0;
        uint8_t* buffer = NULL;

        PrivateKey* key = NULL;
        InputCert* cert = NULL;

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
                case 0x08: /* entity_cert */
                        entityCertPath = optarg;
                        break;
                case 0x09: /* entity_cert_label */
                        entityCertLabel = optarg;
                        break;
                case 0x0A: /* intermediate_cert */
                        intermediateCertPath = optarg;
                        break;
                case 0x0B: /* intermediate_cert_label */
                        intermediateCertLabel = optarg;
                        break;
                case 0x0C: /* root_cert */
                        rootCertPath = optarg;
                        break;
                case 0x0D: /* root_cert_label */
                        rootCertLabel = optarg;
                        break;
                case 0x0E: /* pre_shared_key */
                        preSharedKey = optarg;
                        break;
                case 0x0F: /* pre_shared_key_label */
                        preSharedKeyLabel = optarg;
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

        /* Initialize the PKI libraries */
        kritis3m_pki_configuration pki_lib_config = {
                .logging_enabled = true,
                .log_level = LOG_LVL_GET(),
                .log_callback = pki_lib_log_callback,
        };
        ret = kritis3m_pki_init(&pki_lib_config);
        if (ret != KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to initialize PKI libraries: %s (%d)",
                          kritis3m_pki_error_message(ret),
                          ret);

        if (modulePath == NULL)
                ERROR_OUT("No PKCS#11 module path provided");

        /* Initialize the PKCS#11 module */
        LOG_INFO("Initializing PKCS#11 module \"%s\"", modulePath);
        deviceId = kritis3m_pki_init_entity_token(modulePath, slot, (uint8_t const*) pin, pinSize);
        if (deviceId < KRITIS3M_PKI_SUCCESS)
                ERROR_OUT("unable to initialize token: %s (%d)",
                          kritis3m_pki_error_message(deviceId),
                          deviceId);

        if (keyPath != NULL && keyLabel != NULL)
        {
                key = privateKey_new();
                if (key == NULL)
                        ERROR_OUT("unable to allocate memory for key");

                LOG_INFO("Loading key from \"%s\"", keyPath);

                ret = read_file(keyPath, &buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read key from \"%s\"", keyPath);

                ret = privateKey_loadKeyFromBuffer(key, buffer, bytesInBuffer);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse key: %s (%d)", kritis3m_pki_error_message(ret), ret);

                RESET_BUFFER();

                /* Load an alternative key */
                if (altKeyPath != NULL)
                {
                        LOG_INFO("Loading alternative key from \"%s\"", altKeyPath);

                        /* Read file */
                        ret = read_file(altKeyPath, &buffer, &bytesInBuffer);
                        if (ret < 0)
                                ERROR_OUT("unable to read alt key from \"%s\"", altKeyPath);

                        /* Load key */
                        ret = privateKey_loadAltKeyFromBuffer(key, buffer, bytesInBuffer);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to parse alt key: %s (%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);

                        RESET_BUFFER();
                }
        }
        else if ((keyPath != NULL && keyLabel == NULL) || (keyPath == NULL && keyLabel != NULL))
        {
                ERROR_OUT("Both a PKCS#11 key label and a file path are required");
        }

        if (entityCertPath != NULL && entityCertLabel != NULL)
        {
                cert = inputCert_new();
                if (cert == NULL)
                        ERROR_OUT("unable to allocate memory for certificate");

                LOG_INFO("Loading entity cert from \"%s\"", entityCertPath);

                ret = read_file(entityCertPath, &buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read entity cert from \"%s\"", entityCertPath);

                /* By providing the already loaded private key here, the private key is also
                 * matched to the public key from the certificate. */
                ret = inputCert_initFromBuffer(cert, buffer, bytesInBuffer, key);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse entity cert: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                LOG_INFO("Importing entity cert with label \"%s\"", entityCertLabel);

                ret = kritis3m_pki_entity_token_import_cert(cert, entityCertLabel);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to import entity cert: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                LOG_INFO("Entity certificate successfully imported");

                RESET_INPUT_CERT();
                RESET_BUFFER();
        }
        else if ((entityCertPath != NULL && entityCertLabel == NULL) ||
                 (entityCertPath == NULL && entityCertLabel != NULL))
        {
                ERROR_OUT("Both a PKCS#11 entity certificate label and a file path are required");
        }

        if (key != NULL)
        {
                LOG_INFO("Importing key with label \"%s\"", keyLabel);

                if (entityCertLabel != NULL && strcmp(keyLabel, entityCertLabel) != 0)
                        LOG_WARN("Label of private key and entity certificate do not match");

                ret = privateKey_setExternalRef(key, deviceId, keyLabel);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to set external reference for key: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                /* Check if an alternative key gets its own label. If not, the one from
                 * the primary above is used. */
                if (altKeyLabel != NULL)
                {
                        LOG_INFO("Using alternative key label \"%s\"", altKeyLabel);

                        ret = privateKey_setAltExternalRef(key, deviceId, altKeyLabel);
                        if (ret != KRITIS3M_PKI_SUCCESS)
                                ERROR_OUT("unable to set external reference for alt key: %s (%d)",
                                          kritis3m_pki_error_message(ret),
                                          ret);
                }

                /* Import the key into the secure element */
                ret = kritis3m_pki_entity_token_import_key(key);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to import key: %s (%d)", kritis3m_pki_error_message(ret), ret);

                LOG_INFO("Key successfully imported");
        }

        if (intermediateCertPath != NULL && intermediateCertLabel != NULL)
        {
                cert = inputCert_new();
                if (cert == NULL)
                        ERROR_OUT("unable to allocate memory for certificate");

                LOG_INFO("Loading intermediate cert from \"%s\"", intermediateCertPath);

                ret = read_file(intermediateCertPath, &buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read intermediate cert from \"%s\"", intermediateCertPath);

                /* Do not provide a private key here as we don't have the intermediate key */
                ret = inputCert_initFromBuffer(cert, buffer, bytesInBuffer, NULL);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse intermediate cert: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                LOG_INFO("Importing intermediate cert with label \"%s\"", intermediateCertLabel);

                ret = kritis3m_pki_entity_token_import_cert(cert, intermediateCertLabel);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to import intermediate cert: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                LOG_INFO("Intermediate certificate successfully imported");

                RESET_INPUT_CERT();
                RESET_BUFFER();
        }
        else if ((intermediateCertPath != NULL && intermediateCertLabel == NULL) ||
                 (intermediateCertPath == NULL && intermediateCertLabel != NULL))
        {
                ERROR_OUT("Both a PKCS#11 intermediate certificate label and a file path are "
                          "required");
        }

        if (rootCertPath != NULL)
        {
                cert = inputCert_new();
                if (cert == NULL)
                        ERROR_OUT("unable to allocate memory for certificate");

                LOG_INFO("Loading root cert from \"%s\"", rootCertPath);

                ret = read_file(rootCertPath, &buffer, &bytesInBuffer);
                if (ret < 0)
                        ERROR_OUT("unable to read root cert from \"%s\"", rootCertPath);

                /* Do not provide a private key here as we don't have the root key */
                ret = inputCert_initFromBuffer(cert, buffer, bytesInBuffer, NULL);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to parse root cert: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                if (rootCertLabel != NULL)
                        LOG_INFO("Importing root cert with label \"%s\"", rootCertLabel);
                else
                        LOG_INFO("Importing root cert without label");

                ret = kritis3m_pki_entity_token_import_cert(cert, rootCertLabel);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to import root cert: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                LOG_INFO("Root certificate successfully imported");

                RESET_INPUT_CERT();
                RESET_BUFFER();
        }
        else if (rootCertPath == NULL && rootCertLabel != NULL)
        {
                ERROR_OUT("No root certificate file path provided, but a PKCS#11 label is given");
        }

        if (preSharedKey != NULL && preSharedKeyLabel != NULL)
        {
                LOG_INFO("Importing pre-shared key with label \"%s\"", preSharedKeyLabel);

                ret = kritis3m_pki_entity_token_import_psk(preSharedKey, preSharedKeyLabel);
                if (ret != KRITIS3M_PKI_SUCCESS)
                        ERROR_OUT("unable to import pre-shared key: %s (%d)",
                                  kritis3m_pki_error_message(ret),
                                  ret);

                LOG_INFO("Pre-shared key successfully imported");
        }
        else if ((preSharedKey != NULL && preSharedKeyLabel == NULL) ||
                 (preSharedKey == NULL && preSharedKeyLabel != NULL))
        {
                ERROR_OUT("Both a PKCS#11 pre-shared key label and a key are required");
        }

exit:
        kritis3m_pki_close_entity_token();

        privateKey_free(key);
        inputCert_free(cert);

        if (buffer != NULL)
                free(buffer);

        kritis3m_pki_shutdown();

        return ret;
}
