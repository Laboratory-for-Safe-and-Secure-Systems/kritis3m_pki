#include "kritis3m_pki_common.h"
#include "kritis3m_pki_priv.h"

#include "wolfssl/options.h"

#include "wolfssl/error-ssl.h"
#include "wolfssl/wolfcrypt/memory.h"

/* Internal logging variables */
static int32_t pki_log_level = KRITIS3M_PKI_LOG_LEVEL_ERR;
static kritis3m_pki_log_callback pki_log_callback = NULL;
static bool pki_log_enabled = false;

/* Internal method declarations */
void wolfssl_logging_callback(int level, const char* str);
void kritis3m_pki_default_log_callback(int32_t level, char const* message);

int kritis3m_pki_prepare_logging(kritis3m_pki_configuration const* config)
{
        pki_log_enabled = config->logging_enabled;

        /* Update the internal log level. */
        if ((config->log_level >= KRITIS3M_PKI_LOG_LEVEL_ERR) &&
            (config->log_level <= KRITIS3M_PKI_LOG_LEVEL_DBG))
                pki_log_level = config->log_level;
        else
                return KRITIS3M_PKI_ARGUMENT_ERROR;

        /* Check if we have to enable WolfSSL internal logging */
        if ((pki_log_enabled == true) && (pki_log_level == KRITIS3M_PKI_LOG_LEVEL_DBG))
        {
                wolfSSL_SetLoggingCb(wolfssl_logging_callback);
                int ret = wolfSSL_Debugging_ON();
                if (ret != 0)
                        pki_log(KRITIS3M_PKI_LOG_LEVEL_WRN, "Debug output is not enabled, please compile with DEBUG_WOLFSSL defined");
        }

        if (config->log_callback != NULL)
                pki_log_callback = config->log_callback;
        else
                pki_log_callback = kritis3m_pki_default_log_callback;

        return KRITIS3M_PKI_SUCCESS;
}

void pki_log(int32_t level, char const* message, ...)
{
        if (pki_log_enabled == false || level > pki_log_level)
                return;

        va_list args;
        va_start(args, message);

        char buffer[256];
        vsnprintf(buffer, sizeof(buffer), message, args);

        va_end(args);

        if (pki_log_callback != NULL)
                pki_log_callback(level, buffer);
}

void wolfssl_logging_callback(int level, const char* str)
{
        (void) level;

        if (pki_log_enabled == true && pki_log_callback != NULL)
                pki_log_callback(KRITIS3M_PKI_LOG_LEVEL_DBG, str);
}

void kritis3m_pki_default_log_callback(int32_t level, char const* message)
{
        if (pki_log_enabled == false || level > pki_log_level)
                return;

        printf("%s\n", message);
}
