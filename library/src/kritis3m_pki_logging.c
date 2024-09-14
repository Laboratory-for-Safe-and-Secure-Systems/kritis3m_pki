#include "kritis3m_pki_common.h"
#include "kritis3m_pki_priv.h"

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"
#include "wolfssl/error-ssl.h"


/* Internal logging variables */
static int32_t log_level = KRITIS3M_PKI_LOG_LEVEL_ERR;
static kritis3m_pki_custom_log_callback log_callback = NULL;
static bool log_enabled = false;

/* Internal method declarations */
void wolfssl_logging_callback(int level, const char* str);
void kritis3m_pki_default_log_callback(int32_t level, char const* message);


/* Enable/disable logging infrastructure.
 *
 * Parameter is a boolean value to enable or disable logging.
 *
 * Returns KRITIS3M_PKI_SUCCESS on success, negative error code in case of an error.
 */
int kritis3m_pki_enable_logging(bool enable)
{
	log_enabled = enable;

	/* Check if we have to enable WolfSSL internal logging */
	if (log_enabled == true && log_level == KRITIS3M_PKI_LOG_LEVEL_DBG)
	{
    		int ret = wolfSSL_Debugging_ON();
		if (ret != 0)
		{
			pki_log(KRITIS3M_PKI_LOG_LEVEL_WRN, "Debug output is not compiled in, please compile with DEBUG_WOLFSSL preprocessor makro defined");
		}
	}
	else
		wolfSSL_Debugging_OFF();

	return KRITIS3M_PKI_SUCCESS;
}


/* Set a custom logging callback.
 *
 * Parameter is a function pointer to the custom logging callback.
 *
 * Returns KRITIS3M_PKI_SUCCESS on success, negative error code in case of an error.
 */
int kritis3m_pki_set_custom_log_callback(kritis3m_pki_custom_log_callback new_callback)
{
	/* Update the internal pointer to the callback. */
	if (new_callback != NULL)
		log_callback = new_callback;
	else
		log_callback = kritis3m_pki_default_log_callback;

        wolfSSL_SetLoggingCb(wolfssl_logging_callback);

	return KRITIS3M_PKI_SUCCESS;
}


/* Update the log level.
 *
 * Parameter is the new log level.
 *
 * Returns KRITIS3M_PKI_SUCCESS on success, negative error code in case of an error.
 */
int kritis3m_pki_set_log_level(int32_t new_log_level)
{
	/* Update the internal log level. */
	if ((new_log_level >= KRITIS3M_PKI_LOG_LEVEL_ERR) && (new_log_level <= KRITIS3M_PKI_LOG_LEVEL_DBG))
		log_level = new_log_level;
	else
		return KRITIS3M_PKI_ARGUMENT_ERROR;

	/* Check if we have to enable WolfSSL internal logging */
	if (log_enabled == true && log_level == KRITIS3M_PKI_LOG_LEVEL_DBG)
	{
    		int ret = wolfSSL_Debugging_ON();
		if (ret != 0)
		{
			pki_log(KRITIS3M_PKI_LOG_LEVEL_WRN, "Debug output is not compiled in, please compile with DEBUG_WOLFSSL preprocessor makro defined");
		}
	}
	else
		wolfSSL_Debugging_OFF();

	return KRITIS3M_PKI_SUCCESS;
}


void pki_log(int32_t level, char const* message, ...)
{
	if (log_enabled == false || level > log_level)
		return;

	va_list args;
	va_start(args, message);

	char buffer[256];
	vsnprintf(buffer, sizeof(buffer), message, args);

	va_end(args);

	if (log_callback != NULL)
		log_callback(level, buffer);

}


void wolfssl_logging_callback(int level, const char* str)
{
	(void) level;

	if (log_enabled == true && log_callback != NULL)
		log_callback(KRITIS3M_PKI_LOG_LEVEL_DBG, str);
}


void kritis3m_pki_default_log_callback(int32_t level, char const* message)
{
	if (log_enabled == false || level > log_level)
		return;

	printf("%s\n", message);
}
