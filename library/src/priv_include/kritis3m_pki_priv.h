#ifndef KRITIS3M_PKI_PRIV_H
#define KRITIS3M_PKI_PRIV_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/falcon.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"


#define LARGE_TEMP_SZ 12288

#define ERROR_OUT(error_code) { ret = error_code; goto cleanup; }

#define SubjectAltPublicKeyInfoExtension "2.5.29.72"
#define AltSignatureAlgorithmExtension "2.5.29.73"
#define AltSignatureValueExtension "2.5.29.74"

#define PKCS11_ENTITY_TOKEN_DEVICE_ID 1
#define PKCS11_ISSUER_TOKEN_DEVICE_ID 2


/* Struct declarations (hidden from the public headers) */
typedef struct singlePrivateKey
{
        int type;
        int certKeyType;
        bool init;
        union
        {
                ecc_key ecc;
                RsaKey rsa;
                dilithium_key dilithium;
                falcon_key falcon;
        } key;
        struct
        {
                int deviceId;
                char* label;
        } external;
}
SinglePrivateKey;

struct privateKey
{
        SinglePrivateKey primaryKey;
        SinglePrivateKey alternativeKey;
};

struct issuerCert
{
        bool init;
        uint8_t* buffer;
        size_t size;
};

struct signingRequest
{
        Cert req;

        int altSigAlg;
        uint8_t* altPubKeyDer;
        uint8_t* altSigAlgDer;
        uint8_t* altSigValDer;
};

struct outputCert
{
        Cert cert;
        SinglePrivateKey ownKey;

        int altSigAlg;
        uint8_t* altPubKeyDer;
        uint8_t* altSigAlgDer;
        uint8_t* altSigValDer;
};

/* Internal helper methods */
int getSigAlgForKey(SinglePrivateKey* key);
void freeSinglePrivateKey(SinglePrivateKey* key);
int initPkcs11Token(Pkcs11Token* token, int slot_id, uint8_t const* pin, size_t pin_size, int device_id);
int initPrivateKey(SinglePrivateKey* key, int type);

#endif /* KRITIS3M_PKI_PRIV_H */