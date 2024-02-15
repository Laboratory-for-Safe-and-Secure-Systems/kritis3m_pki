
#include "common.h"

int readFile(const char* filePath, uint8_t* buffer, size_t* bufferSize)
{
        /* Open the file */
        FILE* file = fopen(filePath, "r");

        if (file == NULL)
        {
                printf("file (%s) cannot be opened\n", filePath);
                return -1;
        }

        /* Get length of file */
        fseek(file, 0, SEEK_END);
        int fileSize = ftell(file);
        rewind(file);

        if (fileSize > *bufferSize)
        {
                printf("file (%s) is too large for buffer\n", filePath);
                fclose(file);
                return -1;
        }

        /* Read file to buffer */
        int bytesRead = 0;
        while (bytesRead < fileSize)
        {
                int read = fread(buffer + bytesRead, sizeof(uint8_t), fileSize - bytesRead, file);
                if (read < 0)
                {
                        printf("unable to read file (%s)\n", filePath);
                        fclose(file);
                        return -1;
                }
                bytesRead += read;
        }

        fclose(file);

        *bufferSize = bytesRead;

        return 0;
}


int writeFile(const char* filePath, uint8_t* buffer, size_t bufferSize)
{
        /* Open the file */
        FILE* file = fopen(filePath, "wb");

        if (file == NULL)
        {
                printf("file (%s) cannot be opened\n", filePath);
                return -1;
        }

        /* Write buffer to file */
        int bytesWriten = 0;
        uint8_t* ptr = buffer;
        while (bytesWriten < bufferSize)
        {
                int writen = fwrite(ptr, sizeof(uint8_t), bufferSize - bytesWriten, file);
                if (writen < 0)
                {
                        printf("unable to write file (%s)\n", filePath);
                        fclose(file);
                        return -1;
                }
                bytesWriten += writen;
                ptr += writen;
        }

        fclose(file);
}


int decodeKey(uint8_t* buffer, size_t* buffer_size, int* key_type)
{
        int ret = 0;
        DerBuffer* der = NULL;
        EncryptedInfo info;

        memset(&info, 0, sizeof(EncryptedInfo));

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer
         * object. */
        ret = PemToDer(buffer, *buffer_size, PRIVATEKEY_TYPE, &der, NULL, &info, key_type);

        /* Replace PEM data with DER data as we don't need the PEM anymore. As DER
         * encoded data is always smaller than PEM, we are sure that the buffer can
         * hold the DER data safely. */
        memcpy(buffer, der->buffer, der->length);
        *buffer_size = der->length;

        /* Free the DerBuffer object. */
        FreeDer(&der);

        return ret;
}


int loadPrivateKey(const char* filePath, PrivateKey* key)
{
        int ret = 0;
        int index = 0;

        printf("Loading private key from \"%s\"\n", filePath);

        key->size = sizeof(key->buffer);
        ret = readFile(filePath, key->buffer, &key->size);
        if (ret != 0)
        {
                printf("unable to read file %s\n", filePath);
                return -1;
        }
        printf("Successfully read %lu bytes \n", key->size);

        ret = decodeKey(key->buffer, &key->size, &key->type);
        if (ret != 0)
        {
                printf("unable to decode key\n");
                return -1;
        }

        if (key->type == RSAk)
        {
                printf("RSA key detected\n");

                ret = wc_InitRsaKey(&key->key.rsa, NULL);
                if (ret != 0)
                {
                        printf("unable to init RSA key\n");
                        return -1;
                }
                key->init = true;
                key->certKeyType = RSA_TYPE;
                index = 0;
                ret = wc_RsaPrivateKeyDecode(key->buffer, &index, &key->key.rsa, key->size);
                if (ret != 0)
                {
                        printf("unable to decode RSA key\n");
                        return -1;
                }
        }
        else if (key->type == ECDSAk)
        {
                printf("ECDSA key detected\n");

                ret = wc_ecc_init(&key->key.ecc);
                if (ret != 0)
                {
                        printf("unable to init ECC key\n");
                        return -1;
                }
                key->init = true;
                key->certKeyType = ECC_TYPE;
                index = 0;
                ret = wc_EccPrivateKeyDecode(key->buffer, &index, &key->key.ecc, key->size);
                if (ret != 0)
                {
                        printf("unable to decode ECC key\n");
                        return -1;
                }
        }
        else if ((key->type == DILITHIUM_LEVEL2k) || (key->type == DILITHIUM_LEVEL3k) ||
                (key->type == DILITHIUM_LEVEL5k))
        {
                printf("Dilithium key detected\n");

                wc_dilithium_init(&key->key.dilithium);
                if (ret != 0)
                {
                        printf("unable to init Dilithium key\n");
                        return -1;
                }
                key->init = true;

                switch (key->type)
                {
                case DILITHIUM_LEVEL2k:
                        key->certKeyType = DILITHIUM_LEVEL2_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, 2);
                        break;
                case DILITHIUM_LEVEL3k:
                        key->certKeyType = DILITHIUM_LEVEL3_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, 3);
                        break;
                case DILITHIUM_LEVEL5k:
                        key->certKeyType = DILITHIUM_LEVEL5_TYPE;
                        ret = wc_dilithium_set_level(&key->key.dilithium, 5);
                        break;
                default:
                        printf("unsupported key type %d\n", key->type);
                        ret = -1;
                        break;
                }
                if (ret < 0)
                {
                        printf("unable to set Dilithium level\n");
                        return -1;
                }
                index = 0;
                ret = wc_Dilithium_PrivateKeyDecode(key->buffer, &index,
                                &key->key.dilithium, key->size);
                if (ret != 0)
                {
                        printf("unable to decode Dilithium key\n");
                        return -1;
                }
        }
        else if ((key->type == FALCON_LEVEL1k) || (key->type == FALCON_LEVEL5k))
        {
                printf("Falcon key detected\n");

                wc_falcon_init(&key->key.falcon);
                if (ret != 0)
                {
                        printf("unable to init Falcon key\n");
                        return -1;
                }
                key->init = true;

                switch (key->type)
                {
                case FALCON_LEVEL1k:
                        key->certKeyType = FALCON_LEVEL1_TYPE;
                        ret = wc_falcon_set_level(&key->key.falcon, 1);
                        break;
                case FALCON_LEVEL5k:
                        key->certKeyType = FALCON_LEVEL5_TYPE;
                        ret = wc_falcon_set_level(&key->key.falcon, 5);
                        break;
                default:
                        printf("unsupported key type %d\n", key->type);
                        ret = -1;
                        break;
                }
                if (ret < 0)
                {
                        printf("unable to set Falcon level\n");
                        return -1;
                }
                index = 0;
                ret = wc_Falcon_PrivateKeyDecode(key->buffer, &index,
                                &key->key.falcon, key->size);
                if (ret != 0)
                {
                        printf("unable to decode Falcon key\n");
                        return -1;
                
                }
        }
        else
        {
                printf("unsupported key type %d\n", key->type);
                return -1;
        }
        
        printf("\n");

        return 0;
}


int loadIssuerCert(const char* filePath, IssuerCert* cert)
{
        int ret = 0;
        DerBuffer* der = NULL;
        EncryptedInfo info;

        memset(&info, 0, sizeof(EncryptedInfo));

        printf("Loading issuer certificate from \"%s\"\n", filePath);

        cert->size = sizeof(cert->buffer);
        ret = readFile(filePath, cert->buffer, &cert->size);
        if (ret != 0)
        {
                printf("unable to read file %s\n", filePath);
                return -1;
        }
        printf("Successfully read %lu bytes\n", cert->size);

        /* Convert PEM to DER. The result is stored in the newly allocated DerBuffer
         * object. */
        ret = PemToDer(cert->buffer, cert->size, CERT_TYPE, &der, NULL, &info, NULL);
        if (ret != 0)
        {
                printf("unable to convert PEM to DER\n");
                FreeDer(&der);
                return -1;
        }

        /* Replace PEM data with DER data as we don't need the PEM anymore. As DER
         * encoded data is always smaller than PEM, we are sure that the buffer can
         * hold the DER data safely. */
        memcpy(cert->buffer, der->buffer, der->length);
        cert->size = der->length;

        /* Free the DerBuffer object. */
        FreeDer(&der);

        cert->init = true;

        printf("Successfully decoded issuer certificate\n\n");

        return 0;
}


void freePrivateKey(PrivateKey* key)
{
        if (key->init)
        {
                switch (key->type)
                {
                case RSAk:
                        wc_FreeRsaKey(&key->key.rsa);
                        break;
                case ECDSAk:
                        wc_ecc_free(&key->key.ecc);
                        break;
                case DILITHIUM_LEVEL2k:
                case DILITHIUM_LEVEL3k:
                case DILITHIUM_LEVEL5k:
                        wc_dilithium_free(&key->key.dilithium);
                        break;
                case FALCON_LEVEL1k:
                case FALCON_LEVEL5k:
                        wc_falcon_free(&key->key.falcon);
                        break;
                }
        }
}


void freeOutputCert(OutputCert* outputCert)
{
        if (outputCert->preTbsInit)
        {
                wc_FreeDecodedCert(&outputCert->preTbs);
        }
}


int storeOutputCert(const char* filePath, OutputCert* outputCert)
{
        int ret = 0;

        outputCert->size2 = sizeof(outputCert->buffer2);

        printf("Converting the new certificate to PEM\n");
        
        ret = wc_DerToPem(outputCert->buffer1, outputCert->size1, outputCert->buffer2,
                          outputCert->size2, CERT_TYPE);
        if (ret > 0)
                outputCert->size2 = ret;
        else
        {
                printf("unable to convert DER to PEM\n");
                return -1;
        }

        printf("Writing newly generated certificate to file \"%s\"\n", filePath);
        
        ret = writeFile(filePath, outputCert->buffer2, outputCert->size2);
        if (ret != 0)
        {
                printf("unable to write file %s\n", filePath);
                return -1;
        }

        return 0;
}


static int getSigAlgForKey(PrivateKey* key)
{
        int sigAlg = 0;

        switch (key->type)
        {
        case RSAk:
                sigAlg = CTC_SHA256wRSA; /* ToDo */
                break;
        case ECDSAk:
        {
                switch (key->key.ecc.dp->size)
                {
                case 32:
                        sigAlg = CTC_SHA256wECDSA;
                        break;
                case 48:
                        sigAlg = CTC_SHA384wECDSA;
                        break;
                case 66:
                        sigAlg = CTC_SHA512wECDSA;
                        break;
                default:
                        printf("unsupported ECC curve size: %d\n",
                                key->key.ecc.dp->size);
                        sigAlg = -1;
                }
                break;
        }
        case DILITHIUM_LEVEL2k:
                sigAlg = CTC_DILITHIUM_LEVEL2;
                break;
        case DILITHIUM_LEVEL3k:
                sigAlg = CTC_DILITHIUM_LEVEL3;
                break;
        case DILITHIUM_LEVEL5k:
                sigAlg = CTC_DILITHIUM_LEVEL5;
                break;
        case FALCON_LEVEL1k:
                sigAlg = CTC_FALCON_LEVEL1;
                break;
        case FALCON_LEVEL5k:
                sigAlg = CTC_FALCON_LEVEL5;
                break;
        default:
                sigAlg = -1;
                break;
        }

        return sigAlg;
}


int genAltCertInfo(AltKeyData* altKeyData, PrivateKey* issuerAltKey, PrivateKey* ownAltKey)
{
        int ret = 0;

        if (ownAltKey->init == true)
        {
                /* Export the alternatvie public key for placement in the new certificate */
                printf("Exporting the alt public key\n");

                altKeyData->pubKeySize = sizeof(altKeyData->pubKeyBuffer);
                if (ownAltKey->type == RSAk)
                {
                        ret = wc_RsaKeyToPublicDer(&ownAltKey->key.rsa, altKeyData->pubKeyBuffer,
                                                   (word32)altKeyData->pubKeySize);
                }
                else if (ownAltKey->type == ECDSAk)
                {
                        ret = wc_EccPublicKeyToDer(&ownAltKey->key.ecc, altKeyData->pubKeyBuffer,
                                                   (word32)altKeyData->pubKeySize, 1);
                }
                else if ((ownAltKey->type == DILITHIUM_LEVEL2k) || (ownAltKey->type == DILITHIUM_LEVEL3k) ||
                        (ownAltKey->type == DILITHIUM_LEVEL5k))
                {
                        ret = wc_Dilithium_PublicKeyToDer(&ownAltKey->key.dilithium, altKeyData->pubKeyBuffer,
                                                          (word32)altKeyData->pubKeySize, 1);
                }
                else if ((ownAltKey->type == FALCON_LEVEL1k) || (ownAltKey->type == FALCON_LEVEL5k))
                {
                        ret = wc_Falcon_PublicKeyToDer(&ownAltKey->key.falcon, altKeyData->pubKeyBuffer,
                                                       (word32)altKeyData->pubKeySize, 1);
                }

                if (ret > 0)
                        altKeyData->pubKeySize = ret;
                else 
                {
                        printf("unable to export alternative public key\n");
                        return -1;
                }
        }
        else
        {
                /* We don't generate a hybrid certificate. Hence, we don't have to store
                 * an alternative public key. */
                altKeyData->pubKeySize = 0;
        }

        if (issuerAltKey->init == true)
        {
                printf("Generating the alternative signature algorithm info\n");

                altKeyData->sigAlgSize = sizeof(altKeyData->sigAlgBuffer);
                memset(altKeyData->sigAlgBuffer, 0, sizeof(altKeyData->sigAlgBuffer));

                altKeyData->sigAlgOID = getSigAlgForKey(issuerAltKey);
                if (altKeyData->sigAlgOID <= 0)
                {
                        printf("unable to get signature algorithm info\n");
                        return -1;
                }

                altKeyData->sigAlgSize = SetAlgoID(altKeyData->sigAlgOID,
                                                altKeyData->sigAlgBuffer,
                                                oidSigType, 0);
                if (altKeyData->sigAlgSize <= 0)
                {
                        printf("unable to set signature algorithm info\n");
                        return -1;
                }
        }
        else
        {
                /* We don't generate a hybrid certificate. Hence, we don't have to store
                 * an alternative signature algorithm. */
                altKeyData->sigAlgSize = 0;
        }

        return 0;
}


int prepareOutputCert(OutputCert* outputCert, PrivateKey* issuerKey, AltKeyData* altKeyData)
{
        int ret = 0;

        printf("Preparing the output certificate\n");

        wc_InitCert(&outputCert->cert);

        /* Set primary signature type */
        outputCert->cert.sigType = getSigAlgForKey(issuerKey);
        if (outputCert->cert.sigType <= 0)
        {
                printf("unable to get signature algorithm info\n");
                return -1;
        }

        /* Store the custom extension for the alternative public key (only when 
         * we generate a new hybrid certificate).
         */
        if (altKeyData->pubKeySize > 0)
        {
                ret = wc_SetCustomExtension(&outputCert->cert, 0, 
                                            SubjectAltPublicKeyInfoExtension,
                                            altKeyData->pubKeyBuffer,
                                            altKeyData->pubKeySize);
                if (ret < 0)
                {
                        printf("unable to set custom extension for PQC public key\n");
                        return -1;
                }
        }

        /* Store the custom extension for signature algorithm type (only when we
         * derive from a hybrid certificate).
         */
        if (altKeyData->sigAlgSize > 0)
        {
                ret = wc_SetCustomExtension(&outputCert->cert, 0,
                                            AltSignatureAlgorithmExtension,
                                            altKeyData->sigAlgBuffer,
                                            altKeyData->sigAlgSize);
                if (ret < 0)
                {
                        printf("unable to set custom extension for signature algorithm type\n");
                        return -1;
                }
        }

        return 0;
}


int finalizeOutputCert(OutputCert* outputCert, PrivateKey* issuerKey,
                       PrivateKey* issuerAltKey, PrivateKey* ownKey,
                       AltKeyData* altKeyData)
{
        int ret = 0;
        WC_RNG rng;

        /* Init RNG */
        ret = wc_InitRng(&rng);
        if (ret != 0)
        {
                printf("unable to init RNG\n");
                return -1;
        }
        
        outputCert->size1 = sizeof(outputCert->buffer1);
        memset(outputCert->buffer1, 0, outputCert->size1);
        
        /* Check if have to create the alternative signature */
        if (issuerAltKey->init == true)
        {
                outputCert->size2 = sizeof(outputCert->buffer2);
                memset(outputCert->buffer2, 0, outputCert->size2);
                altKeyData->sigSize = sizeof(altKeyData->sigBuffer);
                memset(altKeyData->sigBuffer, 0, altKeyData->sigSize);

                /* Generate a temporary cert to generate the TBS from it */
                ret = wc_MakeCert_ex(&outputCert->cert, outputCert->buffer1,
                                     outputCert->size1, ownKey->certKeyType,
                                     &ownKey->key, &rng);
                if (ret <= 0)
                {
                        printf("unable to make temporary certificate\n");
                        return -1;
                }

                /* Sign temporary cert. Only needed so wc_ParseCert() doesn't fail down below. */
                ret = wc_SignCert_ex(outputCert->cert.bodySz, outputCert->cert.sigType,
                                     outputCert->buffer1, outputCert->size1,
                                     issuerKey->certKeyType, &issuerKey->key, &rng);
                if (ret <= 0)
                {
                        printf("unable to sign temporary certificate\n");
                        return -1;
                }
                outputCert->size1 = ret;
                
                /* extract the TBS data for signing with alternative key */
                wc_InitDecodedCert(&outputCert->preTbs, outputCert->buffer1, outputCert->size1, 0);
                outputCert->preTbsInit = true;
                ret = wc_ParseCert(&outputCert->preTbs, CERT_TYPE, NO_VERIFY, NULL);
                if (ret < 0)
                {
                        printf("unable to parse temporary certificate\n");
                        return -1;
                }

                ret = wc_GeneratePreTBS(&outputCert->preTbs, outputCert->buffer2, outputCert->size2);
                if (ret < 0)
                {
                        printf("unable to generate PreTBS data\n");
                        return -1;
                }
                printf("PreTBS data is %d bytes.\n", ret);
                outputCert->size2 = ret;

                /* Generate the alternative signature. */
                ret = wc_MakeSigWithBitStr(altKeyData->sigBuffer, altKeyData->sigSize,
                                           altKeyData->sigAlgOID, outputCert->buffer2,
                                           outputCert->size2, issuerAltKey->certKeyType,
                                           &issuerAltKey->key, &rng);
                if (ret < 0)
                {
                        printf("unable to make alternative signature\n");
                        return -1;
                }
                altKeyData->sigSize = ret;
                printf("Alternative signature is %lu bytes.\n", altKeyData->sigSize);

                /* Store the alternative signature in the new certificate */
                ret = wc_SetCustomExtension(&outputCert->cert, 0, 
                                            AltSignatureValueExtension,
                                            altKeyData->sigBuffer,
                                            altKeyData->sigSize);
                if (ret < 0)
                {
                        printf("unable to set custom extension for alternative signature\n");
                        return -1;
                }
        }

        /* Finally, generate the final certificate. */
        outputCert->size1 = sizeof(outputCert->buffer1);
        ret = wc_MakeCert_ex(&outputCert->cert, outputCert->buffer1,
                             outputCert->size1, ownKey->certKeyType,
                             &ownKey->key, &rng);
        if (ret <= 0)
        {
                printf("unable to make final certificate\n");
                return -1;
        }

        /* Sign final certificate. */
        ret = wc_SignCert_ex(outputCert->cert.bodySz, outputCert->cert.sigType,
                             outputCert->buffer1, outputCert->size1,
                             issuerKey->certKeyType, &issuerKey->key, &rng);
        if (ret <= 0)
        {
                printf("unable to sign final certificate\n");
                return -1;
        }
        outputCert->size1 = ret;

        printf("Successfully created the new certificate\n\n");

        return 0;
}

