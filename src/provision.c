#include "provision.h"







/* @brief Converts PEM documents into DER formatted byte arrays.
 * This is a helper function from mbedTLS util pem2der.c
 * (https://github.com/ARMmbed/mbedtls/blob/development/programs/util/pem2der.c#L75)
 *
 * \param pucInput[in]       Pointer to PEM object
 * \param xLen[in]           Length of PEM object
 * \param pucOutput[out]     Pointer to buffer where DER oboject will be placed
 * \param pxOlen[in/out]     Pointer to length of DER buffer.  This value is updated
 *                          to contain the actual length of the converted DER object.
 *
 * \return kStatus_SSS_Success if successful.  kStatus_SSS_Fail if conversion failed.  If buffer is not
 * large enough to hold converted object, pxOlen is still updated but kStatus_SSS_InvalidArgument is returned.
 *
 */
sss_status_t convert_pem_to_der(const unsigned char *pucInput,
    size_t xLen,
    unsigned char *pucOutput,
    size_t *pxOlen)
{
    int lRet;
    const unsigned char *pucS1;
    const unsigned char *pucS2;
    const unsigned char *pucEnd = pucInput + xLen;
    size_t xOtherLen = 0;

    pucS1 = (unsigned char *)strstr((const char *)pucInput, "-----BEGIN");

    if (pucS1 == NULL) {
        return kStatus_SSS_Fail;
    }

    pucS2 = (unsigned char *)strstr((const char *)pucInput, "-----END");

    if (pucS2 == NULL) {
        return kStatus_SSS_Fail;
    }

    pucS1 += 10;

    while (pucS1 < pucEnd && *pucS1 != '-') {
        pucS1++;
    }

    while (pucS1 < pucEnd && *pucS1 == '-') {
        pucS1++;
    }

    if (*pucS1 == '\r') {
        pucS1++;
    }

    if (*pucS1 == '\n') {
        pucS1++;
    }

    if ((pucS2 <= pucS1) || (pucS2 > pucEnd)) {
        return kStatus_SSS_Fail;
    }

    lRet = mbedtls_base64_decode(
        NULL, 0, &xOtherLen, (const unsigned char *)pucS1, pucS2 - pucS1);

    if (lRet == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        return (lRet);
    }

    if (xOtherLen > *pxOlen) {
        return kStatus_SSS_InvalidArgument;
    }

    if ((lRet = mbedtls_base64_decode(pucOutput,
             xOtherLen,
             &xOtherLen,
             (const unsigned char *)pucS1,
             pucS2 - pucS1)) != 0) {
        return (lRet);
    }

    *pxOlen = xOtherLen;

    return kStatus_SSS_Success;
}





/**
 * \brief Returns the base 64 character of the given index.
 * \param[in] id     index to check
 * \param[in] rules  base64 ruleset to use
 * \return the base 64 character of the given index
 */
char base64Char(uint8_t id, const uint8_t * rules)
{
    if (id < 26)
    {
        return (char)('A' + id);
    }
    if ((id >= 26) && (id < 52))
    {
        return (char)('a' + id - 26);
    }
    if ((id >= 52) && (id < 62))
    {
        return (char)('0' + id - 52);
    }
    if (id == 62)
    {
        return rules[0];
    }
    if (id == 63)
    {
        return rules[1];
    }

    if (id == B64_IS_EQUAL)
    {
        return rules[2];
    }
    return B64_IS_INVALID;
}


/** \brief Encode data as base64 string with ruleset option. */
sss_status_t base64encode(
    const uint8_t*  data,         /**< [in] The input byte array that will be converted to base 64 encoded characters */
    size_t          data_size,    /**< [in] The length of the byte array */
    char*           encoded,      /**< [in] The output converted to base 64 encoded characters. */
    size_t*         encoded_size /**< [inout] Input: The size of the encoded buffer, Output: The length of the encoded base 64 character string */
    )
{
    sss_status_t status = kStatus_SSS_Success;
    size_t data_idx = 0;
    size_t b64_idx = 0;
    size_t offset = 0;
    uint8_t id = 0;
    size_t b64_len;
    uint8_t rules[4]   = { '+', '/', '=', 64 };


    do
    {
        // Check the input parameters
        if (encoded == NULL || data == NULL || encoded_size == NULL )
        {
            status = kStatus_SSS_InvalidArgument;
            printf( "Null input parameter:%d", status);
        }

        // Calculate output length for buffer size check
        b64_len = (data_size / 3 + (data_size % 3 != 0)) * 4; // ceil(size/3)*4
        if (rules[3])
        {
            // We add newlines to the output
            if (rules[3] % 4 != 0)
            {
                status = kStatus_SSS_InvalidArgument;
                printf( "newline rules[3] must be multiple of 4:%d", status);
            }
            b64_len += (b64_len / rules[3]) * 2;
        }
        b64_len += 1; // terminating null
        if (*encoded_size < b64_len)
        {
            status = kStatus_SSS_Fail;
            printf( "Length of encoded buffer too small:%d",status);
        }
        // Initialize the return length to 0
        *encoded_size = 0;

        // Loop through the byte array by 3 then map to 4 base 64 encoded characters
        for (data_idx = 0; data_idx < data_size; data_idx += 3)
        {
            // Add \r\n every n bytes if specified
            if (rules[3] && data_idx > 0 && (b64_idx - offset) % rules[3] == 0)
            {
                // as soon as we do this, we introduce an offset
                encoded[b64_idx++] = '\r';
                encoded[b64_idx++] = '\n';
                offset += 2;
            }

            id = (data[data_idx] & 0xFC) >> 2;
            encoded[b64_idx++] = base64Char(id, rules);
            id = (data[data_idx] & 0x03) << 4;
            if (data_idx + 1 < data_size)
            {
                id |= (data[data_idx + 1] & 0xF0) >> 4;
                encoded[b64_idx++] = base64Char(id, rules);
                id = (data[data_idx + 1] & 0x0F) << 2;
                if (data_idx + 2 < data_size)
                {
                    id |= (data[data_idx + 2] & 0xC0) >> 6;
                    encoded[b64_idx++] = base64Char(id, rules);
                    id = data[data_idx + 2] & 0x3F;
                    encoded[b64_idx++] = base64Char(id, rules);
                }
                else
                {
                    encoded[b64_idx++] = base64Char(id, rules);
                    encoded[b64_idx++] = base64Char(B64_IS_EQUAL, rules);
                }
            }
            else
            {
                encoded[b64_idx++] = base64Char(id, rules);
                encoded[b64_idx++] = base64Char(B64_IS_EQUAL, rules);
                encoded[b64_idx++] = base64Char(B64_IS_EQUAL, rules);
            }
        }

        // Strip any trailing nulls
        while (b64_idx > 1 && encoded[b64_idx - 1] == 0)
        {
            b64_idx--;
        }

        // Null terminate end
        encoded[b64_idx++] = 0;

        // Set the final encoded length (excluding terminating null)
        *encoded_size = b64_idx - 1;
    }
    while (false);
    return status;
}



sss_status_t pkeyprovision(sss_object_t *keyObject, ex_sss_boot_ctx_t *pCtx, uint32_t keyId, char *pkeyresult)
{

    int ret = 0;
    uint8_t pubkey[SIZE_PUBKEY] = {0};

    uint8_t buf[4000];
    size_t buf_len = sizeof(buf);

    size_t keyBitLen = ECC_KEY_BIT_LEN;
    size_t keyLen = keyBitLen * 8;
    sss_key_part_t keyPart = kSSS_KeyPart_Pair;
    sss_cipher_type_t cipherType = kSSS_CipherType_EC_NIST_P;

    smStatus_t retStatus = SM_NOT_OK;

    sss_status_t status;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;

    smStatus_t sw_status;
    SE05x_Result_t result = kSE05x_Result_NA;

    sw_status = Se05x_API_CheckObjectExists(
        &pSession->s_ctx, keyId, &result);
    if (SM_OK != sw_status) {
        LOG_E("Failed Se05x_API_CheckObjectExists");
        return kStatus_SSS_Fail;
    }

    if (result != kSE05x_Result_SUCCESS)
    {

    /* doc+:initialize-key-objs */
        status = sss_key_object_init(keyObject, &pCtx->ks);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_init for keyPair Failed...\n");
            return kStatus_SSS_Fail;
        }

        retStatus = Se05x_API_DeleteSecureObject(&pSession->s_ctx, keyId);
        if (retStatus != SM_OK) {
            LOG_W("Error in erasing ObjId=0x%08X (Others)", keyId);
        }


        status = sss_key_object_allocate_handle(
            keyObject, keyId,
            keyPart,
            cipherType, keyLen,
            kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_allocate_handle  for keyPair Failed...\ntrying to get_handle\n");
            return kStatus_SSS_Fail;
        }

        status = sss_key_store_generate_key(
            &pCtx->ks,keyObject,
            keyBitLen,
            NULL);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_store_generate_keypair Failed...skipping\n");
        }

        status = sss_key_store_save(
            &pCtx->ks);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_store_save Failed...skipping\n");
        }

    /* free */
            sss_key_object_free(keyObject);
    }

        status = sss_key_object_init(keyObject, &pCtx->ks);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_init for Pub key Failed...\n");
            return kStatus_SSS_Fail;
        }

        status = sss_key_object_get_handle(
            keyObject, keyId);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_get_handle  for keyPair Failed...\ntrying to get_handle\n");
            return kStatus_SSS_Fail;
        }

            /* doc+:load-certificate-from-se */
            size_t KeyBitLen = SIZE_PUBKEY * 8;
            size_t KeyByteLen = SIZE_PUBKEY;

        status = sss_key_store_get_key(
            &pCtx->ks, keyObject, pubkey, &KeyByteLen, &KeyBitLen);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_store_get_key for extPubkey Failed...%d\n",status);
            return kStatus_SSS_Fail;
        }
    buf_len = sizeof(buf);
    memset (buf ,0 , buf_len);

    /* Convert to base 64 */
    base64encode(pubkey, (pubkey[1] + 2), (char *)buf, &buf_len);

    /* Add a null terminator */
    buf[buf_len] = 0;

    /* Print out the pubkey */
    sprintf(pkeyresult, "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", buf);


    if (ret < 0)
        ret = kStatus_SSS_Fail;

    return kStatus_SSS_Success;
}


sss_status_t writepemcert(sss_object_t *keyObject, ex_sss_boot_ctx_t *pCtx, uint32_t keyId, unsigned char *pemcert)
{

    int ret = 0;
    uint8_t certbuf[SIZE_CLIENT_CERTIFICATE] = {0};

    uint8_t buf[4000];
    size_t buf_len = sizeof(buf);

    unsigned char cert[2000];
    size_t cert_len = sizeof(cert);

    sss_key_part_t keyPart = kSSS_KeyPart_Default;
    sss_cipher_type_t cipherType = kSSS_CipherType_Binary;


        sss_status_t status;
        smStatus_t retStatus = SM_NOT_OK;

    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;

        status = convert_pem_to_der(pemcert,
        strlen((const char *)pemcert), cert,
        &cert_len);
        if (status != kStatus_SSS_Success) {
            printf(" convert_pem_to_der Failed...%d\n", status);
            return kStatus_SSS_Fail;
        }

        /* doc+:initialize-key-objs */

        /* pex_sss_demo_tls_ctx->obj will have the private key handle */
        status = sss_key_object_init(keyObject, &pCtx->ks);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_init for device certificate Failed...\n");
            return kStatus_SSS_Fail;
        }

        retStatus = Se05x_API_DeleteSecureObject(&pSession->s_ctx, keyId);
        if (retStatus != SM_OK) {
            LOG_W("Error in erasing ObjId=0x%08X (Others)", keyId);
        }


        status = sss_key_object_allocate_handle(
            keyObject, keyId,
            keyPart,
            cipherType, cert_len,
            kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_allocate_handle  for device certificate Failed...\ntrying to get_handle\n");
            return kStatus_SSS_Fail;
        }

        status = sss_key_store_set_key(
            &pCtx->ks,keyObject,
            cert,
            cert_len,
            cert_len *8 ,
            NULL,0);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_store_set_device_cert Failed...skipping\n");
        }


        /* free */
        sss_key_object_free(keyObject);



        /* pex_sss_demo_tls_ctx->pub_obj will have the private key handle */
        status = sss_key_object_init(keyObject, &pCtx->ks);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_init for device certificate Failed...\n");
            return kStatus_SSS_Fail;
        }

        status = sss_key_object_get_handle(
            keyObject, keyId);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_object_get_handle  for device certificate Failed...\ntrying to get_handle\n");
            return kStatus_SSS_Fail;
        }


            /* doc+:load-certificate-from-se */
            size_t KeyBitLen = sizeof(certbuf) * 8;
            size_t KeyByteLen = sizeof(certbuf);

        status = sss_key_store_get_key(
            &pCtx->ks, keyObject, certbuf, &KeyByteLen, &KeyBitLen);
        if (status != kStatus_SSS_Success) {
            printf(" sss_key_store_get_key for device certificate Failed...%d\n",status);
            return kStatus_SSS_Fail;
        }



    buf_len = sizeof(buf);
    memset (buf ,0 , buf_len);



    /* Convert to base 64 */
    base64encode(certbuf, (certbuf[2] * 256  + certbuf[3] + 4), (char *)buf, &buf_len);


    /* Add a null terminator */
    buf[buf_len] = 0;

    printf("device cert object ID: %08x\n", keyId);


    /* Print out the device cert */
    printf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", buf);


    if (ret < 0)
        ret = kStatus_SSS_Fail;

    return kStatus_SSS_Success;
}


sss_status_t readuid(ex_sss_boot_ctx_t *pCtx, char *uidresult)
{

    sss_status_t status;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;

    uint8_t buf[4000];
    size_t buf_len = sizeof(buf);

    smStatus_t sw_status;
    SE05x_Result_t result = kSE05x_Result_NA;

    sw_status = Se05x_API_CheckObjectExists(
        &pSession->s_ctx, kSE05x_AppletResID_UNIQUE_ID, &result);
    if (SM_OK != sw_status) {
        LOG_E("Failed Se05x_API_CheckObjectExists");
        return kStatus_SSS_Fail;
    }
    uint8_t uid[SE050_MODULE_UNIQUE_ID_LEN];
    size_t uidLen = sizeof(uid);
    sw_status = Se05x_API_ReadObject(&pSession->s_ctx,
        kSE05x_AppletResID_UNIQUE_ID,
        0,
        (uint16_t)uidLen,
        uid,
        &uidLen);
    if (SM_OK != sw_status) {
        LOG_E("Failed Se05x_API_CheckObjectExists");
        return kStatus_SSS_Fail;
    }
    status = kStatus_SSS_Success;

    buf_len = sizeof(buf);
    memset (buf ,0 , buf_len);

    /* Convert to base 64 */
    base64encode(uid, uidLen, (char *)buf, &buf_len);

    /* Add a null terminator */
    buf[buf_len] = 0;

    /* Print out the UID */
    //sprintf(uidresult, "-----BEGIN UID-----\n%s\n-----END UID-----\n", buf);
    sprintf(uidresult, "%s", buf);

    return status;
}
