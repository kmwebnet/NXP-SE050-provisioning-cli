
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "mbedtls/base64.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef TGT_A71CH
#   include "sm_printf.h"
#endif

#if SSS_HAVE_ALT_SSS
#include "sss_mbedtls.h"
#endif

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>


#include "fsl_sss_api.h"

#define SIZE_PUBKEY 300
#define ECC_KEY_BIT_LEN 256
/*The size of the client certificate should be checked when script is used to store it in GP storage and updated here */
#define SIZE_CLIENT_CERTIFICATE 2048

#define B64_IS_EQUAL   (uint8_t)64
#define B64_IS_INVALID (uint8_t)0xFF

sss_status_t convert_pem_to_der(const unsigned char *pucInput,
    size_t xLen,
    unsigned char *pucOutput,
    size_t *pxOlen);

sss_status_t base64encode(
    const uint8_t*  data,         /**< [in] The input byte array that will be converted to base 64 encoded characters */
    size_t          data_size,    /**< [in] The length of the byte array */
    char*           encoded,      /**< [in] The output converted to base 64 encoded characters. */
    size_t*         encoded_size /**< [inout] Input: The size of the encoded buffer, Output: The length of the encoded base 64 character string */
    );

sss_status_t pkeyprovision(sss_object_t *keyObject, ex_sss_boot_ctx_t *pCtx, uint32_t keyId, char *pkeyresult);

sss_status_t writepemcert(sss_object_t *keyObject, ex_sss_boot_ctx_t *pCtx, uint32_t keyId, unsigned char *pemcert);

sss_status_t readuid(ex_sss_boot_ctx_t *pCtx, char *uidresult);