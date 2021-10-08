/**
 * @file mx_cert_mgmt_lib.c
 * @brief Moxa Certificate Management libraray
 * @copyright Copyright (C) MOXA Inc. All rights reserved.
 * @license This software is distributed under the terms of the MOXA License. See the file COPYING-MOXA for details.
 * @author Joy Tu
 * @date 2021-0928
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sysexits.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
 #include <sys/ioctl.h>/* FIONREAD */
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/sockios.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <def/mx_def.h>
 /*****************************************************************************
 * Definition
 ****************************************************************************/
#define DEBUG_MX_CERT_MGMT
#ifdef DEBUG_MX_CERT_MGMT
#define dbg_printf  printf
#else
#define dbg_printf(...) 
#endif
#define CERT_ENDENTITY_PEM_PATH "endentity.pem" 
#define SSL_CERT_IMPORT_FLAG "import"
#define D_SSL_CHECK_CERT    0x00000001L
#define D_SSL_CHECK_KEY     0x00000002L
#define SSL_FILETYPE_ASN1	X509_FILETYPE_ASN1
#define SSL_FILETYPE_PEM	X509_FILETYPE_PEM
/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/
/**
 * @brief
 *
 * @param argc
 * @param argv[]
 *
 * @return
 */

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/


/*****************************************************************************
 * Private functions
 ****************************************************************************/

/*****************************************************************************
 * Public functions
 ****************************************************************************/
/**
 * @brief
 *
 * @param 
 * @param
 * @param
 *
 * @return
 */

int test_func(int a)
{
    char cmd[512];
    sprintf(cmd, "openssl genrsa -out %s %d", 
                    "ass.cert",
                    2048);
    system(cmd);
    SSL_load_error_strings();
    printf("Joy %s-%d, a = %d\r\n", __func__, __LINE__, a);
}

/**
 * @brief
 *
 * @param 
 * @param
 * @param
 *
 * @return
 */
static int checkCert(char *cert_file, char* key_file, int flag, char* errorStr, int errlen)
{
    SSL_CTX *ctx;
    int ret;

    if (cert_file == NULL)
        return 0;
    if (key_file == NULL)
        key_file = cert_file;

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        dbg_printf("SSL_CTX_new() failed\r\n");
        return -1;  /* lack of resource */
    }
    ret = 0;

    if (flag & D_SSL_CHECK_CERT) {
        if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
            snprintf(errorStr, errlen, "SSL: Unable to set certificate file (%s)\n", cert_file);
            ret = -2;
            goto end;
        }
    }
    if (flag & D_SSL_CHECK_KEY) {
		//char key_buf[64];
		//Scf_getPrivate_key_passwd(0, key_buf);
		//ctx->default_passwd_callback_userdata = key_buf;
		//printf("ctx->default_passwd_callback : %p, ctx->default_passwd_callback_userdata : %p [%s]\n", ctx->default_passwd_callback, ctx->default_passwd_callback_userdata, (char *)ctx->default_passwd_callback_userdata);
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
            snprintf(errorStr, errlen, "SSL: Unable to set private file (%s)\n", cert_file);
            ret = -3;
            goto end;
        }
        if (!SSL_CTX_check_private_key(ctx)) {
            snprintf(errorStr, errlen, "Private key does not match the certificate public key\n");
            ret = -4;
            goto end;
        }
    }

end:
    SSL_CTX_free(ctx);
    return ret;
}

 
/**
 * @brief check import SSL cert file format, and save to flash.
 *
 * @param 
 * @param
 * @param
 *
 * @return
 */

int checkAndSetCertFile(char* file, int len, char *errStr, int errlen)
{
    char *fname, cmd[512];
    FILE *fp;
    int ret;
    int flag;
    char *certFile=NULL;
    char *keyFile=NULL;
    const char*tmpFile = "/var/tmp.pem";

    flag = D_SSL_CHECK_CERT | D_SSL_CHECK_KEY;
    fname = CERT_ENDENTITY_PEM_PATH;
    remove(tmpFile);

    sprintf(cmd, "echo \"%s\" > %s", SSL_CERT_IMPORT_FLAG, tmpFile);
    system(cmd);
    fp = fopen(tmpFile, "a");
    
    if (fp == NULL)
        return -2;

    ret = fwrite(file, 1, len, fp);
    if( ret != len) {
        ret = -3;
        goto error;
    }
    fclose(fp);
    fp = NULL;

    certFile = (char*)tmpFile;
    keyFile = (char*)tmpFile;

    ret = checkCert(certFile, keyFile, flag, errStr, errlen);    
    if (ret < 0) {
        ret -= 10;
        goto error;
    }
    // save
    sprintf(cmd, "mv %s %s", tmpFile, fname);
    system(cmd);

    // sys_send_events(EVENT_ID_SSLIMPORT, 0); 
error:
    if (fp)
        fclose(fp);

    remove(tmpFile);
    return ret;
}

