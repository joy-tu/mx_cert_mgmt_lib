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
#include "mx_cert_mgmt_lib.h"
 /*****************************************************************************
 * Definition
 ****************************************************************************/
#define DEBUG_MX_CERT_MGMT
#ifdef DEBUG_MX_CERT_MGMT
#define dbg_printf  printf
#else
#define dbg_printf(...) 
#endif
#define SSL_CERT_IMPORT_FLAG "import"
#define D_SSL_CHECK_CERT    0x00000001L
#define D_SSL_CHECK_KEY     0x00000002L
#define SSL_FILETYPE_ASN1	X509_FILETYPE_ASN1
#define SSL_FILETYPE_PEM	X509_FILETYPE_PEM
/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/
static int checkCert(char *cert_file, char* key_file, int flag, char* errorStr, int errlen);
static int check_cert_type(char *pem);

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/


/*****************************************************************************
 * Private functions
 ****************************************************************************/
/**
 * @brief:  Check the type of cerificate file.
 *
 * @param 
 *
 * @return type of certificate
 */
static int check_cert_type(char *pem)
{
    FILE *fp;
    char import_flag[128];

    fp = fopen(pem, "r");

    if (fp != NULL) {
        fgets(import_flag, sizeof(import_flag), fp);
        fclose(fp);

        if (!strncmp(import_flag, SSL_CERT_IMPORT_FLAG, strlen(SSL_CERT_IMPORT_FLAG))) {
            return CERT_TYPE_IMPORT;
        } else
            return CERT_TYPE_SELFGEN;
    }
    else
        return CERT_TYPE_SELFGEN;
}
/**
 * @brief:  Check the validate of cerificate file.
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
/*****************************************************************************
 * Public functions
 ****************************************************************************/
/**
 * @brief: Test function
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
    printf("%s-%d, a = %d\r\n", __func__, __LINE__, a);
}
/**
 * @brief: Delete the SSL cert file.
 * @param fname: The location of certificate you wanna delete.
 * @return
 */
int mx_cert_del(char *fname/*int cert_idx*/)
{	
    int ret;

    ret = check_cert_type(fname);
    if (ret == CERT_TYPE_IMPORT) {
        dbg_printf("Delete User's Import PEM\r\n");
        unlink(fname);
        return 1;
    } else {
        return -1;
    }
}
/**
 * @brief: Query the type of SSL cert file.
 * @param fname: The location of certificate you wanna query.
 * @return
 */
int mx_tell_cert_type(char *fname)
{
    return check_cert_type(fname);
}
/**
 * @brief: Check the SSL cert file format which is being imported,
               and save the certificate file to the flash.
 * @param fname: The location of certificate you wanna import.
 * @param data: The raw data of cert-file you wanna import.
 * @param len: The lenght of cert-file you wanna import.
 * @param errStr: 
 * @param errlen:
 
 * @return
 */

/* checkAndSetCertFile */
int mx_import_cert(char * fname, char* data, int len, char *errStr, int errlen)
{
    char cmd[512];
    FILE *fp;
    int ret;
    int flag;
    char *certFile=NULL;
    char *keyFile=NULL;
    const char*tmpFile = "/var/tmp.pem";

    flag = D_SSL_CHECK_CERT | D_SSL_CHECK_KEY;
    remove(tmpFile);

    sprintf(cmd, "echo \"%s\" > %s", SSL_CERT_IMPORT_FLAG, tmpFile);
    system(cmd);
    fp = fopen(tmpFile, "a");
    
    if (fp == NULL)
        return -2;

    ret = fwrite(data, 1, len, fp);
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
/**
 * @brief: Re-generate end entity certificate for HTTPS(web)
 *
 * @param

 
 * @return
 */
int mx_regen_cert(void)
{
    int ret;       
    unsigned long ip;
    char active_ip[32] = {0};
    struct sockaddr_in addr_in;

    ret = check_cert_type(CERT_ENDENTITY_PEM_PATH);
    if (ret == CERT_TYPE_IMPORT)
        return -1; /* The certificate device is using is imported by customer */

    printf("Re-generating the self-signed certificate\r\n");

    net_get_my_ip_by_ifname("eth0", &ip);
    addr_in.sin_addr.s_addr = ip;
    strcpy(active_ip, inet_ntoa(addr_in.sin_addr));
    
    mx_cert_gen_priv_key(CERT_ENDENTITY_KEY_PATH, CERT_ENDENTITY_KEY_LENGTH);
    mx_cert_gen_csr(CERT_ENDENTITY_KEY_PATH, CERT_ENDENTITY_CSR_PATH);
    mx_cert_sign_cert(
            CERT_ENDENTITY_CSR_PATH,
            CERT_ROOTCA_CERT_PATH,
            CERT_ROOTCA_KEY_PATH,
            CERT_ENDENTITY_VALID_DAY,
            CERT_ENDENTITY_CERT_PATH);
    ret = mx_cert_combine_ip_key_cert(CERT_ENDENTITY_PEM_PATH,
            active_ip,
            CERT_ENDENTITY_KEY_PATH,
            CERT_ENDENTITY_CERT_PATH); 
    if (!ret)
        return -1;    
}

int mx_cert_combine_ip_key_cert(char *pem_path,
                                                            char *ip,
                                                            char *key_path,
                                                            char *cert_path)
{
    struct sockaddr_in addr_in;
    FILE *fpw, *fpr;
    char active_ip[32] = {0};
    char *buf;
    int file_len;
    /* open file for PEM format IP/private key/ certficate */
    fpw = fopen(pem_path, "w+");

    /* append active ip */
    fwrite(ip, strlen(ip), 1, fpw);
    fwrite("\n", 1, 1, fpw);

    /* read .key and copy to .pem */
    fpr = fopen(key_path, "r");
    if (fpr == NULL)
        return 0;
    fseek(fpr, 0L, SEEK_END);
    file_len = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);	
    buf = (char*)calloc(file_len, sizeof(char));	
    if (buf == NULL)
        return 0;
    fread(buf, sizeof(char), file_len, fpr);
    fclose(fpr);
    fwrite(buf, file_len, 1, fpw);

    /* read .cert and copy to .pem */
    fpr = fopen(cert_path, "r");
    if (fpr == NULL)
        return 0;
    fseek(fpr, 0L, SEEK_END);
    file_len = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);	
    buf = (char*)calloc(file_len, sizeof(char));	
    if (buf == NULL)
        return 0;
    fread(buf, sizeof(char), file_len, fpr);
    fclose(fpr);
    fwrite(buf, file_len, 1, fpw);    
    fclose(fpw);

    return 1;
}

void mx_cert_gen_priv_key(char *path, int len)
{
    char cmd[512];
    
    sprintf(cmd, "openssl genrsa -out %s %d", 
                path,
                len);
                
    system(cmd);   
}

void mx_cert_gen_csr(char *keypath, char *csrpath)
{
    char cmd[512];

    sprintf(cmd, "openssl req -sha256 -new -key %s -out \ 
                       %s \
                       -subj /C=TW/ST=Taiwan/L=Taipei/O=Moxa/OU=MGate/CN=\"10.123.6.32\"/emailAddress=taiwan@moxa.com",
                       keypath,
                       csrpath);
    system(cmd);
}

void mx_cert_sign_cert(char *csr_path, char *rootcert_path, char *rootkey_path,
                                        int valid_day, char *cert_path)
{
    char cmd[512];

    sprintf(cmd, "openssl x509 -req -in %s -CA %s \
                  -CAkey %s -CAserial ca.serial -CAcreateserial \
                  -days %d -out %s",
                  csr_path,
                  rootcert_path,
                  rootkey_path,
                  valid_day,
                  cert_path);
    system(cmd);  
}

