/**
 * @file mx_cert_mgmt_lib.c
 * @brief Moxa Certificate Management libraray
 * @copyright Copyright (C) MOXA Inc. All rights reserved.
 * @license This software is distributed under the terms of the MOXA License. See the file COPYING-MOXA for details.
 * @author Joy Tu
 * @date 2021-10-06
 */ 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include<dirent.h>  
#include <getopt.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
 #include <sys/ioctl.h>/* FIONREAD */
#include <arpa/inet.h>
#include <netdb.h>
#include <def/mx_def.h>
//#include <../include/mx_cert_mgmt/mx_cert_mgmt_rest.h>
#include <mx_cert_mgmt/conf.h>
#if __ZEPHYR__
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include "mbedtls/md.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/md.h"
#include "mx_mbed.h"
#include <entropy_poll.h>
#else   /* Linux */
#include <linux/sockios.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/ts.h>
#endif
#if USE_MX_NET
#include<mx_net/mx_net.h>
#endif
#include "mx_cert_mgmt_lib.h"
#include "mx_cert_mgmt_event.h"
//#include <mx_platform.h>
 /*****************************************************************************
 * Definition
 ****************************************************************************/
//#define DEBUG_MX_CERT_MGMT
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

#define AES_CRYPT_BITS    128
#define AES_CRYPT_BYTES   (AES_CRYPT_BITS / 8)

#define SHA256LEN                  32
#define SEEDLEN                       16
#define MACLEN                          6
#define CERT_LEN    4096
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
char Gseed[16] = {33, 40, 12, 99, 22, 44, 23, 49,
                            122, 112, 60, 21, 6, 57, 72, 103};

static int do_fake_get_mac(unsigned char *mac)
{
#if USE_MX_NET
    char mac_str[18];

    if (net_get_my_mac(0, mac_str, sizeof(mac_str)) != MX_NET_OK)
    {
        memset(mac, 0, MACLEN);
        return -1;
    }
    sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
        &mac[0],
        &mac[1],
        &mac[2],
        &mac[3],
        &mac[4],
        &mac[5]);
#if 0
    mac[0] = 0x00;
    mac[1] = 0x90;
    mac[2] = 0xe8;
    mac[3] = 0x12;
    mac[4] = 0x34;
    mac[5] = 0x56;
#endif
#endif
    return 1;
}

static int do_fate_get_seed(unsigned char *seed)
{
    FILE *fpr;
    char *data, tmp[16];
    int filelen, i;
    char *token;

    fpr = fopen(CERT_SEED_PATH, "r");
    if (fpr == NULL)
        return -1;
    fseek(fpr, 0L, SEEK_END);
    filelen = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);
    data = (char*)calloc(filelen, sizeof(char));
    if (data == NULL) {
        fclose(fpr);
        return -1;
    }
    fread(data, sizeof(char), filelen, fpr);
    fclose(fpr);

    token = strtok(data, ",");
    i = 0;
    tmp[i] = atoi(token);
    i++;
    while (i < 16) {
        token = strtok(NULL, ",");
        tmp[i] = atoi(token);
        i++;
    }
    memcpy(seed, tmp, 16);

    free(data);
    return 1;
}

static int do_fake_get_serial_num(unsigned char *ser_no){
    *ser_no = 1;

    return 0;
}
#if __linux__
static int _ASN1_GENERALIZEDTIME_print(char *buf, ASN1_GENERALIZEDTIME *tm)
{
    char *v;
    int i;
    int y = 0, M = 0, d = 0;

    i = tm->length;
    v = (char *)tm->data;

    if(i < 12) goto err;
    for(i = 0; i < 12; i++)
        if((v[i] > '9') || (v[i] < '0')) goto err;
    y = (v[0] - '0') * 1000 + (v[1] - '0') * 100 + (v[2] - '0') * 10 + (v[3] - '0');
    M = (v[4] - '0') * 10 + (v[5] - '0');
    if((M > 12) || (M < 1)) goto err;
    d = (v[6] - '0') * 10 + (v[7] - '0');

    sprintf(buf, "%d-%d-%d", y, M, d);
    return(1);
err:
    sprintf(buf, " ");  /* Bad time value */
    return(0);
}

static int _ASN1_UTCTIME_print(char *buf, ASN1_UTCTIME *tm)
{
    char *v;
    int i;
    int y = 0, M = 0, d = 0;

    i = tm->length;
    v = (char *)tm->data;

    if(i < 10) goto err;
    for(i = 0; i < 10; i++)
        if((v[i] > '9') || (v[i] < '0')) goto err;
    y = (v[0] - '0') * 10 + (v[1] - '0');
    if(y < 50) y += 100;
    M = (v[2] - '0') * 10 + (v[3] - '0');
    if((M > 12) || (M < 1)) goto err;
    d = (v[4] - '0') * 10 + (v[5] - '0');

    sprintf(buf, "%d-%d-%d", y + 1900, M, d);
    return(1);
err:
    sprintf(buf, " ");  /* Bad time value */
    return(0);
}
static int _ASN1_TIME_print(char *buf, ASN1_TIME *tm)
{
    if(tm->type == V_ASN1_UTCTIME)
        return _ASN1_UTCTIME_print(buf, tm);
    if(tm->type == V_ASN1_GENERALIZEDTIME)
        return _ASN1_GENERALIZEDTIME_print(buf, tm);
    sprintf(buf, " ");  /* Bad time value */
    return(0);
}
#endif /* __LINUX */
static int remove_padding(unsigned char *buf)
{
    int ret, i;

    ret = 0;

    for (i = 0; i < AES_CRYPT_BYTES; i++) {
        if (buf[i] != '\0')
            ret++;
    }
    return ret;
}
static int do_decry_b(char *certpath, unsigned char *sha256, unsigned char *cert_ram)
{
#if __linux__
    char *data;
    FILE *fpr;
    int filelen, i;
    unsigned char dec_out[AES_CRYPT_BYTES];
    AES_KEY dec_key;

    AES_set_decrypt_key(sha256, AES_CRYPT_BITS, &dec_key);

    fpr = fopen(CERT_ENDENTITY_PEM_PATH, "r");
    fseek(fpr, 0L, SEEK_END);
    filelen = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);
    data = (char*)calloc(filelen, sizeof(char));
    if (data == NULL)
    {
        fclose(fpr);
        return -1;
    }
    fread(data, sizeof(char), filelen, fpr);
    fclose(fpr);

    for (i = 0; i < filelen; i+=AES_CRYPT_BYTES) {
        AES_decrypt((unsigned char*)&data[i], dec_out, &dec_key);
        memcpy(&cert_ram[i], dec_out, AES_CRYPT_BYTES);
    }
    free(data);
    return 0;
#endif /* __LINUX__ */    
}

static int do_decry_f(char *certpath, unsigned char *sha256)
{
#if __linux__
    char *data;
    FILE *fpr, *fpd;
    int filelen, i;
    unsigned char dec_out[AES_CRYPT_BYTES];
    AES_KEY dec_key;

    AES_set_decrypt_key(sha256, AES_CRYPT_BITS, &dec_key);

    fpr = fopen(CERT_ENDENTITY_PEM_PATH, "r");
    if (fpr == NULL)
        return -1;
    fseek(fpr, 0L, SEEK_END);
    filelen = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);
    data = (char*)calloc(filelen, sizeof(char));
    if (data == NULL)
    {
        fclose(fpr);
        return -1;
    }
    fread(data, sizeof(char), filelen, fpr);
    fclose(fpr);
    fpd = fopen(CERT_ENDENTITY_TMP_PATH, "w+");
    if (fpd == NULL)
    {
        free(data);
        return -1;
    }
    for (i = 0; i < filelen; i+=AES_CRYPT_BYTES) {
        AES_decrypt((unsigned char*)&data[i], dec_out, &dec_key);
        fwrite(dec_out, 1, AES_CRYPT_BYTES, fpd);
    }
    fclose(fpd);
    free(data);

    return 0;
#endif /* __LINUX__ */
}

static int do_decry_f_ex(char *certpath, unsigned char *sha256, char *outpath)
{
#if __linux__
    char *data;
    FILE *fpr, *fpd;
    int filelen, i, len;
    unsigned char dec_out[AES_CRYPT_BYTES];
    AES_KEY dec_key;

    AES_set_decrypt_key(sha256, AES_CRYPT_BITS, &dec_key);

    fpr = fopen(certpath, "r");
    if (fpr == NULL)
        return -1;
    fseek(fpr, 0L, SEEK_END);
    filelen = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);
    data = (char*)calloc(filelen, sizeof(char));
    if (data == NULL)
    {
        fclose(fpr);
        return -1;
    }
    fread(data, sizeof(char), filelen, fpr);

    fclose(fpr);
    fpd = fopen(outpath, "w+");
    if (fpd == NULL)
    {
        free(data);
        return -1;
    }
    for (i = 0; i < filelen; i+=AES_CRYPT_BYTES) {
        AES_decrypt((unsigned char*)&data[i], dec_out, &dec_key);
        len = remove_padding(dec_out);
        fwrite(dec_out, 1, len, fpd);
    }
    fclose(fpd);
    free(data);

    return 0;
#endif
}


static int do_encry(char *certpath, unsigned char *sha256)
{
#if __linux__
    char *data;
    FILE *fpr, *fpe;
    int filelen, i;
    unsigned char enc_out[AES_CRYPT_BYTES];
    AES_KEY enc_key;

    fpr = fopen(certpath, "r");
    if (fpr == NULL)
        return -1;
    fseek(fpr, 0L, SEEK_END);
    filelen = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);
    data = (char*)calloc(filelen, sizeof(char));
    if (data == NULL)
    {
        fclose(fpr);
        return -1;
    }
    fread(data, sizeof(char), filelen, fpr);
    fclose(fpr);
    unlink(certpath);
    filelen = filelen;
    AES_set_encrypt_key(sha256, AES_CRYPT_BITS, &enc_key);

    fpe = fopen(certpath, "w+");

    for (i = 0; i < filelen; i+=AES_CRYPT_BYTES) {
        AES_encrypt((unsigned char*)&data[i], enc_out, &enc_key);
        fwrite(enc_out, 1, AES_CRYPT_BYTES, fpe);
    }
    fclose(fpe);
    free(data);
    return 0;
#endif /* __LINUX__ */    
}

static int do_encry_ex(char *certpath, unsigned char *sha256, char *outpath, int flag)
{
#if __linux__
    char *data;
    FILE *fpr, *fpe;
    int filelen, alloclen, i;
    unsigned char enc_out[AES_CRYPT_BYTES];
    AES_KEY enc_key;

    fpr = fopen(certpath, "r");
    if (fpr == NULL)
        return -1;
    fseek(fpr, 0L, SEEK_END);
    filelen = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);

    if (filelen % AES_CRYPT_BYTES == 0)
        alloclen = filelen;
    else {
        alloclen = filelen + (AES_CRYPT_BYTES - (filelen % AES_CRYPT_BYTES));
    }
    data = (char*)calloc(alloclen, sizeof(char));
    if (data == NULL)
    {
        fclose(fpr);
        return -1;
    }
    memset(data, '\0', alloclen);
    fread(data, sizeof(char), filelen, fpr);
    fclose(fpr);
    if (flag)
        unlink(certpath);
    filelen = filelen;

    AES_set_encrypt_key(sha256, AES_CRYPT_BITS, &enc_key);

    fpe = fopen(outpath, "w+");

    for (i = 0; i < filelen; i+=AES_CRYPT_BYTES) {
        AES_encrypt((unsigned char*)&data[i], enc_out, &enc_key);
        fwrite(enc_out, 1, AES_CRYPT_BYTES, fpe);
    }
    fclose(fpe);
    free(data);
    return 0;
#endif /* __LINUX__ */    
}


static int do_sha256(unsigned char *sha256)
{
#if __linux__
    SHA256_CTX sha_ctx;
    unsigned char mac[MACLEN], serial_num, seed[SEEDLEN];
    int *seed_int;

    do_fake_get_mac(mac);
    do_fake_get_serial_num(&serial_num);
    do_fate_get_seed(seed);

    seed[5] += mac[0];
    seed[6] += mac[1];
    seed[7] += mac[2];
    seed[8] += mac[3];
    seed[9] += mac[4];
    seed[10] += mac[5];

    seed_int = (int *)&seed[0];
    *seed_int += serial_num;

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, seed, SEEDLEN);
    SHA256_Final(sha256, &sha_ctx);

    return 0;
#endif /* __LINUX__ */    
}
/**
 * @brief:  Check the type of cerificate file.
 *
 * @param
 *
 * @return type of certificate
 *                  1 if impotred
 *                  2 if self-gen
 */
static int check_cert_type(char *pem)
{
    FILE *fp;
    char import_flag[128];
    int ret;
#ifdef OPTEE_DECRY_ENCRY
    fp = fopen(pem, "r");
    if (fp != NULL) {
        fclose(fp);
        ret = crypto_decryption(pem,
                                        CERT_ENDENTITY_TMP_PATH);
        if (ret != 0) {
            printf("[Err] crypto_decryption %d\r\n", ret);
            return -1;
        }
    } else {
        return 0;
    }
#else
    ret = mx_do_decry_f(pem);
    if (ret < 0)
        return ret;
#endif

    fp = fopen(CERT_ENDENTITY_TMP_PATH, "r");

    if (fp != NULL) {
        fgets(import_flag, sizeof(import_flag), fp);
        fclose(fp);
        unlink(CERT_ENDENTITY_TMP_PATH);
        if (!strncmp(import_flag, SSL_CERT_IMPORT_FLAG, strlen(SSL_CERT_IMPORT_FLAG))) {
            return CERT_TYPE_IMPORT;
        } else
            return CERT_TYPE_SELFGEN;
    }
    else
        return -1;
}
static int checkCertMbed(char *data, int datalen)
{
    int ret = 0;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt pcert;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pkey);
    mbedtls_x509_crt_init(&pcert);

    if ((ret = mbedtls_pk_parse_key(&pkey, data, datalen, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        printk("[SSL] %s-%d: failed! pk_parse_key returned -0x%x\n\n", __func__, __LINE__, -ret);
        ret = -1;
        goto clean1;
    }

    if ((ret = mbedtls_x509_crt_parse(&pcert, data, datalen)) != 0)
    {
        printk("[SSL] %s-%d: failed! x509_crt_parse returned -0x%X\r\n", __func__, __LINE__, -ret);
        ret = -2;
        goto clean1;
    }
clean1:    
    mbedtls_pk_free(&pkey);
    mbedtls_x509_crt_free(&pcert);

    return ret;
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
#if __linux__
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
#endif /* __LINUX__ */    
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

    return 0;
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
    /* At 2021/11/9, we decice that we can delete all certificate. */
    if (ret == CERT_TYPE_IMPORT || ret == CERT_TYPE_SELFGEN) {
        printf("Delete User's Import PEM\r\n");
        unlink(fname);
#if USE_MX_EVENT_AGENT
        mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_CERT_DELETED);
#endif
        return 1;
    } else {
        printf("Delete User's Import PEM- file open fail\r\n");
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

 * @return 0 if success
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
    char*tmpFile = SYSTEM_TMPFS_PATH"/tmp.pem";

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
#if __linux__
    ret = checkCert(certFile, keyFile, flag, errStr, errlen);
    if (ret < 0) {
        ret -= 10;
        goto error;
    }
#else
    ret = checkCertMbed(data, len);
#endif
#ifdef OPTEE_DECRY_ENCRY
    ret = crypto_encryption(tmpFile, fname);
    if (ret != 0) {
        printf("[Err] crypto_decryption %d\r\n", ret);
        return -1;
    }
#else
    // save
    sprintf(cmd, "mv %s %s", tmpFile, fname);
    system(cmd);
    mx_do_encry(fname);
#endif
#if USE_MX_EVENT_AGENT
    mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_CERT_IMPORTED);
#endif
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
    uint32_t ip;
    char active_ip[32] = {0};
    struct sockaddr_in addr_in;

    ret = check_cert_type(CERT_ENDENTITY_PEM_PATH);
    if (ret == CERT_TYPE_IMPORT)
        return -1; /* The certificate device is using is imported by customer */

    printf("Re-generating the self-signed certificate\r\n");

    net_get_my_ip_by_ifname("eth0", &ip);
    addr_in.sin_addr.s_addr = ip;
    strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));

    mx_cert_gen_priv_key(CERT_ENDENTITY_KEY_PATH, CERT_ENDENTITY_KEY_LENGTH);
    mx_cert_gen_csr(CERT_ENDENTITY_KEY_PATH, CERT_ENDENTITY_CSR_PATH, active_ip);
    mx_cert_sign_cert(
            CERT_ENDENTITY_CSR_PATH,
            CERT_ROOTCA_CERT_PATH,
            CERT_ROOTCA_KEY_PATH,
            CERT_ENDENTITY_VALID_DAY,
            CERT_ENDENTITY_CERT_PATH,
            active_ip);
    ret = mx_cert_combine_ip_key_cert(CERT_ENDENTITY_PEM_PATH,
            active_ip,
            CERT_ENDENTITY_KEY_PATH,
            CERT_ENDENTITY_CERT_PATH);
    unlink(CERT_ENDENTITY_KEY_PATH);
    unlink(CERT_ENDENTITY_CERT_PATH);
    if (!ret)
        return -1;
#if USE_MX_EVENT_AGENT        
    mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_CERT_REGEN);
#endif
    return 1;
}
/*
* @brief: combine key and cert
* @return: 0 if success
*               -1 if fail
*/
int mx_cert_combine_ip_key_cert(char *pem_path,
                                                            char *ip,
                                                            char *key_path,
                                                            char *cert_path)
{
    FILE *fpw, *fpr;
    char *buf;
    int file_len;
    int ret;
    /* open file for PEM format IP/private key/ certficate */
    fpw = fopen(CERT_ENDENTITY_TMP_PATH, "w+");
    if (fpw == NULL)
        return -1;
    /* append active ip */
    fwrite(ip, strlen(ip), 1, fpw);
    fwrite("\n", 1, 1, fpw);

    /* read .key and copy to .pem */
    fpr = fopen(key_path, "r");
    if (fpr == NULL)
    {
        fclose(fpw);
        return -1;
    }
    fseek(fpr, 0L, SEEK_END);
    file_len = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);
    buf = (char*)calloc(file_len, sizeof(char));
    if (buf == NULL)
    {
        fclose(fpr);
        fclose(fpw);
        return -1;
    }
    fread(buf, sizeof(char), file_len, fpr);
    fclose(fpr);
    fwrite(buf, file_len, 1, fpw);
    free(buf);

    /* read .cert and copy to .pem */
    fpr = fopen(cert_path, "r");
    if (fpr == NULL)
    {
        fclose(fpw);
        return -1;
    }
    fseek(fpr, 0L, SEEK_END);
    file_len = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);
    buf = (char*)calloc(file_len, sizeof(char));
    if (buf == NULL)
    {
        fclose(fpr);
        fclose(fpw);
        return -1;
    }
    fread(buf, sizeof(char), file_len, fpr);
    fclose(fpr);
    fwrite(buf, file_len, 1, fpw);
    fclose(fpw);
    free(buf);
    /* remove individual key & cert */
    unlink(key_path);
    unlink(cert_path);
#ifdef OPTEE_DECRY_ENCRY
    ret = crypto_encryption(CERT_ENDENTITY_TMP_PATH, pem_path);
    if (ret != 0) {
        printf("[Err] crypto_decryption %d\r\n", ret);
        return -1;
    }
#else
    mx_do_encry(pem_path);
#endif
    return 0;
}

void mx_cert_gen_priv_key(char *path, int len)
{
    char cmd[512];

    sprintf(cmd, "openssl genrsa -out %s %d",
                path,
                len);

    system(cmd);
}

void mx_cert_gen_csr(char *keypath, char *csrpath, char *ip)
{
    char cmd[512];

    sprintf(cmd, "openssl req -sha256 -new -key %s -out \
                       %s \
                       -subj /C=TW/ST=Taiwan/L=Taipei/O=Moxa/OU=MGate/CN=\"%s\"/emailAddress=taiwan@moxa.com",
                       keypath,
                       csrpath,
                       ip);
    system(cmd);
}

void mx_cert_sign_cert(char *csr_path, char *rootcert_path, char *rootkey_path,
                                        int valid_day, char *cert_path, char *ip)
{
    char cmd[512];

    /* Use default 'sh' to execute following command will report POSIX error:
     *   syntax error near unexpected token `('
     * So we use 'bash -c' instead.
     */
    snprintf(cmd, sizeof(cmd), "bash -c \"openssl x509 -req -in %s -CA %s \
                  -CAkey %s -CAserial %s -CAcreateserial \
                  -extensions SAN \
                  -extfile <(printf '[SAN]\\nsubjectAltName=IP:%s') \
                  -days %d -out %s\"",
                  csr_path,
                  rootcert_path,
                  rootkey_path,
                  CA_SERIAL_TMP_PATH,
                  ip,
                  valid_day,
                  cert_path);
    system(cmd);
}

int mx_do_encry(char *certpath)
{
    unsigned char sha256[SHA256LEN];

    do_sha256(sha256);

    do_encry(certpath, sha256);

    return 0;
}
/*
    @input : certpath : File to be decrypted.
    @input : flag       : 1: delete file that has been decrypted
    @output: outpath : File has been decrypted.
*/
int mx_do_encry_ex(char *certpath, char *outpath, int flag)
{
    unsigned char sha256[SHA256LEN];

    do_sha256(sha256);

    do_encry_ex(certpath, sha256, outpath, flag);

    return 0;
}


int mx_do_decry_b(char *certpath, unsigned char *cert_ram)
{
    unsigned char sha256[SHA256LEN];

    do_sha256(sha256);

    do_decry_b(certpath, sha256, cert_ram);

    return 0;
}

int mx_do_decry_f(char *certpath)
{
    int ret;
    unsigned char sha256[32];

    do_sha256(sha256);

    ret = do_decry_f(certpath, sha256);
    return ret;
}

int mx_do_decry_f_ex(char *certpath, char *outpath)

{
    int ret;
    unsigned char sha256[32];

    do_sha256(sha256);

    ret = do_decry_f_ex(certpath, sha256, outpath);
    return ret;
}

static int getCnFromSubject(char *cn_buf, int *cn_len, char *input_buf)
{
    char *ptr1, *ptr2;
    int ret = 0;

    ptr1 = strstr(input_buf, "CN=");
    if (ptr1 == NULL)
    {
        ret = -1;
        goto exit;
    }
    ptr1 += 3; // ignore "CN=""
    ptr2 = strstr(ptr1, ",");
    // indicate there is no char after CN=
    if (ptr2 == NULL)
        ptr2 = input_buf + strlen(input_buf);
    *cn_len = ptr2 - ptr1;
    memcpy(cn_buf, ptr1, *cn_len);  // copy CN into buffer
    cn_buf[*cn_len] = 0;
exit:
    return ret;
}
/*
    @brief: get information of certificate
    @return: 0 if success
                 -1 if fail
*/
int mx_get_cert_info(char *certpath, char *start, char *end, char *issueto, char *issueby)
{
#if __linux__
    X509 *x;
    int ret;

#ifdef OPTEE_DECRY_ENCRY
    FILE *fp;

    fp = fopen(certpath, "r");
    if (fp != NULL) {
        fclose(fp);
        ret = crypto_decryption(certpath,
                                        CERT_ENDENTITY_TMP_PATH);
        if (ret != 0) {
            printf("[Err] crypto_decryption %d\r\n", ret);
            return -1;
        }
    } else {
        return -1;
    }
#else
    ret= mx_do_decry_f(certpath);
    if (ret < 0)
        return ret;
#endif
    x = TS_CONF_load_cert(CERT_ENDENTITY_TMP_PATH);
    unlink(CERT_ENDENTITY_TMP_PATH);
    /* Issued to */

    ret = X509_NAME_get_text_by_NID(X509_get_subject_name(x), OBJ_txt2nid("CN"), issueto, 128);
    dbg_printf("Issueto %s\r\n", issueto);

    /* Issued by */
    ret = X509_NAME_get_text_by_NID(X509_get_issuer_name(x), OBJ_txt2nid("CN"), issueby, 128);
    dbg_printf("issueby %s\r\n", issueby);

    /* Valid from */
    ret = _ASN1_TIME_print(start, X509_get_notBefore(x));
    dbg_printf("start %s\r\n", start);

    /* Valid to */
    ret = _ASN1_TIME_print(end, X509_get_notAfter(x));
    dbg_printf("end %s\r\n", end);

    X509_free(x);

    return 0;
#else
    int ret, fd = 0;
    int info_len = 512;
    DIR *dir;
    char tmp_buf[512] = {0};
    char info[512] = {0};
    unsigned char certificate[CERT_LEN] = {0}; 
    mbedtls_x509_crt         cert;

    mbedtls_x509_crt_init(&cert);
    ret = crypto_decryption(certpath, 
                                    CERT_ENDENTITY_TMP_PATH); 
    if (ret != 0) {
        printk("[Err] crypto_decryption %d\r\n", ret);   
        return ret;
    } 
    if ((dir = opendir(CERT_ENDENTITY_RUN_DIR))) {
        closedir(dir);
    } else {
        mkdir(CERT_ENDENTITY_RUN_DIR, 777);
    }
    if ((fd = open(CERT_ENDENTITY_TMP_PATH, O_RDWR | O_CREAT)) < 0) {
        printk("open fd: %d, path: %s\r\n", fd, CERT_ENDENTITY_TMP_PATH);
    }
    if (fd > 0) {
        ret = read(fd, certificate, CERT_LEN);
        printk("Joy %s-%d, readlen=%d\r\n", __func__, __LINE__, ret);
        printk("%s\r\n", certificate);
        if (ret > 0) {
#if 0        
            mbedtls_ctr_drbg_context ctr_drbg;
            mbedtls_ctr_drbg_init(&ctr_drbg);
            if ((ret = mbedtls_pk_parse_key(&pkey, certificate, SSL_CERTKEY_LEN, NULL, 0,
                                            mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) 
                printk("[SSL] failed! pk_parse_key returned -0x%x\n\n", -ret);        
#endif                
            if ((ret = mbedtls_x509_crt_parse(&cert, certificate, CERT_LEN)) != 0) 
                printk("[SSL] failed! x509_crt_parse returned -0x%X\r\n", -ret);
        }
        printk("JoyFrom %s-%d, len=%d, y=%d,m=%d,d=%d\r\n", __func__, __LINE__, 
            ret, 
            cert.valid_from.year,
            cert.valid_from.mon,
            cert.valid_from.day);   
        ret = snprintf(start, info_len, "%d/%d/%d",
                       cert.valid_from.year, cert.valid_from.mon,
                       cert.valid_from.day);            
        printk("JoyTo %s-%d, len=%d, y=%d,m=%d,d=%d\r\n", __func__, __LINE__, 
            ret, 
            cert.valid_to.year,
            cert.valid_to.mon,
            cert.valid_to.day);   
        ret = snprintf(end, info_len, "%d/%d/%d",
                       cert.valid_to.year, cert.valid_to.mon,
                       cert.valid_to.day);            
 
        ret = mbedtls_x509_dn_gets(tmp_buf, sizeof(tmp_buf), &(cert.subject));
        getCnFromSubject(info, &info_len, tmp_buf);
        printk("Joy Subject %s-%d, info=%s\r\n", __func__, __LINE__, info);
        strcpy(issueto, info);
        ret = mbedtls_x509_dn_gets(tmp_buf, sizeof(tmp_buf), &(cert.issuer));
        getCnFromSubject(info, &info_len, tmp_buf);
        printk("Joy Issuer %s-%d, info=%s\r\n", __func__, __LINE__, info);            
        strcpy(issueby, info);
    } else {
        printk("[SSL] Open cert file fail (fd:%d)\r\n", fd);

        close(fd);
     
        return -1;
    } 

    close(fd);

    return 0;



#endif    
}
