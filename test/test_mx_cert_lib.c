/**
 * @file test_mx_cert_lib.c
 * @brief Moxa Certificate Management daemon application
 * @copyright Copyright (C) MOXA Inc. All rights reserved.
 * @license This software is distributed under the terms of the MOXA License. See the file COPYING-MOXA for details.
 * @author Joy Tu
 * @date 2021-0914
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
#include <def/mx_def.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include "../src/mx_cert_mgmt_lib.h"
/* openssl AES*/
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
/* openssl AES*/
#define BUF_SZ 512
#define VERSION "1.0.0"
/*****************************************************************************
 * Private functions
 ****************************************************************************/
static int test_cert_del(char *file)
{
    int ret;

    ret = mx_cert_del(file);

    if (ret == -1)
        printf("Fail, This certificate is self-gened\r\n");
}

static int test_cert_regen()
{
    int ret;

    ret = mx_regen_cert();
    if (ret == -1)
        printf("Fail, This certificate is imported from user\r\n");
}


/* Testing */
#define AES_CRYPT_BITS    128
#define AES_CRYPT_BYTES   (AES_CRYPT_BITS / 8)
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

static int do_encry_ex(char *certpath, unsigned char *sha256, char *outpath, int flag)
{
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
}


static int do_decry_f_ex(char *certpath, unsigned char *sha256, char *outpath)
{
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

}


int mx_secure_enchance_embed_dev_d(char *certpath, char *outpath)

{
    int ret, i;
    unsigned char secure_enchance_embed_dev[32] = "12345678901234567890123456789012";
    unsigned char secure[8] = "security";
    unsigned char enchance[8] = "enchance";
    unsigned char embed[8] = "embedded";	
    unsigned char dev[8] = "device!!";	
    unsigned char dees[33];
    for (i = 0; i < 8; i++) {
		dees[i] = dev[i];
		dees[i + 8] = embed[i]; 
		dees[i + 16] = enchance[i];
		dees[i + 24] = secure[i];		
    }
    dees[32] = '\0';
    //printf("dees = %s\r\n", dees);
    //do_sha256(sha256);

    ret = do_decry_f_ex(certpath, dees, outpath);
    return ret;
}

int mx_secure_enchance_embed_dev_e(char *certpath, char *outpath, int flag)
{
    int ret, i;
    unsigned char secure_enchance_embed_dev[32] = "12345678901234567890123456789012";
    unsigned char secure[8] = "security";
    unsigned char enchance[8] = "enchance";
    unsigned char embed[8] = "embedded";	
    unsigned char dev[8] = "device!!";	
    unsigned char dees[33];
    for (i = 0; i < 8; i++) {
		dees[i] = dev[i];
		dees[i + 8] = embed[i]; 
		dees[i + 16] = enchance[i];
		dees[i + 24] = secure[i];		
    }
    dees[32] = '\0';	
    //do_sha256(sha256);

    do_encry_ex(certpath, dees, outpath, flag);

    return 0;
}


static int test_cert_decry(char *file)
{
    char cert_b[4096];
    int ret;
#if 0    
#ifdef OPTEE_DECRY_ENCRY
    ret = crypto_decryption(CERT_ENDENTITY_PEM_PATH, 
                                        CERT_ENDENTITY_TMP_PATH);    


    system("cat CERT_ENDENTITY_TMP_PATH");
#else
    mx_do_decry_b(CERT_ENDENTITY_PEM_PATH, cert_b);
    printf("%s\r\n", cert_b);
#endif
#endif
//    mx_secure_enchance_embed_dev_d(file, "output.pem");
    mx_secure_enchance_embed_dev_d("secure_ee_dev", file);
    return 0;
}

static int test_cert_encry(char *file)
{
    char cert_b[4096];
    int ret;
#if 0    
#ifdef OPTEE_DECRY_ENCRY
    ret = crypto_decryption(CERT_ENDENTITY_PEM_PATH, 
                                        CERT_ENDENTITY_TMP_PATH);    


    system("cat CERT_ENDENTITY_TMP_PATH");
#else
    mx_do_decry_b(CERT_ENDENTITY_PEM_PATH, cert_b);
    printf("%s\r\n", cert_b);
#endif
#endif
//    mx_secure_enchance_embed_dev_e("import.pem", file, 0);
    mx_secure_enchance_embed_dev_e(file, "secure_ee_dev", 0);
    return 0;
}

static int test_cert_import(char *file)
{
    FILE *fpr;
    char buf[BUF_SZ], *data;
    int buf_len, filelen, ret;

    fpr = fopen("import.pem", "r");
    fseek(fpr, 0L, SEEK_END);
    filelen = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);	
    data = (char*)calloc(filelen, sizeof(char));	
    if (data == NULL) {
	fclose(fpr);
        return 0;
    }
    fread(data, sizeof(char), filelen, fpr);
    fclose(fpr);

    ret = mx_import_cert(CERT_ENDENTITY_PEM_PATH, data, filelen, buf, BUF_SZ);
}
static void _printf_version(void)
{
    fprintf(stdout, "Moxa Test Tool for mx_cert_lib.c %s\n", VERSION);
}

static void _printf_help(void)
{
    fprintf(stdout,
            "Usage: test_cert_lib [option]\n"
            "Usage: test_cert_lib \n"
            "\n"
            "Options:\n"
            "      --version            display version information and exit\n"
            "      --help               display this help and exit\n"
           );

}
static const char *optstring = "vhi:e:d:rc:";

static struct option opts[] =
{
    { "version",    no_argument, 0, 'v'},
    { "help",        no_argument, 0, 'h'},
    { "import",     required_argument, 0, 'i'},
    { "encryt",     required_argument, 0, 'e'},
    { "decryt",     required_argument, 0, 'd'},
    { "regen",     required_argument, 0, 'r'},
    { "delete",     required_argument, 0, 'c'},    
    { NULL,         required_argument, 0, 0},
};

/*****************************************************************************
 * Public functions
 ****************************************************************************/

int main(int argc, char *argv[])
{
    int c = 0, ret;
    
    while ((c = getopt_long(argc, argv, optstring, opts, NULL)) != -1) {
        switch (c) {
        case 'v':
            _printf_version();
            return EX_OK;

        case 'h':
            _printf_help();
            return EX_OK;
            
        case 'i':
            printf("import file is %s\n", optarg);
            test_cert_import(optarg);
            return EX_OK;

        case 'd':
            printf("decryb file is %s\r\n", optarg);
            test_cert_decry(optarg);
            
            return EX_OK;
        case 'e':
            printf("encryb file is %s\r\n", optarg);
            test_cert_encry(optarg);
            
            return EX_OK;			
        case 'r':
            printf("regen cert \r\n");
            test_cert_regen();
            return EX_OK;
            
        case 'c':
            printf("delete cert is %d\r\n", optarg);
            test_cert_del(optarg);
            return EX_OK;       
            
        default:
             _printf_help();
            return EXIT_FAILURE;
        }
    }
}

