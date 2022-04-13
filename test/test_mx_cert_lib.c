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
#include "mx_cert_mgmt_lib.h"

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

static int test_cert_decry(char *file)
{
    char cert_b[4096];
    int ret;
    
#ifdef OPTEE_DECRY_ENCRY
    ret = crypto_decryption(CERT_ENDENTITY_PEM_PATH, 
                                        CERT_ENDENTITY_TMP_PATH);    


    system("cat CERT_ENDENTITY_TMP_PATH");
#else
    mx_do_decry_b(CERT_ENDENTITY_PEM_PATH, cert_b);
    printf("%s\r\n", cert_b);
#endif
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
static const char *optstring = "vhi:d:rc:";

static struct option opts[] =
{
    { "version",    no_argument, 0, 'v'},
    { "help",        no_argument, 0, 'h'},
    { "import",     required_argument, 0, 'i'},
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

