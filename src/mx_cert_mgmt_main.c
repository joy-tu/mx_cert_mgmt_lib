/**
 * @file mx_cert_mgmt_main.c
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
#include "mx_timed.h"

/*****************************************************************************
 * Definition
 ****************************************************************************/
#define DEBUG_MX_CERT_MGMT
#ifdef DEBUG_MX_CERT_MGMT
#define dbg_printf  printf
#else
#define dbg_printf(...) 
#endif
#define CERT_SLEEP_5MIN 60 * 5
#define CERT_SLEEP_1DAY 60 * 60 * 24
#define SSL_CERT_IMPORT_FLAG "import"
#define CERT_ROOTCA_VALID_DAY 3650 
#define CERT_ROOTCA_KEY_LENGTH 2048
//#define CERT_ROOTCA_KEY_PATH "rootca.key"
//#define CERT_ROOTCA_CERT_PATH "rootca.pem"
#define CERT_ROOTCA_KEY_PATH SYSTEM_READ_ONLY_FILES_PATH"cert/rootca.key"
#define CERT_ROOTCA_CERT_PATH SYSTEM_READ_ONLY_FILES_PATH"cert/rootca.pem"
#define CERT_ENDENTITY_VALID_DAY 365 * 5
#define CERT_ENDENTITY_KEY_LENGTH 2048
#define CERT_ENDENTITY_KEY_PATH "endentity.key"
#define CERT_ENDENTITY_CSR_PATH "endentity.csr"
#define CERT_ENDENTITY_CERT_PATH "endentity.cert"
#define CERT_ENDENTITY_PEM_PATH "endentity.pem"

/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/
static int check_certificate(int active_if);
static int check_import(int active_if);
static void cert_gen_priv_key(char *keypath, int len);
static void cert_gen_csr(char *keypath, char *csrpath);
static void cert_sign_cert(char *rootcert_path, 
                                            char *rootkey_path,
                                        int valid_day, char *cert_path);
static int cert_combine_ip_key_cert(char *pem_path,
                                                            char *ip,
                                                            char *key_path,
                                                            char *cert_path);
                                                            
static const char *optstring = "vh";

static struct option opts[] =
{
    { "version",    0, NULL, 'v'},
    { "help",       0, NULL, 'h'},
    { NULL,         0, NULL, 0},
};

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
static void _printf_version(void)
{
    fprintf(stdout, "Moxa Certificate Mgmt Daemon Version %s\n", VERSION);
}

static void _printf_help(void)
{
    fprintf(stdout,
            "Usage: mx-cert-mgmt [option]\n"
            "Usage: mx-cert-mgmt \n"
            "\n"
            "Options:\n"
            "      --version            display version information and exit\n"
            "      --help               display this help and exit\n"
           );

}

static int check_certificate(int active_if)
{
    FILE *fp;
    unsigned long ip;
    struct sockaddr_in addr_in;
    char ipstr[128], active_ip[32];

    fp = fopen(CERT_ENDENTITY_PEM_PATH, "r");

    if (fp != NULL) {
        dbg_printf("\nFound pem file, now check ip address...\n");
        fgets(ipstr, sizeof(ipstr), fp);
        fclose(fp);
        net_get_my_ip_by_ifname("eth0", &ip);
        addr_in.sin_addr.s_addr = ip;
        strcpy(active_ip, inet_ntoa(addr_in.sin_addr));
        dbg_printf("ipstr=[%s], activeIP=[%s]\n", ipstr, active_ip);
        if (!strncmp(ipstr, active_ip, strlen(active_ip)))
            return 1; /* Active IP == PEM's IP */
        else
            return 0;
    }
    else
        return 0;
}

static int check_import(int active_if)
{
    FILE *fp;
    char import_flag[128];

    fp = fopen(CERT_ENDENTITY_PEM_PATH, "r");

    if (fp != NULL) {
        dbg_printf("\nFound cert file, now check import...\n");
        fgets(import_flag, sizeof(import_flag), fp);
        fclose(fp);

        if (!strncmp(import_flag, SSL_CERT_IMPORT_FLAG, strlen(SSL_CERT_IMPORT_FLAG)))
            return 1;
        else
            return 0;
    }
    else
        return 0;
}

static void cert_gen_priv_key(char *path, int len)
{
    char cmd[512];
    
    sprintf(cmd, "openssl genrsa -out %s %d", 
                path,
                len);
                
    system(cmd);   
}

static void cert_gen_csr(char *keypath, char *csrpath)
{
    char cmd[512];

    sprintf(cmd, "openssl req -sha256 -new -key %s -out \ 
                       %s \
                       -subj /C=TW/ST=Taiwan/L=Taipei/O=Moxa/OU=MGate/CN=\"10.123.6.32\"/emailAddress=taiwan@moxa.com",
                       keypath,
                       csrpath);
    system(cmd);
}

static void cert_sign_cert(char *rootcert_path, char *rootkey_path,
                                        int valid_day, char *cert_path)
{
    char cmd[512];

    sprintf(cmd, "openssl x509 -req -in endentity.csr -CA %s \
                  -CAkey %s -CAserial ca.serial -CAcreateserial \
                  -days %d -out %s",
                  rootcert_path,
                  rootkey_path,
                  valid_day,
                  cert_path);
    system(cmd);  
}

static int cert_combine_ip_key_cert(char *pem_path,
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

    sprintf(buf, "%d/%d/%d", y, M, d);
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

    sprintf(buf, "%d/%d/%d", y + 1900, M, d);
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
/*****************************************************************************
 * Public functions
 ****************************************************************************/
#define BUF_SZ 512
#define CERT_BUF_LEN  4096
#define DEFAULT_KEY_LENGTH  1024

int main(int argc, char *argv[])
{
    int c = 0, ret;
    int buf_len, file_len;
    unsigned long ip;
    char active_ip[32] = {0};
    char cmd[512];
    struct sockaddr_in addr_in;
    FILE *fpw, *fpr;
    int filelen;
    char *buf, *data;

    dbg_printf("%s-%d, version=%s\r\n", __func__, __LINE__,VERSION);
    //system("apt-get install -y net-tools > /null");
    while ((c = getopt_long(argc, argv, optstring, opts, NULL)) != -1) {
        switch (c) {
        case 'v':
            _printf_version();
            return EX_OK;

        case 'h':
            _printf_help();
            return EX_OK;

        default:
            return EXIT_FAILURE;
        }
    }
#if 0    
    while ((buf = OPENSSL_malloc(CERT_BUF_LEN)) == NULL)
        usleep(100*1000);
    buf_len = sslRSAKey_new(buf, CERT_BUF_LEN); /* takes about 2 seconds */
    {
        SSL_CTX *ctx;
        (ctx = SSL_CTX_new(SSLv23_server_method()));
    }
    SSL_load_error_strings();
#endif    
    if (net_get_my_ip_by_ifname("eth0", &ip) == 0) {
	dbg_printf("Ok****net_get_my_ip_by_ifname - %x****\r\n", ip);
    } else {
	dbg_printf("Fail****net_get_my_ip_by_ifname ****\r\n");
    }
    addr_in.sin_addr.s_addr = ip;
    strcpy(active_ip, inet_ntoa(addr_in.sin_addr));
    dbg_printf("active_ip = %s\r\n", active_ip);

#if 0 /* Generate rootCA */
    sprintf(cmd, "openssl genrsa -out %s %d", 
                CERT_ROOTCA_KEY_PATH,
                CERT_ROOTCA_KEY_LENGTH);
    system(cmd);

    sprintf(cmd, "openssl req -new -x509 -key %s -days %d -sha256 \
                -extensions v3_ca -out %s \
                -subj /C=TW/ST=Taiwan/L=Taipei/O=Moxa/OU=MGate/CN=\"Moxa Inc.\"/emailAddress=taiwan@moxa.com",
                CERT_ROOTCA_KEY_PATH,
                CERT_ROOTCA_VALID_DAY,
                CERT_ROOTCA_CERT_PATH);
    system(cmd);            
#endif

    ret = checkAndSetCertFile(data, filelen, buf, BUF_SZ);
    if (check_import(1)) {   // Found import.
        goto ck_valid;
    }
    ret = check_certificate(1);
    if (ret) { /* Certificate already exists in db */
        goto ck_valid;
    } else {
        /* Generate Key & CSR & sign cert & combine */
#if 1
    test_func(10);
    cert_gen_priv_key(CERT_ENDENTITY_KEY_PATH, CERT_ENDENTITY_KEY_LENGTH);
    cert_gen_csr(CERT_ENDENTITY_KEY_PATH, CERT_ENDENTITY_CSR_PATH);
    cert_sign_cert(
            CERT_ROOTCA_CERT_PATH,
            CERT_ROOTCA_KEY_PATH,
            CERT_ENDENTITY_VALID_DAY,
            CERT_ENDENTITY_CERT_PATH);
    ret = cert_combine_ip_key_cert(CERT_ENDENTITY_PEM_PATH,
            active_ip,
            CERT_ENDENTITY_KEY_PATH,
            CERT_ENDENTITY_CERT_PATH); 
    if (!ret)
        return -1;
#else
        sprintf(cmd, "openssl genrsa -out %s %d", 
                    CERT_ENDENTITY_KEY_PATH,
                    CERT_ENDENTITY_KEY_LENGTH);
        system(cmd);   

        sprintf(cmd, "openssl req -sha256 -new -key %s -out \ 
                           %s \
                           -subj /C=TW/ST=Taiwan/L=Taipei/O=Moxa/OU=MGate/CN=\"10.123.6.32\"/emailAddress=taiwan@moxa.com",
                           CERT_ENDENTITY_KEY_PATH,
                           CERT_ENDENTITY_CSR_PATH);
        system(cmd);  

        sprintf(cmd, "openssl x509 -req -in endentity.csr -CA %s \
                          -CAkey %s -CAserial ca.serial -CAcreateserial \
                          -days %d -out %s",
                          CERT_ROOTCA_CERT_PATH,
                          CERT_ROOTCA_KEY_PATH,
                          CERT_ENDENTITY_VALID_DAY,
                          CERT_ENDENTITY_CERT_PATH);
        system(cmd);  
        /* open file for PEM format IP/private key/ certficate */
        fpw = fopen(CERT_ENDENTITY_PEM_PATH, "w+");
        fwrite(active_ip, strlen(active_ip), 1, fpw);
        fwrite("\n", 1, 1, fpw);

        /* read .key and copy to .pem */
        fpr = fopen(CERT_ENDENTITY_KEY_PATH, "r");
        if (fpr == NULL)
            return 1;
        fseek(fpr, 0L, SEEK_END);
        file_len = ftell(fpr);
        fseek(fpr, 0L, SEEK_SET);	
        buf = (char*)calloc(file_len, sizeof(char));	
        if (buf == NULL)
            return 1;
        fread(buf, sizeof(char), file_len, fpr);
        fclose(fpr);
        fwrite(buf, file_len, 1, fpw);

        /* read .cert and copy to .pem */
        fpr = fopen(CERT_ENDENTITY_CERT_PATH, "r");
        if (fpr == NULL)
            return 1;
        fseek(fpr, 0L, SEEK_END);
        file_len = ftell(fpr);
        fseek(fpr, 0L, SEEK_SET);	
        buf = (char*)calloc(file_len, sizeof(char));	
        if (buf == NULL)
            return 1;
        fread(buf, sizeof(char), file_len, fpr);
        fclose(fpr);
        fwrite(buf, file_len, 1, fpw);    
        fclose(fpw);
#endif
    }
ck_valid:
    //sleep(CERT_SLEEP_5MIN);
    while (1) {
        X509 *x;
        int ret;
        char buf[60];
        x = TS_CONF_load_cert(CERT_ENDENTITY_PEM_PATH);
        ret = _ASN1_TIME_print(buf, X509_get_notBefore(x));
        printf("1buf = %s\r\n", buf);
        ret = _ASN1_TIME_print(buf, X509_get_notAfter(x));   
        printf("2buf = %s\r\n", buf);
        x = TS_CONF_load_cert("/cert/rootca.pem");
        ret = _ASN1_TIME_print(buf, X509_get_notBefore(x));
        printf("3buf = %s\r\n", buf);
        ret = _ASN1_TIME_print(buf, X509_get_notAfter(x));   
        printf("4buf = %s\r\n", buf);   

        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        printf("now: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

        sleep(CERT_SLEEP_1DAY);
    }
    return 1;
}
