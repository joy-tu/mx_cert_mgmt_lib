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
#include <openssl/evp.h>
#include "mx_timed.h"
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
#define CERT_SLEEP_5MIN 60 * 5
#define CERT_SLEEP_1DAY 60 * 60 * 24
#define SSL_CERT_IMPORT_FLAG "import"
#define CERT_ROOTCA_VALID_DAY 3650 
#define CERT_ROOTCA_KEY_LENGTH 2048
//#define CERT_ROOTCA_KEY_PATH "rootca.key"
//#define CERT_ROOTCA_CERT_PATH "rootca.pem"
#if 0
#define CERT_ROOTCA_KEY_PATH SYSTEM_READ_ONLY_FILES_PATH"cert/rootca.key"
#define CERT_ROOTCA_CERT_PATH SYSTEM_READ_ONLY_FILES_PATH"cert/rootca.pem"
#define CERT_ENDENTITY_VALID_DAY 365 * 5
#define CERT_ENDENTITY_KEY_LENGTH 2048
#define CERT_ENDENTITY_KEY_PATH SYSTEM_WRITABLE_FILES_PATH"/cert/endentity.key"
#define CERT_ENDENTITY_CSR_PATH SYSTEM_WRITABLE_FILES_PATH"/cert/endentity.csr"
#define CERT_ENDENTITY_CERT_PATH SYSTEM_WRITABLE_FILES_PATH"/cert/endentity.cert"
#define CERT_ENDENTITY_PEM_PATH SYSTEM_WRITABLE_FILES_PATH"/cert/endentity.pem"
#endif
/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/
static int check_certificate(int active_if);
static int check_import(int active_if);
#if 0 
static void cert_gen_priv_key(char *keypath, int len);
static void cert_gen_csr(char *keypath, char *csrpath);
static void cert_sign_cert(char *rootcert_path, 
                                            char *rootkey_path,
                                        int valid_day, char *cert_path);
static int cert_combine_ip_key_cert(char *pem_path,
                                                            char *ip,
                                                            char *key_path,
                                                            char *cert_path);
#endif
static int cert_get_valid_date(char *_buf, struct tm *tm);                                                            
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
    int ret;

    ret = mx_do_decry_f(CERT_ENDENTITY_PEM_PATH);
    fp = fopen(CERT_ENDENTITY_TMP_PATH, "r");
    if (ret == 1)
        unlink(CERT_ENDENTITY_TMP_PATH);


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
    int ret;
    
    ret= mx_do_decry_f(CERT_ENDENTITY_PEM_PATH);
    fp = fopen(CERT_ENDENTITY_TMP_PATH, "r");
    if (ret == 1)
        unlink(CERT_ENDENTITY_TMP_PATH);
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
#if 0
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
#endif
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

static int cert_get_valid_date(char *_buf, struct tm *tm) 
{
    char * pch;
    int cnt = 0;

    dbg_printf("%s-%d, date=%s\r\n", __func__, __LINE__, _buf);
    pch = strtok(_buf, "/");
    while (pch != NULL) {  
      if (cnt == 0) {
        tm->tm_year = atoi(pch) - 1900; 
        dbg_printf("year=%d\r\n", tm->tm_year);
      } else if (cnt == 1) {
        tm->tm_mon = atoi(pch);
        dbg_printf("mon=%d\r\n", tm->tm_mon);
      } else if (cnt == 2) {
        tm->tm_mday = atoi(pch);
        dbg_printf("day=%d\r\n", tm->tm_mday);
      }
      cnt++;
      pch = strtok (NULL, "/");
    }
    tm->tm_hour = 0;
    tm->tm_min = 0;
    tm->tm_sec = 0;
    if (cnt > 2)
      return 1;
    else 
      return -1;
}

static int cert_ck_expire(struct tm *now, struct tm *cert) 
{
    int days = 0;
    int tmp = 0;

    tmp = cert->tm_year - now->tm_year;

    if (tmp > 0)
        days += tmp * 365;
    else {
        tmp = abs(tmp);
        tmp = tmp * 365;
        days -= tmp;
    }
    
    tmp = cert->tm_mon - now->tm_mon;
    if (tmp > 0)
        days += tmp * 30;
    else {
        tmp = abs(tmp);
        tmp = tmp * 30;
        days -= tmp;
    }

    tmp = cert->tm_mday - now->tm_mday;
    if (tmp > 0)
        days += tmp;        
    else {
        tmp = abs(tmp);
        days -= tmp;
    }        
    dbg_printf("days=%d\r\n", days);
    if (days > 61)
        return 0; /* save */
    else
        return days; /* will expire */
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
    char buf[BUF_SZ], *data;
    X509 *x;
    char _buf[64], tmp[64], cert_b[4096];
    struct tm tm, rootca_date, endtitiy_date;
    time_t t, t2;
    double seconds;

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

    if (net_get_my_ip_by_ifname("eth0", &ip) == 0) {
	dbg_printf("Ok****net_get_my_ip_by_ifname - %x****\r\n", ip);
    } else {
	dbg_printf("Fail****net_get_my_ip_by_ifname ****\r\n");
    }
    addr_in.sin_addr.s_addr = ip;
    strcpy(active_ip, inet_ntoa(addr_in.sin_addr));
    dbg_printf("active_ip = %s\r\n", active_ip);

#if 0 
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
/* Test function for import */
//#define IMPORT_TEST
//#define DELETE_TEST
//#define REGEN_TEST
//#define ENCRYP_TEST
//#define DECRY_TEST
#ifdef DECRY_TEST
    printf("test1\r\n");
    mx_do_decry_b(CERT_ENDENTITY_PEM_PATH, cert_b);
    printf("test2\r\n");
    printf("%s\r\n", cert_b);
    printf("test3\r\n");
    return 0;
#endif
#ifdef ENCRYP_TEST
    //mx_do_encry(CERT_ENDENTITY_PEM_PATH);
#endif
#ifdef IMPORT_TEST
{
    FILE *fpr;

    fpr = fopen("import.pem", "r");
    fseek(fpr, 0L, SEEK_END);
    filelen = ftell(fpr);
    fseek(fpr, 0L, SEEK_SET);	
    data = (char*)calloc(filelen, sizeof(char));	
    if (data == NULL)
        return 0;
    fread(data, sizeof(char), filelen, fpr);
    fclose(fpr);
    //printf("%s\r\n", data);
    ret = mx_import_cert(CERT_ENDENTITY_PEM_PATH, data, filelen, buf, BUF_SZ);
}
#endif
#ifdef DELETE_TEST
{
    mx_cert_del(CERT_ENDENTITY_PEM_PATH);
}
#endif
#ifdef REGEN_TEST
{
    mx_regen_cert();
}
#endif
    ret = mx_tell_cert_type(CERT_ENDENTITY_PEM_PATH);
    if (ret == CERT_TYPE_IMPORT) {
        printf("Certificate is Imported\r\n");
    } else {
        printf("Certificate is Self-Gened\r\n");
    }
    if (check_import(1)) {   // Found import.
        goto ck_valid;
    }
    ret = check_certificate(1);
    if (ret) { /* Certificate already exists in db */
        goto ck_valid;
    } else {
        /* Generate Key & CSR & sign cert & combine */
        printf("Generating certificate................\r\n");
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
ck_valid:
    /* Get rootca && end entity expiration date */
    mx_do_decry_f(CERT_ENDENTITY_PEM_PATH);
    x = TS_CONF_load_cert(CERT_ENDENTITY_TMP_PATH);
    unlink(CERT_ENDENTITY_TMP_PATH);
    ret = _ASN1_TIME_print(_buf, X509_get_notBefore(x));
    ret = _ASN1_TIME_print(_buf, X509_get_notAfter(x)); 
    ret = cert_get_valid_date(_buf, &rootca_date);
    strftime(tmp, sizeof(tmp), "rootca_date:%c\r\n", &rootca_date);
    dbg_printf(tmp);
    x = TS_CONF_load_cert(CERT_ROOTCA_CERT_PATH);
    ret = _ASN1_TIME_print(_buf, X509_get_notBefore(x));
    ret = _ASN1_TIME_print(_buf, X509_get_notAfter(x));   
    ret = cert_get_valid_date(_buf, &endtitiy_date);
    strftime(tmp, sizeof(tmp), "endtitiy_date:%c\r\n", &endtitiy_date);
    dbg_printf(tmp);
     //sleep(CERT_SLEEP_5MIN);
    while (1) {
        /* compare the date between now and rootca/end entity */
        double ret;
        t = time(NULL);

        tm = *localtime(&t);
        tm.tm_year += 20;
        strftime(tmp, sizeof(tmp), "now_date:%c\r\n", &tm);
        dbg_printf(tmp);
        ret = cert_ck_expire(&tm, &rootca_date);
        if (ret > 0) {
            printf("todo send for rootca will expired (%d)\r\n", ret);
        } else if (ret < 0)
            printf("todo send for rootca expired (%d)\r\n", ret);        
        ret = cert_ck_expire(&tm, &endtitiy_date);
        if (ret > 0) {
            printf("todo send for end-cert will expired (%d)\r\n", ret);
        } else if (ret < 0)
            printf("todo send for end-cert expired (%d)\r\n", ret); 
        
        printf("now: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

        sleep(CERT_SLEEP_1DAY);
    }
    return 1;
}
