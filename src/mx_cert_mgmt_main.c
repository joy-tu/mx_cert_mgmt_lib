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
/* CMAKE generates the definition file based on cmake/config.cmake. */
#if __linux__
#include <sysexits.h>
#include <../include/mx_cert_mgmt/conf.h>
#else
#include "conf.h"
#endif
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>/* FIONREAD */
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <def/mx_def.h>
#if __ZEPHYR__
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include "mbedtls/md.h"
#include <zephyr/posix/pthread.h>
#include "ark_ssl.h"
#include <entropy_poll.h>
#else   /* Linux */
#include <linux/sockios.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ts.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#endif
#include <rest/rest_parser.h>
#include<dirent.h>  
#include<sys/types.h>  
#include<sys/stat.h>  
//#include<mx_net/mx_net.h>
#include "mx_cert_mgmt_lib.h"
#include "mx_cert_mgmt_event.h"
#if __linux__
#include <../include/mx_cert_mgmt/mx_cert_mgmt_rest.h>
#else
#include <mx_cert_mgmt_rest.h>
#endif
//#include "mx_cert_mgmt_rest.h"
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
#define CERT_SLEEP_5MIN 60 * 5
#define CERT_SLEEP_1DAY 60 * 60 * 24
#define SSL_CERT_IMPORT_FLAG "import"
#define CERT_ROOTCA_VALID_DAY 3650 
#define CERT_ROOTCA_KEY_LENGTH 2048
#define MODE (S_IRWXU | S_IRWXG | S_IRWXO)  
#if __ZEPHYR__
#define CERTMGMT_THREAD_STACK_SIZE 10240
static K_THREAD_STACK_DEFINE(thread_stack, CERTMGMT_THREAD_STACK_SIZE);
#endif
/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/
static int check_certificate(int active_if);
static int check_import(int active_if);
static int cert_get_valid_date(char *_buf, struct tm *tm);                                                            
static const char *optstring = "vh";
static int cert_mgmt_terminate = 0;
static pthread_t cert_mgmt_thread_idx;

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
/*
 * Signal handler for SIGINT or SIGQUIT. When program receives SIGINT/SIGQUIT,
 * it will terminate itself.
 */
static void sigquit_handler(int sig)
{
    cert_mgmt_terminate = 1;
    rest_cleanup();
    printf("Received signal(%d)\n", sig);
}

static void _printf_version(void)
{
#if __ZEPHYR__
    fprintf(stdout, "Moxa Certificate Mgmt Daemon \r\n");
#else
    fprintf(stdout, "Moxa Certificate Mgmt Daemon Version %s\n", VERSION);
#endif    
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
/* 
    @brief : Check the validation of certificate
    @return: 1 if  valid.
                 0 if invalid.
                 -1 if crypto_decryption fail

*/
static int check_certificate(int active_if)
{
    FILE *fp;
    uint32_t ip;
    int inter, i;
    uint32_t my_ip[4];
    struct sockaddr_in addr_in;
    char ipstr[128], active_ip[32];
    int ret;
#ifdef OPTEE_DECRY_ENCRY
    fp = fopen(CERT_ENDENTITY_PEM_PATH, "r");
    if (fp != NULL) {
        fclose(fp);
        ret = crypto_decryption(CERT_ENDENTITY_PEM_PATH, 
                                        CERT_ENDENTITY_TMP_PATH);
        if (ret != 0) {
            printf("[Err] crypto_decryption %d\r\n", ret);
            return -1;
        }
    } else {
        return 0;
    }
#else
    ret = mx_do_decry_f(CERT_ENDENTITY_PEM_PATH);
    if (ret < 0)
        return 0;
#endif
    fp = fopen(CERT_ENDENTITY_TMP_PATH, "r");

    if (fp != NULL) {
        dbg_printf("\nFound pem file, now check ip address...\n");
        fgets(ipstr, sizeof(ipstr), fp);
        fclose(fp);
        unlink(CERT_ENDENTITY_TMP_PATH);
#if USE_MX_NET        
        inter = net_max_interfaces();
        if (inter > 0) {
            for (i = 0; i < inter; i++) {
                net_get_my_ip(i, &my_ip[i]);
                printf("my_ip - %x\r\n", my_ip[i]);
            }
            addr_in.sin_addr.s_addr = my_ip[0];
            strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
            printf("active_ip = %s\r\n", active_ip);        
        } else { /* for docker */
            net_get_my_ip_by_ifname("eth0", &ip);
            addr_in.sin_addr.s_addr = ip;
            strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
        }        
#endif
        dbg_printf("ipstr=[%s], activeIP=[%s]\n", ipstr, active_ip);
        if (!strncmp(ipstr, active_ip, strlen(active_ip)))
            return 1; /* Active IP == PEM's IP */
        else
            return 0;
    }
    else
        return 0;
}
/* 
    @brief : Check the imported flag of certificate
    @return: 1 if  imported.
                 0 if  Non imported.
                 -1 if crypto_decryption fail
*/
static int check_import(int active_if)
{
    FILE *fp;
    char import_flag[128];
    int ret;
#ifdef OPTEE_DECRY_ENCRY    
    fp = fopen(CERT_ENDENTITY_PEM_PATH, "r");
    if (fp != NULL) {
        fclose(fp);
        ret = crypto_decryption(CERT_ENDENTITY_PEM_PATH, 
                                        CERT_ENDENTITY_TMP_PATH);
        if (ret != 0) {
            printf("[Err] crypto_decryption %d\r\n", ret);
            return -1;
        }
    } else {
        return 0;
    }                                        
#else                                        
    ret= mx_do_decry_f(CERT_ENDENTITY_PEM_PATH);
    if (ret < 0)
        return ret;     
#endif        
    fp = fopen(CERT_ENDENTITY_TMP_PATH, "r");

    if (fp != NULL) {
        dbg_printf("\nFound cert file, now check import...\n");
        fgets(import_flag, sizeof(import_flag), fp);
        fclose(fp);
        unlink(CERT_ENDENTITY_TMP_PATH);

        if (!strncmp(import_flag, SSL_CERT_IMPORT_FLAG, strlen(SSL_CERT_IMPORT_FLAG)))
            return 1;
        else
            return 0;
    }
    else
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
#endif /* __LINUX__ */
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

  
static int mk_dir(char *dir)  
{  
    DIR *mydir = NULL;  
    if ((mydir= opendir(dir))==NULL) {  
      int ret = mkdir(dir, MODE);
#if __ZEPHYR__
      printk("Joy %s-%d ret = %d\r\n", __func__ ,__LINE__, ret);
#endif
      if (ret != 0) {  
          return -1;  
      }  
        //printf("%s created sucess!/n", dir);  
    } else {  
        //printf("%s exist!/n", dir);  
    }  
    closedir(mydir); 
    return 0;  
}  

#define MGMT_BITS    128
#define MGMT_BYTES   (MGMT_BITS / 8)
static int remove_padding(unsigned char *buf)
{
    int ret, i;

    ret = 0;

    for (i = 0; i < MGMT_BYTES; i++) {
        if (buf[i] != '\0')
            ret++;
    }
    return ret;
}
#if __linux__
static int do_secure_ee_dev_f_ex(char *certpath, unsigned char *sha256, char *outpath)
{
    char *data;
    FILE *fpr, *fpd;
    int filelen, i, len;
    unsigned char dec_out[MGMT_BYTES];
    AES_KEY dec_key;

    AES_set_decrypt_key(sha256, MGMT_BITS, &dec_key);

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
    for (i = 0; i < filelen; i+=MGMT_BYTES) {
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
    //unsigned char secure_enchance_embed_dev[32] = "12345678901234567890123456789012";
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

    ret = do_secure_ee_dev_f_ex(certpath, dees, outpath);
    return ret;
}
#endif /* __LINUX__ */
/*****************************************************************************
 * Public functions
 ****************************************************************************/
#define BUF_SZ 512
#define CERT_BUF_LEN  4096
#define DEFAULT_KEY_LENGTH  1024
#define DEFAULT_GEN_KEY_SEED_STR      "MOXA_CONN_IDC"
#define DEFAULT_KEY_PEM_SIZE          2048
#define DEFAULT_CERT_PEM_SIZE         2048
#define DEFAULT_CERT_SERIAL           "1"
#define FLASH_SSL_CERT_HEADER         "===SSL CERTIFICATE RECORD: IP "
#define CERT_FILE_PATH                SYSTEM_WRITABLE_FILES_PATH"/cert"
#define CERT_FILE_NAME                "a.pem"
#define SSL_CERTKEY_LEN               (DEFAULT_KEY_PEM_SIZE+DEFAULT_CERT_PEM_SIZE)

static mbedtls_pk_context       pkey;
static mbedtls_x509_crt         cert;
static mbedtls_entropy_context  entropy;
static mbedtls_ctr_drbg_context ctr;
static int hardclock_init = 0;
static struct timeval tv_init;
static unsigned long mbedtls_mx_timing_hardclock(void)
{
    struct timeval tv_cur;

    if (hardclock_init == 0)
    {
        gettimeofday(&tv_init, NULL);
        hardclock_init = 1;
    }

    gettimeofday(&tv_cur, NULL);
    return ((tv_cur.tv_sec  - tv_init.tv_sec) * 1000000
            + (tv_cur.tv_usec - tv_init.tv_usec));
}

static int mbedtls_mx_hardclock_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    unsigned long timer = mbedtls_mx_timing_hardclock();
    ((void) data);
    *olen = 0;

    if (len < sizeof(unsigned long))
    {
        return (0);
    }

    memcpy(output, &timer, sizeof(unsigned long));
    *olen = sizeof(unsigned long);

    return (0);
}

int mx_cert_mgmt_daemon_test(void *ptr)
{

    int rc, ret, len;
    unsigned char *temp = NULL;
    unsigned char date_from[16] = {0}, date_to[16] = {0};
    struct net_if_addr *if_addr;
    unsigned char name[32] = {0};
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    mbedtls_pk_context *issuer_key = &pkey, *subject_key = &pkey;
    int fd = 0;

#if __ZEPHYR__
    printk("Joy %s-%d\r\n", __func__, __LINE__);
//    for (;;)
//        sleep(5);
#endif
    if ((fd = open(CERT_FILE_PATH"/"CERT_FILE_NAME, O_RDWR | O_CREAT)) < 0)
    {
        printk("open fd: %d, path: %s\r\n", fd, CERT_FILE_PATH);
    }
    
    temp = malloc(SSL_CERTKEY_LEN);
    printk("Joy %s-%d, fd = %d, temp=%x\r\n", __func__, __LINE__, fd, temp);

    if (temp == NULL)
    {
        printk("[SSL] Failed, malloc failed\r\n");
        return -1;
    }

    memset(temp, 0, SSL_CERTKEY_LEN);

    if_addr = net_if_get_by_index(1)->config.ip.ipv4->unicast;

    len = sprintf((char *)temp, "%s%s\r\n",
                  FLASH_SSL_CERT_HEADER, net_sprint_addr(AF_INET, &if_addr->address.in_addr));
    printk("Joy %s-%d, len =%d\r\n", __func__, __LINE__, len);

    mbedtls_pk_init(&pkey);
    mbedtls_ctr_drbg_init(&ctr);	
    mbedtls_x509_crt_init(&cert);
    mbedtls_entropy_init(&entropy);
    printk("Joy %s-%d\r\n", __func__, __LINE__);

    mbedtls_entropy_add_source(&entropy, mbedtls_mx_hardclock_poll, NULL,
                           MBEDTLS_ENTROPY_MIN_PLATFORM,
                           MBEDTLS_ENTROPY_SOURCE_STRONG);
    printk("Joy %s-%d\r\n", __func__, __LINE__);
#if 1
    if ((rc = mbedtls_ctr_drbg_seed(&ctr,
                                    mbedtls_entropy_func,
                                    &entropy,
                                    (unsigned char *)DEFAULT_GEN_KEY_SEED_STR,
                                    strlen(DEFAULT_GEN_KEY_SEED_STR)))
            != 0) {
        printk("[SSL] Cannot seed rng rc %d %s\n", rc, MBEDTLS_CONFIG_FILE);
        return -1;
    }        
#endif
    /* generate a 1024-bit RSA key pair (ssl_gen_rsa_key) */
    printk("Joy %s-%d\r\n", __func__, __LINE__);

    if ((ret = mbedtls_pk_setup(&pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0)
    {
        printk("[SSL] failed! pk_setup returned -0x%04x\r\n", -ret);
        return ret;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pkey), mbedtls_ctr_drbg_random, &ctr,
                              DEFAULT_KEY_LENGTH, 65537);

    if (ret != 0)
    {
        printk("[SSL] failed! rsa_gen_key returned -0x%04x\r\n", -ret);
        return ret;
    }

    // Write PEM key to buffer
    if ((ret = mbedtls_pk_write_key_pem(&pkey, temp + len,
                                        DEFAULT_KEY_PEM_SIZE)) != 0)
    {
        printk("[SSL] pk_write_key_pem failed\r\n");
        ret = -2;
        goto free;
    }    
    //len = header + key
    len = strlen((char *)temp);

    // to do : get local time
    sprintf((char *)date_from, "%04d%02d%02d%02d%02d%02d",
            2020,  1, 1, 0, 0, 0);

    sprintf((char *)date_to, "%04d%02d%02d%02d%02d%02d",
            2040, 1, 1, 0, 0, 0);

    sprintf((char *)name, "CN=%s", net_sprint_addr(AF_INET, &if_addr->address.in_addr));
    printk("Joy %s-%d\r\n", __func__, __LINE__);

    mbedtls_x509write_crt_init(&crt);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_mpi_init(&serial);

    if ((ret = mbedtls_mpi_read_string(&serial, 10, DEFAULT_CERT_SERIAL)) != 0)
    {
        printk("[SSL] failed! mpi_read_string returned -0x%02x\r\n", -ret);
        ret = -3;
        goto cleanup;
    }

    mbedtls_x509write_crt_set_subject_key(&crt, subject_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);

    if ((ret = mbedtls_x509write_crt_set_subject_name(&crt, (char *)name)) != 0)
    {
        printk("[SSL] failed! x509write_crt_set_subject_name returned -0x%02x\r\n", -ret);
        ret = -3;
        goto cleanup;
    }
    printk("Joy %s-%d\r\n", __func__, __LINE__);

    if ((ret = mbedtls_x509write_crt_set_issuer_name(&crt, (char *)name)) != 0)
    {
        printk("[SSL] failed! x509write_crt_set_issuer_name returned -0x%02x\r\n", -ret);
        ret = -3;
        goto cleanup;
    }

    if ((ret = mbedtls_x509write_crt_set_serial(&crt, &serial)) != 0)
    {
        printk("[SSL] failed! x509write_crt_set_serial returned -0x%02x\r\n", -ret);
        ret = -3;
        goto cleanup;
    }

    if ((ret = mbedtls_x509write_crt_set_validity(&crt, (char *)date_from, (char *)date_to)) != 0)
    {
        printk("[SSL] failed! x509write_crt_set_validity returned -0x%02x\r\n", -ret);
        ret = -3;
        goto cleanup;
    }
    if ((ret = mbedtls_x509write_crt_pem(&crt, temp + len, DEFAULT_CERT_PEM_SIZE, mbedtls_ctr_drbg_random, &ctr)) < 0)
    {
        printk("[SSL] failed! x509write_crt_pem returned -0x%02x\r\n", -ret);
        ret = -3;
        goto cleanup;
    }
    printk("Joy %s-%d\r\n", __func__, __LINE__);

    if ((ret = mbedtls_x509_crt_parse(&cert, temp + len, DEFAULT_CERT_PEM_SIZE)) != 0)
    {
        printk("[SSL] failed! x509_crt_parse returned -0x%02x\r\n", -ret);
        ret = -3;
        goto cleanup;
    }

    //len = header + key + cert
    len = strlen((char *)temp);
    printf("Joy %s-%d len =%d\r\n", __func__, __LINE__, len);
    if ((ret = write(fd, temp, len)) <= 0)
    {
        printk("[SSL] Save certificate fail(%d)\r\n", ret);
    }
    printk("Joy %s-%d, ret = %d, fd = %d len - %d\r\n", 
        __func__, __LINE__, ret, fd, len);

cleanup:
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&crt);
free:

    if (temp != NULL)
    {
        free(temp);
    }
    close(fd);
    return ret;

}

int mx_cert_mgmt_daemon(void *ptr)
{
    int c = 0, ret, inter, i;
    uint32_t ip;
    char active_ip[32] = {0};
    uint32_t my_ip[4] = {0};
    struct sockaddr_in addr_in;
#if __linux__
    X509 *x;
#endif    
    char _buf[64], tmp[64], cmd[64];
    struct tm tm, rootca_date, endtitiy_date;
    time_t t;
    int cert_mgmt_module_id;
#if __ZEPHYR__
    printk("Joy %s-%d\r\n", __func__, __LINE__);
    for (;;)
        sleep(5);
#endif
#if 1
#if USE_MX_NET        
    inter = net_max_interfaces();
    if (inter > 0) {
        for (i = 0; i < inter; i++) {
            net_get_my_ip(i, &my_ip[i]);
            printf("my_ip - %x\r\n", my_ip[i]);
        }
        addr_in.sin_addr.s_addr = my_ip[0];
        strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
        dbg_printf("active_ip = %s\r\n", active_ip);        
    } else { /* for docker */
        if (net_get_my_ip_by_ifname("eth0", &ip) == 0) {
            dbg_printf("Ok****net_get_my_ip_by_ifname - %x****\r\n", ip);
        } else {
            dbg_printf("Fail****net_get_my_ip_by_ifname ****\r\n");
        }
        addr_in.sin_addr.s_addr = ip;
        strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
        dbg_printf("active_ip = %s\r\n", active_ip);
    }
#else
    strcpy(active_ip, "192.168.127.1");
#endif  

    ret = mx_tell_cert_type(CERT_ENDENTITY_PEM_PATH);
    if (ret == CERT_TYPE_IMPORT) {
        dbg_printf("Certificate is Imported\r\n");
    } else {
        dbg_printf("Certificate is Self-Gened\r\n");
    }
    if (check_import(1) == 1) {   // Found import.
        goto ck_valid;
    }
    ret = check_certificate(1);
    if (ret == 1) { /* Certificate already exists in db */
        goto ck_valid;
    } else {
        /* Generate Key & CSR & sign cert & combine */
        printf("Generating certificate................\r\n");
#if __linux__
        mx_secure_enchance_embed_dev_d(CERT_ROOTCA_KEY_SECURE
			, CERT_ROOTCA_KEY_PATH);
#endif
#if USE_OPENSSL
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
	 sprintf(cmd, "rm %s", 
	            CERT_ROOTCA_KEY_PATH);
	 system(cmd);		
        if (ret < 0)
            return -1;
#else
#if 0
    {
        int rc;

        mbedtls_pk_init(&pkey);
        mbedtls_x509_crt_init(&cert);
        mbedtls_ctr_drbg_init(&ctr);	
        mbedtls_entropy_init(&entropy);

        mbedtls_entropy_add_source(&entropy, mbedtls_mx_hardclock_poll, NULL,
                               MBEDTLS_ENTROPY_MIN_PLATFORM,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);

        if ((rc = mbedtls_ctr_drbg_seed(&ctr,
                                        mbedtls_entropy_func,
                                        &entropy,
                                        (unsigned char *)DEFAULT_GEN_KEY_SEED_STR,
                                        strlen(DEFAULT_GEN_KEY_SEED_STR)))
                != 0) {
            printk("[SSL] Cannot seed rng rc %d %s\n", rc, MBEDTLS_CONFIG_FILE);
            return -1;
        }        
    }
#endif    
#endif
    }
ck_valid:
    /* Get rootca && end entity expiration date */
#ifdef OPTEE_DECRY_ENCRY
    ret = crypto_decryption(CERT_ENDENTITY_PEM_PATH, 
                                        CERT_ENDENTITY_TMP_PATH); 
    if (ret != 0) {
        printf("[Err] crypto_decryption %d\r\n", ret);   
        return ret;
    }        
#else
    ret = mx_do_decry_f(CERT_ENDENTITY_PEM_PATH);
    
    if (ret < 0)
        return ret;       
#endif
#if __linux__	
    x = TS_CONF_load_cert(CERT_ROOTCA_CERT_PATH);

    if (x == NULL)
    {
        printf("TS_CONF_load_cert(%s) failed!\n", CERT_ENDENTITY_TMP_PATH);

        return -1;
    }
#endif
    memset(tmp, 0 , sizeof(tmp));
    memset(_buf, 0 , sizeof(_buf));	
    memset(&rootca_date, 0 , sizeof(rootca_date));	
#if __linux__	
    ret = _ASN1_TIME_print(_buf, X509_get_notBefore(x));
    ret = _ASN1_TIME_print(_buf, X509_get_notAfter(x)); 

    ret = cert_get_valid_date(_buf, &rootca_date);
    strftime(tmp, sizeof(tmp), "rootca_date:%c\r\n", &rootca_date);
    X509_free(x);
    
    dbg_printf(tmp);
    
    x = TS_CONF_load_cert(CERT_ENDENTITY_TMP_PATH);
    unlink(CERT_ENDENTITY_TMP_PATH);
    if (x == NULL)
        return -1;
#endif
    memset(tmp, 0 , sizeof(tmp));
    memset(_buf, 0 , sizeof(_buf));	
    memset(&endtitiy_date, 0 , sizeof(endtitiy_date));		
#if __linux__
    ret = _ASN1_TIME_print(_buf, X509_get_notBefore(x));
    ret = _ASN1_TIME_print(_buf, X509_get_notAfter(x));   

    ret = cert_get_valid_date(_buf, &endtitiy_date);
    strftime(tmp, sizeof(tmp), "endtitiy_date:%c\r\n", &endtitiy_date);
    X509_free(x);
#endif
    dbg_printf(tmp);
     //sleep(CERT_SLEEP_5MIN);
    {
        char start[128], end[128], issueto[128], issueby[128];
        mx_get_cert_info(CERT_ENDENTITY_TMP_PATH, start, end, issueto, issueby);
        dbg_printf("Start=%s,End=%s, issueto=%s, issueby=%s\r\n", start, end, issueto, issueby);
    }
    while (!cert_mgmt_terminate) {
        /* compare the date between now and rootca/end entity */
        int ret;
        t = time(NULL);

        tm = *localtime(&t);
	 tm.tm_year = tm.tm_year + 1900;
	 tm.tm_mon = tm.tm_mon + 1;
	 rootca_date.tm_year = rootca_date.tm_year + 1900;
	 endtitiy_date.tm_year = endtitiy_date.tm_year + 1900;
	 
        //tm.tm_year += 20;
        strftime(tmp, sizeof(tmp), "now_date:%c\r\n", &tm);
        dbg_printf(tmp);
        ret = cert_ck_expire(&tm, &rootca_date);
        if (ret > 0) {
            dbg_printf("todo send for rootca will expired (%d)\r\n", ret);
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ROOTCA_WILL_EXPIRE);
#endif            
        } else if (ret < 0) {
            dbg_printf("todo send for rootca expired (%d)\r\n", ret);      
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ROOTCA_EXPIRE);
#endif
        }
        ret = cert_ck_expire(&tm, &endtitiy_date);
        if (ret > 0) {
            dbg_printf("todo send for end-cert will expired (%d)\r\n", ret);
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ENDCERT_WILL_EXPIRE);
#endif            
        } else if (ret < 0) {
            dbg_printf("todo send for end-cert expired (%d)\r\n", ret); 
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ENDCERT_EXPIRE);
#endif            
        }
        dbg_printf("now: %d-%02d-%02d %02d:%02d:%02d, checking expiration date...\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

        sleep(CERT_SLEEP_1DAY);
    }
    return 0;
#endif    
}

int mx_cert_mgmt_init(void)
{
    int ret;
    int cert_mgmt_module_id;
#if 0    
#if USE_MX_NET        
    inter = net_max_interfaces();
    if (inter > 0) {
        for (i = 0; i < inter; i++) {
            net_get_my_ip(i, &my_ip[i]);
            printf("my_ip - %x\r\n", my_ip[i]);
        }
        addr_in.sin_addr.s_addr = my_ip[0];
        strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
        dbg_printf("active_ip = %s\r\n", active_ip);        
    } else { /* for docker */
        if (net_get_my_ip_by_ifname("eth0", &ip) == 0) {
            dbg_printf("Ok****net_get_my_ip_by_ifname - %x****\r\n", ip);
        } else {
            dbg_printf("Fail****net_get_my_ip_by_ifname ****\r\n");
        }
        addr_in.sin_addr.s_addr = ip;
        strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
        dbg_printf("active_ip = %s\r\n", active_ip);
    }
#endif    
#endif
    mk_dir(CERT_ENDENTITY_RUN_DIR);
    mk_dir(SYSTEM_WRITABLE_FILES_PATH);
    mk_dir(CERT_ENDENTITY_RW_DIR);

    ret = cert_mgmt_rest_init("cert", &cert_mgmt_module_id);
    if (ret < 0)
        return EXIT_FAILURE;
#if __linux__    
    mx_cert_mgmt_daemon(NULL);
#else 
    printk("Joy %s-%d\r\n", __func__, __LINE__);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstack(&attr, thread_stack, CERTMGMT_THREAD_STACK_SIZE);
    pthread_create(&cert_mgmt_thread_idx, &attr, mx_cert_mgmt_daemon_test, NULL);
#endif /* __linux__ */

    return 0;

#if 0
    ret = mx_tell_cert_type(CERT_ENDENTITY_PEM_PATH);
    if (ret == CERT_TYPE_IMPORT) {
        dbg_printf("Certificate is Imported\r\n");
    } else {
        dbg_printf("Certificate is Self-Gened\r\n");
    }
    if (check_import(1) == 1) {   // Found import.
        goto ck_valid;
    }
    ret = check_certificate(1);
    if (ret == 1) { /* Certificate already exists in db */
        goto ck_valid;
    } else {
        /* Generate Key & CSR & sign cert & combine */
        printf("Generating certificate................\r\n");
#if __linux__
        mx_secure_enchance_embed_dev_d(CERT_ROOTCA_KEY_SECURE
			, CERT_ROOTCA_KEY_PATH);
#endif
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
	 sprintf(cmd, "rm %s", 
	            CERT_ROOTCA_KEY_PATH);
	 system(cmd);		
        if (ret < 0)
            return -1;
    }
ck_valid:
    /* Get rootca && end entity expiration date */
#ifdef OPTEE_DECRY_ENCRY
    ret = crypto_decryption(CERT_ENDENTITY_PEM_PATH, 
                                        CERT_ENDENTITY_TMP_PATH); 
    if (ret != 0) {
        printf("[Err] crypto_decryption %d\r\n", ret);   
        return ret;
    }        
#else
    ret = mx_do_decry_f(CERT_ENDENTITY_PEM_PATH);
    
    if (ret < 0)
        return ret;       
#endif
#if __linux__	
    x = TS_CONF_load_cert(CERT_ROOTCA_CERT_PATH);
//    x = TS_CONF_load_cert(CERT_ENDENTITY_TMP_PATH);
//    unlink(CERT_ENDENTITY_TMP_PATH);
    if (x == NULL)
    {
        printf("TS_CONF_load_cert(%s) failed!\n", CERT_ENDENTITY_TMP_PATH);
        /* net_get_my_mac() will not fill MAC if no interface found,
         * resulting in do_sha256() using different key each time called,
         * and certificate will not correctly decrpyted so
         * TS_CONF_load_cert(CERT_ENDENTITY_TMP_PATH) will return NULL.
         * Segmentation fault when calling X509_get_notBefore(NULL)
         * in the following */
        return -1;
    }
#endif
    memset(tmp, 0 , sizeof(tmp));
    memset(_buf, 0 , sizeof(_buf));	
    memset(&rootca_date, 0 , sizeof(rootca_date));	
#if __linux__	
    ret = _ASN1_TIME_print(_buf, X509_get_notBefore(x));
    ret = _ASN1_TIME_print(_buf, X509_get_notAfter(x)); 

    ret = cert_get_valid_date(_buf, &rootca_date);
    strftime(tmp, sizeof(tmp), "rootca_date:%c\r\n", &rootca_date);
    X509_free(x);
    
    dbg_printf(tmp);
//    x = TS_CONF_load_cert(CERT_ROOTCA_CERT_PATH);
    x = TS_CONF_load_cert(CERT_ENDENTITY_TMP_PATH);
    unlink(CERT_ENDENTITY_TMP_PATH);
    if (x == NULL)
        return -1;
#endif
    memset(tmp, 0 , sizeof(tmp));
    memset(_buf, 0 , sizeof(_buf));	
    memset(&endtitiy_date, 0 , sizeof(endtitiy_date));		
#if __linux__
    ret = _ASN1_TIME_print(_buf, X509_get_notBefore(x));
    ret = _ASN1_TIME_print(_buf, X509_get_notAfter(x));   

    ret = cert_get_valid_date(_buf, &endtitiy_date);
    strftime(tmp, sizeof(tmp), "endtitiy_date:%c\r\n", &endtitiy_date);
    X509_free(x);
#endif
    dbg_printf(tmp);
     //sleep(CERT_SLEEP_5MIN);
    {
        char start[128], end[128], issueto[128], issueby[128];
        mx_get_cert_info(CERT_ENDENTITY_TMP_PATH, start, end, issueto, issueby);
        dbg_printf("Start=%s,End=%s, issueto=%s, issueby=%s\r\n", start, end, issueto, issueby);
    }
    while (!cert_mgmt_terminate) {
        /* compare the date between now and rootca/end entity */
        int ret;
        t = time(NULL);

        tm = *localtime(&t);
	 tm.tm_year = tm.tm_year + 1900;
	 tm.tm_mon = tm.tm_mon + 1;
	 rootca_date.tm_year = rootca_date.tm_year + 1900;
	 endtitiy_date.tm_year = endtitiy_date.tm_year + 1900;
	 
        //tm.tm_year += 20;
        strftime(tmp, sizeof(tmp), "now_date:%c\r\n", &tm);
        dbg_printf(tmp);
        ret = cert_ck_expire(&tm, &rootca_date);
        if (ret > 0) {
            dbg_printf("todo send for rootca will expired (%d)\r\n", ret);
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ROOTCA_WILL_EXPIRE);
#endif            
        } else if (ret < 0) {
            dbg_printf("todo send for rootca expired (%d)\r\n", ret);      
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ROOTCA_EXPIRE);
#endif
        }
        ret = cert_ck_expire(&tm, &endtitiy_date);
        if (ret > 0) {
            dbg_printf("todo send for end-cert will expired (%d)\r\n", ret);
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ENDCERT_WILL_EXPIRE);
#endif            
        } else if (ret < 0) {
            dbg_printf("todo send for end-cert expired (%d)\r\n", ret); 
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ENDCERT_EXPIRE);
#endif            
        }
        dbg_printf("now: %d-%02d-%02d %02d:%02d:%02d, checking expiration date...\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

        sleep(CERT_SLEEP_1DAY);
    }
    return 0;
#endif    
}

#if __linux__
int main(int argc, char *argv[])
{
    int c = 0, ret, inter, i;
    uint32_t ip;
    char active_ip[32] = {0};
    uint32_t my_ip[4] = {0};
    struct sockaddr_in addr_in;
#if __linux__
    X509 *x;
#endif    
    char _buf[64], tmp[64], cmd[64];
    struct tm tm, rootca_date, endtitiy_date;
    time_t t;
    int cert_mgmt_module_id;
    
    dbg_printf("%s-%d, version=%s\r\n", __func__, __LINE__,VERSION);

    /*
     * Terminate the program when user tries to end it by pressing Ctrl+C.
     */
#if __linux__
    signal(SIGINT, sigquit_handler);     /* Ctrl+C: interrupt program, num=2 */
    signal(SIGQUIT, sigquit_handler);    /* quit program, num=3 */
    signal(SIGTERM, sigquit_handler);    /* kill: terminate program, num=15 */
#endif    
    //system("apt-get install -y net-tools > /null");
#if __linux__    
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
    fprintf(stderr, "mx-cert-mgmt daemon running...\n");

    mx_cert_mgmt_init();
    
    exit(EXIT_SUCCESS);
#endif    
#if 0
#if USE_MX_NET        
    inter = net_max_interfaces();
    if (inter > 0) {
        for (i = 0; i < inter; i++) {
            net_get_my_ip(i, &my_ip[i]);
            printf("my_ip - %x\r\n", my_ip[i]);
        }
        addr_in.sin_addr.s_addr = my_ip[0];
        strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
        dbg_printf("active_ip = %s\r\n", active_ip);        
    } else { /* for docker */
        if (net_get_my_ip_by_ifname("eth0", &ip) == 0) {
            dbg_printf("Ok****net_get_my_ip_by_ifname - %x****\r\n", ip);
        } else {
            dbg_printf("Fail****net_get_my_ip_by_ifname ****\r\n");
        }
        addr_in.sin_addr.s_addr = ip;
        strncpy(active_ip, inet_ntoa(addr_in.sin_addr), sizeof(active_ip));
        dbg_printf("active_ip = %s\r\n", active_ip);
    }
#endif    
    mk_dir(CERT_ENDENTITY_RUN_DIR);
    mk_dir(SYSTEM_WRITABLE_FILES_PATH);
    mk_dir(CERT_ENDENTITY_RW_DIR);

    ret = cert_mgmt_rest_init("cert", &cert_mgmt_module_id);
    if (ret < 0)
        return EXIT_FAILURE;
    //mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ROOTCA_WILL_EXPIRE);
#if 0 
    sprintf(cmd, "openssl genrsa -out %s %d", 
                CERT_ROOTCA_KEY_PATH,
                CERT_ROOTCA_KEY_LENGTH);
    system(cmd);

    sprintf(cmd, "openssl req -new -x509 -key %s -days %d -sha256 \
                -extensions v3_ca -out %s \
                -subj /C=TW/ST=Taiwan/L="New Taipei"/O=Moxa/OU=MGate/CN=\"Moxa Inc.\"/emailAddress=taiwan@moxa.com",
                CERT_ROOTCA_KEY_PATH,
                CERT_ROOTCA_VALID_DAY,
                CERT_ROOTCA_CERT_PATH);
    system(cmd);            
#endif
    ret = mx_tell_cert_type(CERT_ENDENTITY_PEM_PATH);
    if (ret == CERT_TYPE_IMPORT) {
        dbg_printf("Certificate is Imported\r\n");
    } else {
        dbg_printf("Certificate is Self-Gened\r\n");
    }
    if (check_import(1) == 1) {   // Found import.
        goto ck_valid;
    }
    ret = check_certificate(1);
    if (ret == 1) { /* Certificate already exists in db */
        goto ck_valid;
    } else {
        /* Generate Key & CSR & sign cert & combine */
        printf("Generating certificate................\r\n");
#if __linux__
        mx_secure_enchance_embed_dev_d(CERT_ROOTCA_KEY_SECURE
			, CERT_ROOTCA_KEY_PATH);
#endif
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
	 sprintf(cmd, "rm %s", 
	            CERT_ROOTCA_KEY_PATH);
	 system(cmd);		
        if (ret < 0)
            return -1;
    }
ck_valid:
    /* Get rootca && end entity expiration date */
#ifdef OPTEE_DECRY_ENCRY
    ret = crypto_decryption(CERT_ENDENTITY_PEM_PATH, 
                                        CERT_ENDENTITY_TMP_PATH); 
    if (ret != 0) {
        printf("[Err] crypto_decryption %d\r\n", ret);   
        return ret;
    }        
#else
    ret = mx_do_decry_f(CERT_ENDENTITY_PEM_PATH);
    
    if (ret < 0)
        return ret;       
#endif
#if __linux__	
    x = TS_CONF_load_cert(CERT_ROOTCA_CERT_PATH);
//    x = TS_CONF_load_cert(CERT_ENDENTITY_TMP_PATH);
//    unlink(CERT_ENDENTITY_TMP_PATH);
    if (x == NULL)
    {
        printf("TS_CONF_load_cert(%s) failed!\n", CERT_ENDENTITY_TMP_PATH);
        /* net_get_my_mac() will not fill MAC if no interface found,
         * resulting in do_sha256() using different key each time called,
         * and certificate will not correctly decrpyted so
         * TS_CONF_load_cert(CERT_ENDENTITY_TMP_PATH) will return NULL.
         * Segmentation fault when calling X509_get_notBefore(NULL)
         * in the following */
        return -1;
    }
#endif
    memset(tmp, 0 , sizeof(tmp));
    memset(_buf, 0 , sizeof(_buf));	
    memset(&rootca_date, 0 , sizeof(rootca_date));	
#if __linux__	
    ret = _ASN1_TIME_print(_buf, X509_get_notBefore(x));
    ret = _ASN1_TIME_print(_buf, X509_get_notAfter(x)); 

    ret = cert_get_valid_date(_buf, &rootca_date);
    strftime(tmp, sizeof(tmp), "rootca_date:%c\r\n", &rootca_date);
    X509_free(x);
    
    dbg_printf(tmp);
//    x = TS_CONF_load_cert(CERT_ROOTCA_CERT_PATH);
    x = TS_CONF_load_cert(CERT_ENDENTITY_TMP_PATH);
    unlink(CERT_ENDENTITY_TMP_PATH);
    if (x == NULL)
        return -1;
#endif
    memset(tmp, 0 , sizeof(tmp));
    memset(_buf, 0 , sizeof(_buf));	
    memset(&endtitiy_date, 0 , sizeof(endtitiy_date));		
#if __linux__
    ret = _ASN1_TIME_print(_buf, X509_get_notBefore(x));
    ret = _ASN1_TIME_print(_buf, X509_get_notAfter(x));   

    ret = cert_get_valid_date(_buf, &endtitiy_date);
    strftime(tmp, sizeof(tmp), "endtitiy_date:%c\r\n", &endtitiy_date);
    X509_free(x);
#endif
    dbg_printf(tmp);
     //sleep(CERT_SLEEP_5MIN);
    {
        char start[128], end[128], issueto[128], issueby[128];
        mx_get_cert_info(CERT_ENDENTITY_TMP_PATH, start, end, issueto, issueby);
        dbg_printf("Start=%s,End=%s, issueto=%s, issueby=%s\r\n", start, end, issueto, issueby);
    }
    while (!cert_mgmt_terminate) {
        /* compare the date between now and rootca/end entity */
        int ret;
        t = time(NULL);

        tm = *localtime(&t);
	 tm.tm_year = tm.tm_year + 1900;
	 tm.tm_mon = tm.tm_mon + 1;
	 rootca_date.tm_year = rootca_date.tm_year + 1900;
	 endtitiy_date.tm_year = endtitiy_date.tm_year + 1900;
	 
        //tm.tm_year += 20;
        strftime(tmp, sizeof(tmp), "now_date:%c\r\n", &tm);
        dbg_printf(tmp);
        ret = cert_ck_expire(&tm, &rootca_date);
        if (ret > 0) {
            dbg_printf("todo send for rootca will expired (%d)\r\n", ret);
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ROOTCA_WILL_EXPIRE);
#endif            
        } else if (ret < 0) {
            dbg_printf("todo send for rootca expired (%d)\r\n", ret);      
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ROOTCA_EXPIRE);
#endif
        }
        ret = cert_ck_expire(&tm, &endtitiy_date);
        if (ret > 0) {
            dbg_printf("todo send for end-cert will expired (%d)\r\n", ret);
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ENDCERT_WILL_EXPIRE);
#endif            
        } else if (ret < 0) {
            dbg_printf("todo send for end-cert expired (%d)\r\n", ret); 
#if USE_MX_EVENT_AGENT            
            mx_cert_event_notify(MX_CERT_EVENT_NOTIFY_ENDCERT_EXPIRE);
#endif            
        }
        dbg_printf("now: %d-%02d-%02d %02d:%02d:%02d, checking expiration date...\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

        sleep(CERT_SLEEP_1DAY);
    }
    return 0;
#endif    
}
#endif
