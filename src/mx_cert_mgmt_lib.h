#ifndef __MX_CERT_MGMT_LIG_H__
#define __MX_CERT_MGMT_LIG_H__
#include <def/mx_def.h>

/*****************************************************************************
 * Definition
 ****************************************************************************/
#define OPTEE_DECRY_ENCRY 1
#define CERT_SEED_PATH SYSTEM_READ_ONLY_FILES_PATH"cert/seed" 
//#define CERT_ROOTCA_KEY_PATH SYSTEM_DEFAULT_FILES_PATH"/cm/rootca.key"
#define CERT_ROOTCA_KEY_PATH SYSTEM_TEMP_FILES_PATH"/ee_dev"
//#define CERT_ROOTCA_CERT_PATH SYSTEM_DEFAULT_FILES_PATH"/cm/rootca.pem"
#define CERT_ROOTCA_CERT_PATH SYSTEM_DEFAULT_FILES_PATH"/cm/secure_ee_dev_all"
#define CERT_ROOTCA_KEY_SECURE SYSTEM_DEFAULT_FILES_PATH"/cm/secure_ee_dev"
#define CERT_ENDENTITY_VALID_DAY 365 * 5
#define CERT_ENDENTITY_KEY_LENGTH 2048
#define CERT_ENDENTITY_RUN_DIR SYSTEM_TMPFS_PATH"/cert"
#define CERT_ENDENTITY_RW_DIR SYSTEM_WRITABLE_FILES_PATH"/cert"
#define CERT_ENDENTITY_RWTEST_DIR SYSTEM_WRITABLE_FILES_PATH"/joy"
#define CA_SERIAL_TMP_PATH SYSTEM_TMPFS_PATH"/cert/ca.serial"
#define CERT_ENDENTITY_TMP_PATH SYSTEM_TMPFS_PATH"/cert/tmp.pem"
#define CERT_ENDENTITY_KEY_PATH SYSTEM_TMPFS_PATH"/cert/endentity.key"
#define CERT_ENDENTITY_CSR_PATH SYSTEM_TMPFS_PATH"/cert/endentity.csr"
#define CERT_ENDENTITY_CERT_PATH SYSTEM_TMPFS_PATH"/cert/endentity.cert"
#define CERT_ENDENTITY_PEM_PATH SYSTEM_WRITABLE_FILES_PATH"/cert/endentity.pem"

#define CERT_TYPE_IMPORT 1
#define CERT_TYPE_SELFGEN 2 
#if 0
typedef enum
{
    CERT_REST_OK                                = 0,
    CERT_REST_PARAM_FAIL                = -1,
    CERT_REST_INIT_FAIL                  = -2,
    CERT_REST_CB_REGISTER_FAIL           = -3,
    CERT_REST_GET_VAL_FAIL               = -4,
    CERT_REST_SET_VAL_FAIL               = -5,
    CERT_REST_TYPE_CONVERT_FAIL          = -6,
    CERT_REST_MALLOC_FAIL                = -7,
    CERT_REST_VAL_OUT_OF_RANGE           = -8,
    CERT_REST_JSON_FAIL                         = -9,
    CERT_REST_FILE_NOT_EXIST                    = -10,
    CERT_REST_PEM_NOT_INSTALLED            = -11
} CERT_REST_RET;
#endif
/*****************************************************************************
 * Public functions
 ****************************************************************************/
int mx_get_cert_info(char *certpath, char *start, char *end, char *issueto, char *issueby);
void mx_cert_sign_cert(char *csr_path, char *rootcert_path, char *rootkey_path,
                                        int valid_day, char *cert_path, char *ip);
void mx_cert_gen_csr(char *keypath, char *csrpath, char *ip);
void mx_cert_gen_priv_key(char *path, int len);
int mx_cert_combine_ip_key_cert(char *pem_path, char *ip, 
                      char *key_path, char *cert_path);
int mx_import_cert(char *fname, char* data, int len, char *errStr, int errlen);
int mx_cert_del(char *fname/*int cert_idx*/);
int mx_regen_cert(void);
int mx_tell_cert_type(char *fname);
int mx_do_encry(char *certpath);
int mx_do_encry_ex(char *certpath, char *outpath, int flag);

int mx_do_decry_b(char *certpath, unsigned char *cert_ram);

int mx_do_decry_f(char *certpath);
int mx_do_decry_f_ex(char *certpath, char *outpath);

int mx_secure_enchance_embed_dev_d(char *certpath, char *outpath);
int mx_secure_enchance_embed_dev_e(char *certpath, char *outpath, int flag);

#endif //__MX_CERT_MGMT_LIG_H__
