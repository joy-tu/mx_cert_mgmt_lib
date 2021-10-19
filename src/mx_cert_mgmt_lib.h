#ifndef __MX_CERT_MGMT_LIG_H__
#define __MX_CERT_MGMT_LIG_H__
#include <def/mx_def.h>
/*****************************************************************************
 * Definition
 ****************************************************************************/
#define CERT_ROOTCA_KEY_PATH SYSTEM_READ_ONLY_FILES_PATH"cert/rootca.key"
#define CERT_ROOTCA_CERT_PATH SYSTEM_READ_ONLY_FILES_PATH"cert/rootca.pem"
#define CERT_ENDENTITY_VALID_DAY 365 * 5
#define CERT_ENDENTITY_KEY_LENGTH 2048
#define CERT_ENDENTITY_TMP_PATH SYSTEM_TMPFS_PATH"/cert/tmp.pem"
#define CERT_ENDENTITY_KEY_PATH SYSTEM_TMPFS_PATH"/cert/endentity.key"
#define CERT_ENDENTITY_CSR_PATH SYSTEM_TMPFS_PATH"/cert/endentity.csr"
#define CERT_ENDENTITY_CERT_PATH SYSTEM_TMPFS_PATH"/cert/endentity.cert"
#define CERT_ENDENTITY_PEM_PATH SYSTEM_WRITABLE_FILES_PATH"/cert/endentity.pem"

#define CERT_TYPE_IMPORT 1
#define CERT_TYPE_SELFGEN 2 

/*****************************************************************************
 * Public functions
 ****************************************************************************/
void mx_cert_sign_cert(char *csr_path, char *rootcert_path, char *rootkey_path,
                                        int valid_day, char *cert_path) ;                   
void mx_cert_gen_csr(char *keypath, char *csrpath);
void mx_cert_gen_priv_key(char *path, int len);
int mx_cert_combine_ip_key_cert(char *pem_path, char *ip, 
                      char *key_path, char *cert_path);
int mx_import_cert(char *fname, char* data, int len, char *errStr, int errlen);
int mx_cert_del(char *fname/*int cert_idx*/);
int mx_regen_cert(void);
int mx_tell_cert_type(char *fname);
int mx_do_encry(char *certpath);
int mx_do_decry_b(char *certpath, unsigned char *cert_ram);
int mx_do_decry_f(char *certpath);
#endif //__MX_CERT_MGMT_LIG_H__
