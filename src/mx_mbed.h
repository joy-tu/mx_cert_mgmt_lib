/**
 * \file
 * Initialize SSL connection with MbedTLS Module
 *
 * \copyright
 * Copyright (C) MOXA Inc. All rights reserved.
 * This software is distributed under the terms of the
 * MOXA License.  See the file COPYING-MOXA for details.
 *
 */

#ifndef _MX_MBED_H_
#define _MX_MBED_H_

#include <zephyr/kernel.h>
#include <errno.h>
#include <zephyr/posix/unistd.h>
#include <zephyr/posix/time.h>
#include <zephyr/posix/sys/time.h>
#include <zephyr/syscall_handler.h>
#include <mbedtls/mbedtls_config.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/platform.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef mbedtls_ssl_context SSL;

typedef struct
{
    mbedtls_ssl_config          conf;           /* SSL configuration */
    mbedtls_x509_crt            cert;           /* Certificate (own) */
    mbedtls_ctr_drbg_context    ctr;            /* Counter random generator state */
    mbedtls_entropy_context     entropy;        /* Entropy context */
    mbedtls_pk_context          pkey;           /* Private key */
} SSL_CTX;

int mbed_sslctx_init(SSL_CTX *ctx, const char *crt);
void mbed_sslctx_uninit(SSL_CTX *ctx);
void mbed_ssl_close(mbedtls_ssl_context *ssl);
int mbed_ssl_accept(mbedtls_ssl_context **ssl, SSL_CTX *ssl_ctx, int *sock, void *phys_ctx);
int mbed_ssl_read(mbedtls_ssl_context *ssl, unsigned char *buf, int len);
int mbed_ssl_write(mbedtls_ssl_context *ssl, const unsigned char *buf, int len);
void mbed_ssl_pre_gen_key(SSL_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif  /* _MX_MBED_H */
