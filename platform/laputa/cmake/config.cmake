# project config

# define file authentication key size
set(DEFINE_VALUE_FILE_AUTH_SIZEM 32)

# crypto library use openssl
set (ENABLE_OPENSSL 1)

# crypto library use mbedtls
set (ENABLE_MBEDTLS 0)

# debug printf define
set (ENABLE_DEBUG_LOG 0)

# error printf define
set (ENABLE_ERROR_LOG 1)

# link mx-rest
set (LINK_MX_REST 1)

# link mx-event
set (LINK_MX_EVENT 1)

# link mx-platform for optee_aes enc/dec file
set (LINK_MX_PLATFORM 1)

# link lib cfgapi
set (LINK_MX_CFGAPI 1)

# disable zephyr
set (OS_PLATFORM_ZEPHYR 0)

# enable linux
set (OS_PLATFORM_LINUX 1)

# config version
set (CFG_CERT_VERSION "1.0")

# rest version
set(CFG_REST_VERSION "1.0")
