cmake_minimum_required(VERSION 3.12)
project(mx-cert-mgmtd VERSION 0.0.1 LANGUAGES C)

set (PROJECT_ROOT ${CMAKE_SOURCE_DIR}/../..)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../../scripts")
#include(astyle)
set(MXCERT_LIB "rest-cert")

include_directories(
    ${PROJECT_ROOT}/include/
    ${PROJECT_ROOT}/src/
    #    ${PROJECT_ROOT}/../include/ # remove after release
)

set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(SOURCE_CODE_LIST
    ${PROJECT_ROOT}/src/mx_cert_mgmt_main.c

    ${PROJECT_ROOT}/src/mx_cert_mgmt_rest.c
    #${PROJECT_ROOT}/src/mx_lldp_event.c
    ${PROJECT_ROOT}/src/mx_cert_mgmt_event.c
    #${PROJECT_ROOT}/src/mx_xxx.c
)

set(LIB_SOURCE_CODE_LIST
    ${PROJECT_ROOT}/src/mx_cert_mgmt_lib.c
    #${PROJECT_ROOT}/src/mx_cert_mgmt_rest.c
    #${PROJECT_ROOT}/src/mx_lldp_event.c
    ${PROJECT_ROOT}/src/mx_cert_mgmt_event.c
    #${PROJECT_ROOT}/src/mx_xxx_xxx.c
)

add_library(${MXCERT_LIB} SHARED ${LIB_SOURCE_CODE_LIST})

target_include_directories(
    ${MXCERT_LIB} PRIVATE
    ${PROJECT_ROOT}/include/
    ${PROJECT_ROOT}/src/
)

set_target_properties(
    ${MXCERT_LIB}
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON
    #    PUBLIC_HEADER ${PROJECT_ROOT}/include/mx_timed/mx_timed_intf.h
)


# TODO: add fPIC?
#set_property(TARGET mxtimed PROPERTY POSITION_INDEPENDENT_CODE ON)

set(LINK_LIB_LIST
    "mx-event-agent"
    ${MXCERT_LIB}
    "parson"
    "ssl"
    "crypto"
    "mx-net"
)

set(LINK_MXLIB_LIST
    "mx-event-agent"
    "parson"
    "ssl"
    "crypto"
    "mx-net"
    "rest"
)

add_compile_definitions(
	VERSION="${PROJECT_VERSION}"
)

add_executable(${PROJECT_NAME} ${SOURCE_CODE_LIST})

target_link_libraries(${PROJECT_NAME} ${LINK_LIB_LIST})
target_link_libraries(${MXCERT_LIB} ${LINK_MXLIB_LIST})
# main app
install(
    TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION /usr/bin
    COMPONENT app
)

# Library
#install(
#   TARGETS "mxcert"
#   LIBRARY DESTINATION /usr/lib
#   COMPONENT lib
#)

install(
    TARGETS ${MXCERT_LIB}
    LIBRARY DESTINATION /usr/lib
    COMPONENT lib
)

install(
    FILES ../../rootca/rootca.key
    DESTINATION /cert
    COMPONENT lib
)


install(
    FILES ../../rootca/rootca.pem
    DESTINATION /cert
    COMPONENT lib
)

install(
    FILES ../../seed/seed
    DESTINATION /cert
    COMPONENT lib
)

install(
	#    FILES ../../include/mx_cert_mgmt/mx_cert_mgmt_rest.h ../../src/mx_cert_mgmt_lib.h
    FILES ../../src/mx_cert_mgmt_lib.h
    DESTINATION /usr/include/mx_cert_mgmt/
    COMPONENT dev
)
set(CPACK_GENERATOR "DEB")
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Joy Tu")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
#####################################################
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Joy Tu <joy.tu@moxa.com>")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "Moxa Certificate Daemon & Library")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.3.1-6), libc6 (<< 3)")
#set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
#set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
#set(CMAKE_INSTALL_RPATH "/usr/lib")
set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS_POLICY ">=")


# version
#set(CPACK_DEBIAN_PACKAGE_RELEASE 3)

# lib
set(CPACK_DEBIAN_LIB_PACKAGE_NAME "mx-cert-mgmtd-lib")
set(CPACK_DEBIAN_LIB_PACKAGE_DEPENDS "libparson1, libmx-rest1, mx-event, libmx-net1")
set(CPACK_DEBIAN_LIB_DESCRIPTION "Moxa Cert Mgmt Library")

# daemon
set(CPACK_DEBIAN_APP_PACKAGE_NAME "mx-cert-mgmtd-app")
set(CPACK_DEBIAN_APP_PACKAGE_DEPENDS "libparson1, libmx-rest1, libmx-net1, mx-event, mx-cert-mgmtd-lib")
set(CPACK_DEBIAN_APP_DESCRIPTION "Moxa Cert Mgmt Daemon")

# dev
set(CPACK_DEBIAN_DEV_PACKAGE_NAME "mx-cert-mgmtd-dev")
set(CPACK_DEBIAN_DEV_PACKAGE_DEPENDS "mx-cert-mgmtd-lib")
set(CPACK_DEBIAN_DEV_DESCRIPTION "Moxa Cert Mgmt Library Development")

set(CPACK_DEBIAN_PACKAGE_DEBUG ON)
set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wformat=0 -Os")
add_compile_options(-Wall -Werror)
include(CPack)

# test client
#add_executable("mxtimec" ${PROJECT_ROOT}/src/mx_timed_client.c)
#
#target_link_libraries("mxtimec" ${LINK_LIB_LIST})
