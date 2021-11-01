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
    #${PROJECT_ROOT}/src/mx_xxx.c
)

set(LIB_SOURCE_CODE_LIST
    ${PROJECT_ROOT}/src/mx_cert_mgmt_lib.c
    ${PROJECT_ROOT}/src/mx_cert_mgmt_rest.c
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
	#    "mx-event-agent"
    ${MXCERT_LIB} 
    "parson"
    "ssl"
    "crypto"
    "mx-net"
)

set(LINK_MXLIB_LIST
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
    FILES ../../include/mx_cert_mgmt/mx_cert_mgmt_rest.h
    DESTINATION /usr/include/mx_cert_mgmt/
    COMPONENT lib
)
set(CPACK_GENERATOR "DEB")
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Joy Tu")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
include(CPack)

# test client
#add_executable("mxtimec" ${PROJECT_ROOT}/src/mx_timed_client.c)
#
#target_link_libraries("mxtimec" ${LINK_LIB_LIST})
