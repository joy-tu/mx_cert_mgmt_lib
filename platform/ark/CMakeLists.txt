cmake_minimum_required(VERSION 3.12)
project(mx_cert_mgmt VERSION 1.1.0 LANGUAGES C)

set(PROJECT_ROOT ${CMAKE_SOURCE_DIR}/../..)
# current platform is ARK
set(PLATFORM_NAME "ark")

# project release folder for ark
set(PROJECT_RELEASE "release")
set(PROJECT_RELEASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_RELEASE})
set(PROJECT_RELEASE_FOR_ARK_DIR ${PROJECT_RELEASE_DIR}/${PLATFORM_NAME}/${PROJECT_NAME})

# project release folder for file need to put in root-filesystem
set(ROOTFILES "rootfile")
set(ROOTFILES_DIR ${PROJECT_RELEASE_DIR}/${PLATFORM_NAME}/${ROOTFILES})

# SCM upload folder directory
set(SCM_UPLOAD_DIR ${PROJECT_ROOT}/upload)
# SRC_SCM_ARTIFACT_DIR: project release source code directory
set(SRC_SCM_ARTIFACT_DIR ${SCM_UPLOAD_DIR})

# re-init release folder
if(IS_DIRECTORY ${PROJECT_RELEASE_DIR})
    message("re-init ark release folder")
    file(REMOVE_RECURSE ${PROJECT_RELEASE_DIR}})
endif()

# re-init scm folder
if(IS_DIRECTORY ${SCM_UPLOAD_DIR})
    message("re-init scm folder")
    file(REMOVE_RECURSE ${SCM_UPLOAD_DIR})
endif()

# mkdir directory
message(${PROJECT_RELEASE_DIR})
file(MAKE_DIRECTORY ${PROJECT_RELEASE_DIR})
message(${SCM_UPLOAD_DIR})
file(MAKE_DIRECTORY ${SCM_UPLOAD_DIR})
message(${SRC_SCM_ARTIFACT_DIR})
file(MAKE_DIRECTORY ${SRC_SCM_ARTIFACT_DIR})
message(${PROJECT_RELEASE_FOR_ARK_DIR})
file(MAKE_DIRECTORY ${PROJECT_RELEASE_FOR_ARK_DIR})
message(${ROOTFILES_DIR})
file(MAKE_DIRECTORY ${ROOTFILES_DIR})

# cmake config
include(cmake/config.cmake)
configure_file(config.h.in ${PROJECT_ROOT}/include/mx_cert_mgmt/conf.h)

add_custom_target(SrcCodeArtifacts

    # copy source code file_directory
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_ROOT}/src ${PROJECT_RELEASE_FOR_ARK_DIR}

    # copy all header in directory
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_ROOT}/include/mx_cert_mgmt ${PROJECT_RELEASE_FOR_ARK_DIR}

    # copy ark-zephyr CMakelists.txt
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/zephyr/CMakeLists.txt ${PROJECT_RELEASE_FOR_ARK_DIR}

    # copy all file in release directory to scm upload foder
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_RELEASE_DIR} ${SRC_SCM_ARTIFACT_DIR}
)
