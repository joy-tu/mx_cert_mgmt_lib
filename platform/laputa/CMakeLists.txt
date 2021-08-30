cmake_minimum_required(VERSION 3.12)
project(mx-timed VERSION 0.0.0 LANGUAGES C)

set (PROJECT_ROOT ${CMAKE_SOURCE_DIR}/../..)

include_directories(
    ${PROJECT_ROOT}/include/
    ${PROJECT_ROOT}/src/
    ${PROJECT_ROOT}/../include/ # remove after release
)

set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT}/build)

set(SOURCE_CODE_LIST
    ${PROJECT_ROOT}/src/mx_timed_event.c
    ${PROJECT_ROOT}/src/mx_timed_config.c
    ${PROJECT_ROOT}/src/mx_timed_main.c
    ${PROJECT_ROOT}/src/mx_timed.c
)

set(LIB_SOURCE_CODE_LIST
    ${PROJECT_ROOT}/src/mx_timed_db.c
    ${PROJECT_ROOT}/src/mx_timed_intf.c
)

add_library("mxtimed" SHARED ${LIB_SOURCE_CODE_LIST})

# TODO: add fPIC?
#set_property(TARGET mxtimed PROPERTY POSITION_INDEPENDENT_CODE ON)

set(LINK_LIB_LIST
    "pthread"
    "mxtimed"
    "parson"
)

add_compile_definitions(
	MX_TIMED_VERSION="${PROJECT_VERSION}"
)

add_executable(${PROJECT_NAME} ${SOURCE_CODE_LIST})

target_link_libraries(${PROJECT_NAME} ${LINK_LIB_LIST})
