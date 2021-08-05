cmake_minimum_required(VERSION 3.12)
project(mx-timed VERSION 0.0.0 LANGUAGES C)

set (PROJECT_ROOT ${CMAKE_SOURCE_DIR}/../..)

include_directories(
    ${PROJECT_ROOT}/include/
)

set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT}/build)

set(SOURCE_CODE_LIST
    ${PROJECT_ROOT}/src/mx_timed_main.c
)

add_compile_definitions(
	MX_TIMED_VERSION="${PROJECT_VERSION}"
)

add_executable(${PROJECT_NAME} ${SOURCE_CODE_LIST})
