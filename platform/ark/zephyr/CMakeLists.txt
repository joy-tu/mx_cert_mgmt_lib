target_include_directories(app PUBLIC ${CMAKE_CURRENT_LIST_DIR})

file(GLOB SOURCE_LIST
    mx_cert_mgmt_event.c
    mx_cert_mgmt_event.h
    mx_cert_mgmt_lib.c
    mx_cert_mgmt_lib.h
    #    mx_cert_mgmt_main.c
    mx_cert_mgmt_rest.c
)

target_sources(app PRIVATE ${SOURCE_LIST})
