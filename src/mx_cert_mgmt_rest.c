/**
 * @file mx_cert_mgmt_rest.c
 * @brief Moxa Certificate Management REST API
 * @copyright Copyright (C) MOXA Inc. All rights reserved.
 * @license This software is distributed under the terms of the MOXA License. See the file COPYING-MOXA for details.
 * @author Joy Tu
 * @date 2021-10-28
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sysexits.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
 #include <sys/ioctl.h>/* FIONREAD */
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/sockios.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <def/mx_def.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <rest/rest_parser.h>
#include <rest/multipart_parser.h>
#include <parson.h>
#include "mx_cert_mgmt_lib.h"
 /*****************************************************************************
 * Definition
 ****************************************************************************/
#define RESPONSE                            "response"
#define DATA                                "data"
#define ERROR                   "error"
#define MESSAGE                 "message"
#define RESPONSE_INVALID    "response data is invalid"
#define CANOPEN_OPTION_RESPONSE_SUCCESS                "success"
#define DATA_NESTED_RESPONSE      DATA"."RESPONSE
#define NESTED_MESSAGE                  ERROR"."MESSAGE
#define BUF_SZ 512

#ifdef DEBUG_MX_CERT_MGMT
#define dbg_printf  printf
#else
#define dbg_printf(...) 
#endif
/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/
static CERT_REST_RET create_output(JSON_Value **output_val, JSON_Object **output_obj)
{
    if (output_val == NULL) {
        dbg_printf("param fail\n");
        return CERT_REST_PARAM_FAIL;
    }

    if (output_obj == NULL) {
        dbg_printf("param fail\n");
        return CERT_REST_PARAM_FAIL;
    }

    if ((*output_val = json_value_init_object()) == NULL) {
        dbg_printf("get output_val fail\n");
        return CERT_REST_INIT_FAIL;
    }

    if ((*output_obj = json_value_get_object(*output_val)) == NULL) {
        dbg_printf("get output_obj fail\n");
        return CERT_REST_GET_VAL_FAIL;
    }

    return CERT_REST_OK;
}

static CERT_REST_RET create_output_error_message(char **jsonptr, char *error_message)
{
    JSON_Value *output_val = NULL;
    JSON_Object *output_obj;

    if (jsonptr == NULL) {
        dbg_printf("param fail\n");
        return CERT_REST_PARAM_FAIL;
    }

    if (error_message == NULL) {
        dbg_printf("param fail\n");
        return CERT_REST_PARAM_FAIL;
    }

    if ((output_val = json_value_init_object()) == NULL) {
        dbg_printf("get output_val fail\n");
        return CERT_REST_INIT_FAIL;
    }

    if ((output_obj = json_value_get_object(output_val)) == NULL) {
        dbg_printf("get output_obj fail\n");
        return CERT_REST_GET_VAL_FAIL;
    }

    if (json_object_dotset_string(output_obj, NESTED_MESSAGE, error_message) != JSONSuccess) {
        dbg_printf("get error message fail\n");
        return CERT_REST_SET_VAL_FAIL;
    }

    if ((*jsonptr = json_serialize_to_string(output_val)) == NULL) {
        dbg_printf("json convert to string fail\n");
        return CERT_REST_TYPE_CONVERT_FAIL;
    }

    json_value_free(output_val);
    return CERT_REST_OK;
}

static int _json_set(
    JSON_Value *json_value,
    const char *key,
    void *value,
    int type)
{
    JSON_Object *obj = NULL;
    JSON_Status status;

    if ((obj = json_value_get_object(json_value)) == NULL) {
        return -1;
    }

    if (type == JSONNumber) {
        status = json_object_dotset_number(obj, key, *(int *)value);
    } else if (type == JSONBoolean) {
        status = json_object_dotset_boolean(obj, key, *(int *)value);
    } else if (type == JSONString) {
        status = json_object_dotset_string(obj, key, (char *)value);
    } else if (type == JSONArray) {
        JSON_Array *list;

        /* if not exist, create */
        if (json_object_dothas_value(obj, key) == 0) {
            if (json_object_dotset_value(obj,
                                         key,
                                         json_value_init_array()) != JSONSuccess) {
                return -1;
            }
        }

        if (!(list = json_object_dotget_array(obj, key))) {
            return -1;
        }
        status = json_array_append_string(list, (char *)value);
    } else {
        return -1;
    }

    if (status != JSONSuccess) {
        return -1;
    }

    return 0;
}
/**
 * @brief Get issueto value from config and append to JSON
 *
 * @param root: root of object
 *
 * @return CERTD_REST_OK/CERTD_REST_ERR_JSON
 */
static int _get_issueto(JSON_Value *root)
{
    char start[128], end[128], issueto[128], issueby[128];
    mx_get_cert_info(CERT_ENDENTITY_PEM_PATH, start, end, issueto, issueby);
    //printf("Start=%s,End=%s, issueto=%s, issueby=%s\r\n", start, end, issueto, issueby);

    if (_json_set(root, "data.issueto", issueto, JSONString) < 0) {
        return CERT_REST_JSON_FAIL;
    }

    return CERT_REST_OK;
}

/**
 * @brief Get startdate value from config and append to JSON
 *
 * @param root: root of object
 *
 * @return CERTD_REST_OK/CERTD_REST_ERR_JSON
 */
static int _get_startdate(JSON_Value *root)
{
    char start[128], end[128], issueto[128], issueby[128];
    mx_get_cert_info(CERT_ENDENTITY_PEM_PATH, start, end, issueto, issueby);
    //printf("Start=%s,End=%s, issueto=%s, issueby=%s\r\n", start, end, issueto, issueby);
    if (_json_set(root, "data.startdate", start, JSONString) < 0) {
        return CERT_REST_JSON_FAIL;
    }

    return CERT_REST_OK;
}

/**
 * @brief Get Enddate value from config and append to JSON
 *
 * @param root: root of object
 *
 * @return CERTD_REST_OK/CERTD_REST_ERR_JSON
 */
static int _get_enddate(JSON_Value *root)
{
    char start[128], end[128], issueto[128], issueby[128];
    mx_get_cert_info(CERT_ENDENTITY_PEM_PATH, start, end, issueto, issueby);
    //printf("Start=%s,End=%s, issueto=%s, issueby=%s\r\n", start, end, issueto, issueby);
    if (_json_set(root, "data.enddate", end, JSONString) < 0) {
        return CERT_REST_JSON_FAIL;
    }

    return CERT_REST_OK;
}
/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/


/*****************************************************************************
 * Private functions
 ****************************************************************************/
static int _rest_get_cert_info(
    const char *uri,
    char *input_data,
    int32_t input_data_size
)
{
    JSON_Value *output = NULL;
    char *json_string = NULL;
    int error;

    if (!uri) {
        error = CERT_REST_PARAM_FAIL;
        goto BAD_REQ;
    }

    if (!(output = json_value_init_object())) {
        error = CERT_REST_INIT_FAIL;
        goto BAD_REQ;
    }

    /* get config */
    error = _get_startdate(output);
    error = _get_enddate(output);
    error = _get_issueto(output);
    //error = _get_tz(output);
    if ((json_string = json_serialize_to_string(output)) == NULL) {
        error = CERT_REST_JSON_FAIL;
        goto BAD_REQ;
    }

    if (rest_write(json_string, strlen(json_string) + 1) != REST_OK) {
        error = CERT_REST_SET_VAL_FAIL;
        goto BAD_REQ;
    }

    json_free_serialized_string(json_string);
    json_value_free(output);

    return REST_HTTP_STATUS_OK;

BAD_REQ:

    if (output) {
        json_value_free(output);
    }

    if (json_string) {
        json_free_serialized_string(json_string);
    }

//    _rest_error(error, rest_error_msg[(0 - error)]);

    return REST_HTTP_STATUS_BAD_REQUEST;
}

static int _rest_post_cert_pem(
    const char *uri,
    char *input_data,
    int32_t input_data_size
)
{
    MULTIPART_PART *multiform_item_list = NULL;
    char *boundary = NULL;
    char buf[BUF_SZ];
    JSON_Value *output_val = NULL;
    JSON_Object *output_obj;

    char *jsonptr = NULL, *error_message = NULL;

    if (uri == NULL) {
        dbg_printf("param fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }

    if (parse_boundary(&boundary, input_data) != MULTIFORM_OK) {
        dbg_printf("parse_boundary fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }

    if (mp_parse(&multiform_item_list, boundary, strlen(boundary), input_data, input_data_size) != MULTIFORM_OK) {
        dbg_printf("mp_parse fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }

    if ((multiform_item_list == NULL) || (mx_import_cert(CERT_ENDENTITY_PEM_PATH, multiform_item_list->data, multiform_item_list->data_size, buf, BUF_SZ) < 0)) {
        dbg_printf("get input data fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }

    if (create_output(&output_val, &output_obj) != CERT_REST_OK) {
        dbg_printf("get output_data fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }

    if (json_object_dotset_string(output_obj, DATA_NESTED_RESPONSE, CANOPEN_OPTION_RESPONSE_SUCCESS) != JSONSuccess) {
        dbg_printf("get response fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }

    if ((jsonptr = json_serialize_to_string(output_val)) == NULL) {
        dbg_printf("json to string fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }

    if (rest_write(jsonptr, strlen(jsonptr)) != REST_OK) {
        dbg_printf("write to handle fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }

    free(boundary);
    mp_free_all_parts(multiform_item_list);
    json_free_serialized_string(jsonptr);
    json_value_free(output_val);

    return REST_HTTP_STATUS_CREATED;

CERT_POST_BAD_REQUEST:
    free(boundary);
    mp_free_all_parts(multiform_item_list);
    json_free_serialized_string(jsonptr);
    json_value_free(output_val);

    if (create_output_error_message(&jsonptr, error_message) != CERT_REST_OK) {
        dbg_printf("fail");
    }

    if (rest_write(jsonptr, strlen(jsonptr)) != REST_OK) {
        dbg_printf("json write to handler\n");
    }

    json_free_serialized_string(jsonptr);
    free(error_message);

    return REST_HTTP_STATUS_BAD_REQUEST;

}

static int _rest_del_cert_pem(
    const char *uri,
    char *input_data,
    int32_t input_data_size
)
{
    char *jsonptr = NULL, *error_message = NULL;

    if (uri == NULL) {
        dbg_printf("param fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_DELETE_REQUEST;
    }

CERT_DELETE_REQUEST:

    if (create_output_error_message(&jsonptr, error_message) != CERT_REST_OK) {
        dbg_printf("fail");
    }

    if (rest_write(jsonptr, strlen(jsonptr)) != REST_OK) {
        dbg_printf("json write to handler\n");
    }

    json_free_serialized_string(jsonptr);
    free(error_message);

    return REST_HTTP_STATUS_BAD_REQUEST;

}
/*****************************************************************************
 * Public functions
 ****************************************************************************/
/**
 * @brief: Test function
 *
 * @param 
 * @param
 * @param
 *
 * @return
 */

int cert_mgmt_rest_init(char *module_name, int *id)
{
    int ret, ret_id;
    printf("%s-%d\r\n", __func__, __LINE__);
    if (module_name == NULL || id == NULL) {
        fprintf(stderr, "%s line: %d\n", __FILE__, __LINE__);
        return -1;
    }

    if ((ret_id = rest_init(module_name)) < REST_OK) {
        fprintf(stderr, "(%s:%d)init rest fail (%d).\n", __FILE__, __LINE__, ret_id);
        return -1;
    }

    /* get all config of time */
    if ((ret = rest_cb_register(ret_id,
                                "/certinfo",
                                REST_OP_GET,
                                _rest_get_cert_info)) != REST_OK) {
        fprintf(stderr, "(%s:%d)register rest cb fail.\n", __FILE__, __LINE__);
        return -1;
    }

    /* post certificate file (PEM) */
    if ((ret = rest_cb_register(ret_id,
                                "/pemfile",
                                REST_OP_POST,
                                _rest_post_cert_pem)) != REST_OK) {
        fprintf(stderr, "(%s:%d)register rest cb fail.\n", __FILE__, __LINE__);
        return -1;
    }

    /* delete certificate file (PEM) */
    if ((ret = rest_cb_register(ret_id,
                                "/pemfile",
                                REST_OP_DELETE,
                                _rest_del_cert_pem)) != REST_OK) {
        fprintf(stderr, "(%s:%d)register rest cb fail.\n", __FILE__, __LINE__);
        return -1;
    }
    *id = ret_id;

    return 0;
}
