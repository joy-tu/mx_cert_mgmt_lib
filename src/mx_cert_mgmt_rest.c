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
#include <def/mx_def.h>
#ifdef __ZEPHYR__
#else   /* Linux */
#include <linux/sockios.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#endif
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
#define DEBUG_MX_CERT_REST
#ifdef DEBUG_MX_CERT_REST
#define dbg_printf  printf
#else
#define dbg_printf(...) 
#endif
/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/
const char *rest_error_msg[] =
{
    "Success",
    "Invalid parameters",
    "Init error",
    "CB_REGISTER error",
    "get value is error",
    "set value is  error",
    "TYPE_CONVERT_FAIL",
    "MALLOC_FAIL",
    "VAL_OUT_OF_RANGE",
    "Json fail",
    "file is not exist"
};

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

static int _rest_error(
    int error_id,
    const char *error_message
)
{
    JSON_Value *json_value = NULL;
    //int error;
    char *p = NULL;

    if (!(json_value = json_value_init_object()))
    {
        return -1;
    }

    if (_json_set(json_value, "error.message", (void *)error_message, JSONString) < 0)
    {
        return -1;
    }
#if 0
    if (_json_set(json_value, "error.code", (void *)&error_id, JSONNumber) < 0)
    {
        return -1;
    }
#endif
    if ((p = json_serialize_to_string(json_value)) == NULL)
    {
        return -1;
    }

    //error = rest_write(p, strlen(p) + 1);

    json_value_free(json_value);
    json_free_serialized_string(p);
    return 0;
}

static int _get_issueby(JSON_Value *root)
{
    int ret;
    char start[128], end[128], issueto[128], issueby[128];
    ret = mx_get_cert_info(CERT_ENDENTITY_PEM_PATH, start, end, issueto, issueby);
    if (ret == -1) {/* opening cert fail */
        if (_json_set(root, "data.issueby", "Not installed", JSONString) < 0) {
            return CERT_REST_JSON_FAIL;
        }
        return CERT_REST_PEM_NOT_INSTALLED;
    }
    //printf("Start=%s,End=%s, issueto=%s, issueby=%s\r\n", start, end, issueto, issueby);

    if (_json_set(root, "data.issueby", issueby, JSONString) < 0) {
        return CERT_REST_JSON_FAIL;
    }

    return CERT_REST_OK;
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
    int ret;
    char start[128], end[128], issueto[128], issueby[128];
    ret = mx_get_cert_info(CERT_ENDENTITY_PEM_PATH, start, end, issueto, issueby);
    if (ret == -1) {/* opening cert fail */
        if (_json_set(root, "data.issueto", "Not installed", JSONString) < 0) {
            return CERT_REST_JSON_FAIL;
        }    
        return CERT_REST_PEM_NOT_INSTALLED;
    }
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
    int ret;
    char start[128], end[128], issueto[128], issueby[128];
    ret = mx_get_cert_info(CERT_ENDENTITY_PEM_PATH, start, end, issueto, issueby);
    if (ret == -1) { /* opening cert fail */
        if (_json_set(root, "data.startdate", "Not installed", JSONString) < 0) {
            return CERT_REST_JSON_FAIL;
        }    
        return CERT_REST_PEM_NOT_INSTALLED;
    }
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
    int ret;
    char start[128], end[128], issueto[128], issueby[128];
    ret = mx_get_cert_info(CERT_ENDENTITY_PEM_PATH, start, end, issueto, issueby);
    if (ret == -1) {/* opening cert fail */
        if (_json_set(root, "data.enddate", "Not installed", JSONString) < 0) {
            return CERT_REST_JSON_FAIL;
        }    
        return CERT_REST_PEM_NOT_INSTALLED;
    }
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
REST_HTTP_STATUS _rest_get_cert_info(
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
    if (error < 0) {
        if (error == CERT_REST_PEM_NOT_INSTALLED) {
        } else {
            error = CERT_REST_JSON_FAIL;
            goto BAD_REQ;    
        }
    }
    error = _get_enddate(output);
    if (error < 0) {
        if (error == CERT_REST_PEM_NOT_INSTALLED) {
        } else {
            error = CERT_REST_JSON_FAIL;
            goto BAD_REQ;    
        }
    }    
    error = _get_issueto(output);
    if (error < 0) {
        if (error == CERT_REST_PEM_NOT_INSTALLED) {
        } else {
            error = CERT_REST_JSON_FAIL;
            goto BAD_REQ;    
        }
    }    
    error = _get_issueby(output);
    if (error < 0) {
        if (error == CERT_REST_PEM_NOT_INSTALLED) {
        } else {
            error = CERT_REST_JSON_FAIL;
            goto BAD_REQ;    
        }    
    }    
    //error = _get_tz(output);
    if ((json_string = json_serialize_to_string(output)) == NULL) {
        error = CERT_REST_JSON_FAIL;
        goto BAD_REQ;
    }

    if (rest_write(json_string, strlen(json_string)) != REST_OK) {
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

    _rest_error(error, rest_error_msg[(0 - error)]);

    return REST_HTTP_STATUS_BAD_REQUEST;
}
int _parse_boundary(char **boundary, const char *data)
{
    int boundary_len = 0, i;

    if (boundary == NULL || data == NULL)
    {
        return MULTIFORM_FAIL;
    }

    if (strchr(data, '\r') == NULL)
    {
        return MULTIFORM_FAIL;
    }

    for (i = 0; *(data + i) != '\r'; ++i)
    {
        boundary_len++;
    }

    boundary_len -= strlen("--");

    if ((*boundary = calloc(sizeof(char), (strlen("boundary=") + boundary_len + 1))) == NULL)
    {
        return MULTIFORM_FAIL;
    }

    snprintf(*boundary, (strlen("boundary=") + boundary_len + 1), "boundary=%s", data + strlen("--"));

    return MULTIFORM_OK;
}

REST_HTTP_STATUS _rest_post_cert_pem(
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
    int ret;
    
    char *jsonptr = NULL, *error_message = NULL;

    if (uri == NULL) {
        dbg_printf("param fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }
    printf("%s-%d, parse=%d\r\n", __func__, __LINE__, 
    parse_boundary(&boundary, input_data));

    if (parse_boundary(&boundary, input_data) != MULTIFORM_OK) {
        dbg_printf("parse_boundary fail----\n");
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
    if ((multiform_item_list == NULL) ) {
        dbg_printf("get input data fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_POST_BAD_REQUEST;
    }
    ret = mx_import_cert(CERT_ENDENTITY_PEM_PATH, 
                                        multiform_item_list->data, 
                                        multiform_item_list->data_size, 
                                        buf, 
                                        BUF_SZ);
    if (ret != 0) {
        dbg_printf("mx_import_cert fail\n");
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
    printf("%s-%d\r\n", __func__, __LINE__);
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
REST_HTTP_STATUS _rest_post_self_cert_regen(const char *uri, char *input_data, int32_t input_data_size)
{
    JSON_Value *input_val = NULL, *output_val = NULL;
    JSON_Object  *output_obj;

    char *jsonptr = NULL, *error_message = NULL;

    if (uri == NULL)
    {
        dbg_printf("param fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_REGEN_BAD_REQUEST;
    }
    if (mx_regen_cert()  == -1) {
        dbg_printf("mx_regen_cert fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_REGEN_BAD_REQUEST;
    }
#if 0
    if (parse_input_obj(&input_val, &input_obj, input_data) != CERT_REST_OK)
    {
        dbg_printf("get input data fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_REGEN_BAD_REQUEST;
    }

    if (get_json_num_boolean(input_obj, ACTION_OPTION, &action_option) != CERT_REST_OK)
    {
        dbg_printf("get action_option fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_REGEN_BAD_REQUEST;
    }
    if (check_val_range(action_option, CANOPEN_ACTION_OPTION_APPLY, CANOPEN_ACTION_OPTION_DISCARD) != CERT_REST_OK)
    {
        dbg_printf("out of range\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_REGEN_BAD_REQUEST;
    }

    if (action_option == CANOPEN_ACTION_OPTION_APPLY)
    {
        canopen_save_restart();
    }
    else if (action_option == CANOPEN_ACTION_OPTION_DISCARD)
    {
        canopen_config_restore();
    }
#endif
    if (create_output(&output_val, &output_obj) != CERT_REST_OK)
    {
        dbg_printf("get output_data fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_REGEN_BAD_REQUEST;
    }

    if (json_object_dotset_string(output_obj, DATA_NESTED_RESPONSE, CANOPEN_OPTION_RESPONSE_SUCCESS) != JSONSuccess)
    {
        dbg_printf("get response fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_REGEN_BAD_REQUEST;
    }

    if ((jsonptr = json_serialize_to_string(output_val)) == NULL)
    {
        dbg_printf("json to string fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_REGEN_BAD_REQUEST;
    }

    if (rest_write(jsonptr, strlen(jsonptr)) != REST_OK)
    {
        dbg_printf("write to handle fail\n");
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_REGEN_BAD_REQUEST;
    }

    json_free_serialized_string(jsonptr);
    json_value_free(input_val);
    json_value_free(output_val);
    return REST_HTTP_STATUS_CREATED;

CERT_REGEN_BAD_REQUEST:
    json_free_serialized_string(jsonptr);
    json_value_free(input_val);
    json_value_free(output_val);

    if (create_output_error_message(&jsonptr, error_message) != CERT_REST_OK)
    {
        dbg_printf("fail");
    }

    if (rest_write(jsonptr, strlen(jsonptr)) != REST_OK)
    {
        dbg_printf("json write to handler\n");
    }

    json_free_serialized_string(jsonptr);
    free(error_message);

    return REST_HTTP_STATUS_BAD_REQUEST;
}

REST_HTTP_STATUS _rest_del_cert_pem(
    const char *uri,
    char *input_data,
    int32_t input_data_size
)
{
    char *jsonptr = NULL, *error_message = NULL;

    if (uri == NULL) {
        dbg_printf("%s-%d param fail\n", __func__, __LINE__);
        error_message = malloc(strlen(RESPONSE_INVALID) + 1);
        sprintf(error_message, RESPONSE_INVALID);
        goto CERT_DELETE_REQUEST;
    }
    
    if (mx_cert_del(CERT_ENDENTITY_PEM_PATH) > 0)
        return REST_HTTP_STATUS_NO_CONTENT;
    /* 2022/3/11, center decide that, we response ok at any situation */
    return REST_HTTP_STATUS_NO_CONTENT;        
    error_message = malloc(strlen(RESPONSE_INVALID) + 1);
    sprintf(error_message, RESPONSE_INVALID);
CERT_DELETE_REQUEST:
    if (create_output_error_message(&jsonptr, error_message) != CERT_REST_OK) {
        dbg_printf("%s-%d fail\r\n", __func__, __LINE__);
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
    //printf("%s-%d\r\n", __func__, __LINE__);
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
    /* post self-cert regeneation */
#if 0 /* I and center decide to remove this function at 11/8 */
    if ((ret = rest_cb_register(ret_id, 
                                "/self-cert", 
                                REST_OP_POST, 
                                _rest_post_self_cert_regen)) != REST_OK)
    {
        fprintf(stderr, "(%s:%d)register rest cb fail.\n", __FILE__, __LINE__);
        return -1;
    }
#endif    
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
