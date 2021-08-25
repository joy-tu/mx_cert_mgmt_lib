/**
 * @file mx_timed_db.c
 * @brief
 * @author Ethan Tsai
 * @date 2021-08-25
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <parson.h>
#include <sys/stat.h>

#include "mx_timed_db.h"

/**
 * @brief
 *
 * @return
 */
static JSON_Value *db_open(const char *file)
{
    JSON_Value *configs = NULL;

    configs = json_parse_file(file);

    if (!configs)
    {
        return NULL;
    }

    return configs;
}

/**
 * @brief
 *
 * @param config
 */
static void db_close(JSON_Value *config)
{
    json_value_free(config);
}

/**
 * @brief
 *
 * @return
 */
static void db_save(JSON_Value *config, const char *file)
{
    if (!config || !file)
    {
        return;
    }

    json_serialize_to_file_pretty(config, file);
}

/**
 * @brief
 *
 * @param obj
 * @param name
 * @param value
 *
 * @return
 */
static int _json_obj_set_integer(
    JSON_Object *obj,
    const char *name,
    int value)
{
    int current = 0;

    /* not exist, insert anyway */
    if (!json_object_dothas_value(obj, name))
    {
        json_object_dotset_number(obj, name, value);
        return DB_CHANGED;
    }

    current = (int)json_object_dotget_number(obj, name);

    if (current != value)
    {
        json_object_dotset_number(obj, name, value);
        return DB_CHANGED;
    }

    return DB_OK;
}

/**
 * @brief
 *
 * @param obj
 * @param name
 * @param value
 *
 * @return
 */
static int _json_obj_set_string(
    JSON_Object *obj,
    const char *name,
    const char *value)
{
    const char *current = NULL;

    /* not exist, insert anyway */
    if (!json_object_dothas_value(obj, name))
    {
        json_object_dotset_string(obj, name, value);
        return DB_CHANGED;
    }

    current = json_object_dotget_string(obj, name);

    if (strcmp(current, value))
    {
        json_object_dotset_string(obj, name, value);
        return DB_CHANGED;
    }

    return DB_OK;
}


/**
 * @brief
 *
 * @param name
 * @param value
 * @param type
 *
 * @return
 */
int db_get(
    const char *file,
    const char *name,
    void *value,
    int type)
{
    JSON_Value *config = NULL;
    JSON_Object *obj = NULL;

    config = db_open(file);

    if (!config)
    {
        return DB_OPEN_FAIL;
    }

    obj = json_value_get_object(config);

    if (!json_object_dothas_value(obj, name))
    {
        return DB_NAME_NOT_EXIST;
    }

    if (type == JSONNumber)
    {
        *(int *)value = json_object_dotget_number(obj, name);
    }
    else if (type == JSONString)
    {
        const char *p = json_object_dotget_string(obj, name);

        if (p)
        {
            strncpy((char *)value, p, strlen(p));
        }
    }

    db_close(config);
    return DB_OK;
}

/**
 * @brief
 *
 * @param name
 * @param value
 * @param type
 * @param notify_change
 * @param config_type
 *
 * @return
 */
int db_set(
    const char *file,
    const char *name,
    void *value,
    int type,
    void (*notify_change)(int type),
    int config_type)
{
    JSON_Value *config = NULL;
    JSON_Object *obj = NULL;
    int change = 0;

    config = db_open(file);

    if (!config)
    {
        return DB_OPEN_FAIL;
    }

    obj = json_value_get_object(config);

    if (type == JSONNumber)
    {
        change = _json_obj_set_integer(obj, name, *(int *)value);
    }
    else if (type == JSONString)
    {
        change = _json_obj_set_string(obj, name, (char *)value);
    }

    if (change)
    {
        db_save(config, file);
    }

    db_close(config);

    if (change && notify_change)
    {
        notify_change(config_type);
    }

    return DB_OK;
}

/**
 * @brief
 *
 * @param target
 * @param source
 *
 * @return
 */
int db_copy(const char *target, const char *source)
{
    JSON_Value *config = NULL;

    if (!target || !source)
    {
        return DB_INVALID_PARAMETER;
    }

    if (!(config = db_open(source)))
    {
        return DB_OPEN_FAIL;
    }

    db_save(config, target);

    db_close(config);
    return DB_OK;
}

/**
 * @brief
 *
 * @param file
 *
 * @return
 */
int db_check(const char *file)
{
    JSON_Value *config = NULL;
    struct stat buffer;

    if (!file)
    {
        return DB_INVALID_PARAMETER;
    }

    if (stat(file, &buffer) != 0)
    {
        return DB_FILE_NOT_EXIST;
    }

    if (!(config = db_open(file)))
    {
        return DB_OPEN_FAIL;
    }

    // TODO: validation

    db_close(config);
    return DB_OK;
}
