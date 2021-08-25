#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <parson.h>

#include "mx_timed_db.c"

static char *config;

JSON_Value *__wrap_json_parse_file(const char *file)
{
    JSON_Value *val  = NULL;
    int enable = (int)mock();

    if (enable)
    {
        val = json_parse_string(config);
    }

    return val;
}

JSON_Status __wrap_json_serialize_to_file_pretty(const JSON_Value *value, const char *filename)
{
    config = json_serialize_to_string_pretty(value);
    return JSONSuccess;
}

int __wrap_stat(const char *path, struct stat *buf)
{
    return (int)mock();
}

static int _setup(void **state)
{
    config =
        "{ \
        \"name\": \"ethan\", \
        \"age\": 40 \
    }";
    return 0;
}

static int _teardown(void **state)
{
    config = "{}";
    return 0;
}

static void _test_db_open_close(void **state)
{
    JSON_Value *val  = NULL;

    will_return(__wrap_json_parse_file, 0);

    val = db_open("123");

    assert_null(val);

    will_return(__wrap_json_parse_file, 1);

    val = db_open("123");

    assert_non_null(val);

    db_close(val);
}

static void _test_notify(int type)
{
    int value = (int)mock();
    assert_int_equal(type, value);
}

static void _test_db_get_set(void **state)
{
    char name[32] = {0};
    int rv;
    int number;

    /* open file fail */
    will_return(__wrap_json_parse_file, 0);

    rv = db_get("123", "age", &number, JSONNumber);

    assert_int_equal(rv, DB_OPEN_FAIL);

    /* open file fail */
    will_return(__wrap_json_parse_file, 0);

    rv = db_set("123", "name", "Ethan", JSONString, NULL, 0);

    assert_int_equal(rv, DB_OPEN_FAIL);

    will_return_always(__wrap_json_parse_file, 1);

    /* get exist */
    rv = db_get("123", "age", &number, JSONNumber);

    assert_int_equal(number, 40);

    /* update exist */
    number = 35;

    rv = db_set("123", "age", &number, JSONNumber, NULL, 0);

    assert_int_equal(rv, 0);

    /* get back to check */
    rv = db_get("123", "age", &number, JSONNumber);

    assert_int_equal(rv, 0);

    assert_int_equal(number, 35);

    /* try to set age again */
    rv = db_set("123", "age", &number, JSONNumber, NULL, 0);

    assert_int_equal(rv, 0);

    rv = db_get("123", "age", &number, JSONNumber);

    assert_int_equal(rv, 0);

    assert_int_equal(number, 35);

    /* try to set name again */
    rv = db_set("123", "name", "Joyce", JSONString, NULL, 0);

    assert_int_equal(rv, 0);

    rv = db_get("123", "name", name, JSONString);

    assert_int_equal(rv, 0);

    assert_string_equal(name, "Joyce");

    /* try to set name again */
    rv = db_set("123", "name", "Joyce", JSONString, NULL, 0);

    assert_int_equal(rv, 0);

    rv = db_get("123", "name", name, JSONString);

    assert_int_equal(rv, 0);

    assert_string_equal(name, "Joyce");

    /* set unexist */
    rv = db_set("123", "contact.tel", "02-87972088", JSONString, NULL, 0);

    assert_int_equal(rv, 0);

    rv = db_get("123", "contact.tel", name, JSONString);

    assert_int_equal(rv, 0);

    assert_string_equal(name, "02-87972088");

    /* set unexist number */
    number = 9527;

    rv = db_set("123", "contact.id", &number, JSONNumber, NULL, 0);

    assert_int_equal(rv, 0);

    number = 0;

    rv = db_get("123", "contact.id", &number, JSONNumber);

    assert_int_equal(rv, 0);
    assert_int_equal(number, 9527);

    /* get unexist */
    rv = db_get("123", "contact.email", &number, JSONNumber);

    assert_int_equal(rv, DB_NAME_NOT_EXIST);

    /* test callback and parameter */
    number = 9876;

    will_return(_test_notify, 100);

    rv = db_set("123", "contact.id", &number, JSONNumber, _test_notify, 100);

    assert_int_equal(rv, 0);
}

static void _test_db_save(void **state)
{
    db_save(NULL, "123");
}

static void _test_db_copy(void **state)
{
    int rv;

    rv = db_copy(NULL, NULL);

    assert_int_equal(rv, DB_INVALID_PARAMETER);

    will_return(__wrap_json_parse_file, 0);

    rv = db_copy("123", "456");

    assert_int_equal(rv, DB_OPEN_FAIL);

    will_return_always(__wrap_json_parse_file, 1);

    rv = db_copy("123", "456");

    assert_int_equal(rv, DB_OK);
}

static void _test_db_check(void **state)
{
    int rv;

    rv = db_check(NULL);

    assert_int_equal(rv, DB_INVALID_PARAMETER);

    will_return(__wrap_stat, -1);

    rv = db_check("123");

    assert_int_equal(rv, DB_FILE_NOT_EXIST);

    will_return_always(__wrap_stat, 0);

    will_return(__wrap_json_parse_file, 0);

    rv = db_check("123");

    assert_int_equal(rv, DB_OPEN_FAIL);

    will_return(__wrap_json_parse_file, 1);

    rv = db_check("123");

    assert_int_equal(rv, DB_OK);
}

int main(void)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test(_test_db_open_close),
        cmocka_unit_test(_test_db_get_set),
        cmocka_unit_test(_test_db_save),
        cmocka_unit_test(_test_db_copy),
        cmocka_unit_test(_test_db_check),
    };
    return cmocka_run_group_tests(tests, _setup, _teardown);
}
