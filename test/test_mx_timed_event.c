/**
 * @file test_mx_timed_event.c
 * @brief Test mx_timed_event.c
 * @author Ethan Tsai
 * @version
 * @date 2021-08-19
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "mx_timed_event.c"

/* real functions */
void *__real_calloc(size_t nitems, size_t size);

/* wrap functions */
void *__wrap_calloc(size_t nitems, size_t size)
{
    int enable = (int)mock();
    return (void *)((enable) ? __real_calloc(nitems, size) : NULL);
}

static void _test_event_register(void **state)
{
    int rv = 0;

    will_return(__wrap_calloc, 0);

    rv = event_register(1, 0, 0, NULL, NULL);

    assert_int_equal(rv, -1);

    will_return_always(__wrap_calloc, 1);

    rv = event_register(1, 0, 0, NULL, NULL);

    rv = event_deregister(1);

    assert_int_equal(rv, 0);
}

static void _test_event_timer_register(void **state)
{
    int rv = 0;
    int id = 0;

    will_return(__wrap_calloc, 0);

    id = event_timer_register(0, 0, NULL);

    assert_int_equal(id, -1);

    will_return_always(
        __wrap_calloc,
        1);

    id = event_timer_register(0, 0, NULL);

    rv = event_timer_deregister(id);

    assert_int_equal(rv, 0);
}

static void _test_search_event_by_fd(void **state)
{
    int rv;

    will_return_always(__wrap_calloc, 1);

    rv = event_register(1, 0, 0, NULL, NULL);

    rv = event_deregister(2);

    assert_int_not_equal(rv, 0);

    rv = event_deregister(1);

    assert_int_equal(rv, 0);
}

static void _test_search_timer_by_id(void **state)
{
    int rv = 0;
    int id = 0;

    will_return_always(
        __wrap_calloc,
        1);

    id = event_timer_register(0, 0, NULL);

    rv = event_timer_deregister(id + 1);

    assert_int_not_equal(rv, 0);

    rv = event_timer_deregister(id);

    assert_int_equal(rv, 0);
}

static void __timeout_handler(int id)
{
    return;
}

static void _test_event_timeout_handler(void **state)
{
    struct list_head *list = NULL;
    int fd, timer_id1, timer_id2;
    int rv;

    will_return_always(__wrap_calloc, 1);

    rv = event_register(1, 0, 0, NULL, __timeout_handler);

    assert_int_equal(rv, 0);

    rv = event_register(2, 0, 2, NULL, __timeout_handler);

    assert_int_equal(rv, 0);

    timer_id1 = event_timer_register(0, 0, __timeout_handler);

    assert_int_not_equal(timer_id1, -1);

    /* test timer interval */
    timer_id2 = event_timer_register(0, 1, __timeout_handler);

    assert_int_not_equal(timer_id2, -1);

    sleep(1);

    /* test here */
    _event_timeout_handler();

    fd = 1;

    list = list_search(&event_list, (void *)&fd, _search_event_by_fd);

    assert_null(list);

    fd = 2;

    list = list_search(&event_list, (void *)&fd, _search_event_by_fd);

    assert_non_null(list);

    list = list_search(&timer_list, (void *)&timer_id1, _search_timer_by_id);

    assert_null(list);

    list = list_search(&timer_list, (void *)&timer_id2, _search_timer_by_id);

    assert_non_null(list);
}

int main(void)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test(_test_event_register),
        cmocka_unit_test(_test_event_timer_register),
        cmocka_unit_test(_test_search_event_by_fd),
        cmocka_unit_test(_test_search_timer_by_id),
        cmocka_unit_test(_test_event_timeout_handler),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
