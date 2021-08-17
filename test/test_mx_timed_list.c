#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "mx_timed_list.h"

LIST_HEAD(test_list);

struct test_list_node
{
    struct list_head list;
    int number;
};

#define GET_LIST_PTR(_e) &_e->list

static void _test_push(void **state)
{
    struct test_list_node *new = calloc(1, sizeof(struct test_list_node));

    assert_non_null(new);

    new->number = 1;

    list_push(&new->list, &test_list);

    assert_ptr_equal(new, list_entry(test_list.prev,
                                     struct test_list_node,
                                     list));

    list_del(GET_LIST_PTR(new));

    assert_ptr_equal(test_list.prev, &test_list);

    free(new);
}

static int _compare(
    struct list_head *new,
    struct list_head *current,
    struct list_head *head
)
{
    struct test_list_node *new_node = NULL;
    struct test_list_node *current_node = NULL;
    struct test_list_node *next_node = NULL;

    new_node = list_entry(new, struct test_list_node, list);
    current_node = list_entry(current, struct test_list_node, list);

    if (current->next != head)
    {
        next_node = list_entry(current->next, struct test_list_node, list);
    }

    /* left */
    if (new_node->number < current_node->number)
    {
        return -1;
    }

    /* right */
    if (new_node->number >= current_node->number)
    {
        if (!next_node)
        {
            return 1;
        }

        if (next_node && new_node->number < next_node->number)
        {
            return 1;
        }
    }

    return 0;
}

static void _test_insert_by(void **state)
{
    struct list_head *pos, *next;
    struct test_list_node *entry;
    int number = 0;

    /* insert 9,7,5,3,2,1 */
    for (number = 9; number >= 0; number = number - 2)
    {
        entry = calloc(1, sizeof(struct test_list_node));

        assert_non_null(entry);

        entry->number = number;

        list_insert_by(GET_LIST_PTR(entry), &test_list, _compare);
    }

    /* insert 0,2,4,6,8 */
    for (number = 0; number < 10; number = number + 2)
    {
        entry = calloc(1, sizeof(struct test_list_node));

        assert_non_null(entry);

        entry->number = number;

        list_insert_by(GET_LIST_PTR(entry), &test_list, _compare);
    }

    /* insert 10 */
    entry = calloc(1, sizeof(struct test_list_node));

    assert_non_null(entry);

    entry->number = 10;

    list_insert_by(GET_LIST_PTR(entry), &test_list, _compare);

    number = 0;

    list_for_each_safe(pos, next, &test_list)
    {
        entry = list_entry(pos, struct test_list_node, list);
        assert_int_equal(number++, entry->number);

        list_del(pos);
        free(entry);
    }
}

static int _search_by_number(struct list_head *entry, void *num)
{
    struct test_list_node *c;
    int check = *(int *)num;

    c = list_entry(entry, struct test_list_node, list);

    return (c->number == check) ? 1 : 0;
}

static void _test_search(void **state)
{
    struct list_head *entry = NULL;
    struct test_list_node *new = NULL;
    int number = 1;

    entry = list_search(&test_list, &number, _search_by_number);

    assert_null(entry);

    new = calloc(1, sizeof(struct test_list_node));

    assert_non_null(new);

    new->number = 1;

    list_push(&new->list, &test_list);

    entry = list_search(&test_list, &number, _search_by_number);

    assert_ptr_equal(new, list_entry(entry, struct test_list_node, list));

    list_del(&new->list);
    free(new);
}

int main(void)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test(_test_push),
        cmocka_unit_test(_test_insert_by),
        cmocka_unit_test(_test_search),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

