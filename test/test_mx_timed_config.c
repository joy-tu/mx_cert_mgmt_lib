#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <parson.h>

#include "mx_timed_config.c"

ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags)
{
    return (int)mock();
}

int __wrap_accept(int sockfd, struct sockaddr *restrict addr,
                  socklen_t *restrict addrlen)
{
    return (int)mock();
}

int __wrap_socket(int domain, int type, int protocol)
{
    return (int)mock();
}

int __wrap_bind(int sockfd, const struct sockaddr *addr,
        socklen_t addrlen)
{
    return (int)mock();
}

int __wrap_close(int fd)
{
    return 0;
}

int __wrap_event_register(
        int fd, uint8_t op, time_t timeout,
        void (*callback)(int, int),
        void (*timeout_handler)(int)
)
{
    return 0;
}

int __wrap_event_deregister(int fd)
{
    return 0;
}

int __wrap_timed_intf_init(void)
{
    return (int)mock();
}

static void _test_recv_handler(void **state)
{
    _recv_handler(0, 0);

    _recv_handler(1, 0);

    will_return(__wrap_recv, 0);

    _recv_handler(1, EVENT_OP_READ);

    will_return(__wrap_recv, 1);

    _recv_handler(1, EVENT_OP_READ);
}

static void _test_connect_handler(void **state)
{
    _connect_handler(0, 0);

    _connect_handler(1, 0);

    will_return(__wrap_accept, -1);

    _connect_handler(1, EVENT_OP_READ);

    will_return(__wrap_accept, 1);

    _connect_handler(1, EVENT_OP_READ);
}

static void _test_init_listener(void **state)
{
    int rv = 0;

    will_return(__wrap_socket, -1);

    rv = _init_listener();

    assert_int_equal(rv, -1);

    will_return_always(__wrap_socket, 0);

    will_return(__wrap_bind, -1);

    rv = _init_listener();

    assert_int_equal(rv, -1);

    will_return(__wrap_bind, 0);

    rv = _init_listener();

    assert_int_equal(rv, 0);
}

static void _test_deinit_listener(void **state)
{
    int rv = _deinit_listener();
    assert_int_equal(rv, 0);
}

static void _test_timed_config_init(void **state)
{
    int rv = 0;

    will_return_always(__wrap_socket, 0);

    will_return_always(__wrap_bind, 0);

    will_return(__wrap_timed_intf_init, TIMED_UNAVAILABLE);

    rv = timed_config_init();

    assert_int_equal(rv, -1);

    will_return(__wrap_timed_intf_init, TIMED_OK);

    rv = timed_config_init();

    assert_int_equal(rv, 0);
}

static void _test_timed_config_deinit(void **state)
{
    int rv = timed_config_deinit();
    assert_int_equal(rv, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(_test_recv_handler),
        cmocka_unit_test(_test_connect_handler),
        cmocka_unit_test(_test_init_listener),
        cmocka_unit_test(_test_deinit_listener),
        cmocka_unit_test(_test_timed_config_init),
        cmocka_unit_test(_test_timed_config_deinit),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
