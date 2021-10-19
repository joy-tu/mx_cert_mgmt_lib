INCLUDE_PATH := \
	-I../src \
	-I../include \
	-I../../include

SRC_DIR := ../src

COVERAGE := -fprofile-arcs -ftest-coverage

CFLAGS := -Wall -O0 ${INCLUDE_PATH} ${COVERAGE}

LDFLAGS := -lcmocka

TARGETS := \
	test_mx_cert_lib
#TARGETS := \
#	test_mx_timed_list \
#	test_mx_timed_event \
#	test_mx_timed_db \
#	test_mx_cert_lib
#	test_mx_timed_config \
#	test_mx_cert_lib 

.PHONY: all
all: ${TARGETS}
	gcovr -r .

.PHONY: clean
clean:
	rm -f *.gcov *.gcno *.gcda
	rm -f ${TARGETS}

test_mx_timed_event: test_mx_timed_event.c ${SRC_DIR}/mx_timed_event.c
	gcc -o $@ ${CFLAGS} -Wl,--wrap=calloc $< ${LDFLAGS}
	./$@

test_mx_timed_list: test_mx_timed_list.c ${SRC_DIR}/mx_timed_list.h
	gcc -o $@ ${CFLAGS} -DUNIT_TESTING $< ${LDFLAGS}
	./$@

test_mx_timed_db: test_mx_timed_db.c ${SRC_DIR}/mx_timed_db.c
	gcc -o $@ ${CFLAGS} -DUNIT_TESTING\
		-Wl,--wrap=json_parse_file \
		-Wl,--wrap=json_serialize_to_file_pretty \
		-Wl,--wrap=stat \
		$< ${LDFLAGS} -lparson
	./$@

test_mx_timed_config: test_mx_timed_config.c ${SRC_DIR}/mx_timed_config.c
	gcc -o $@ ${CFLAGS} -DUNIT_TESTING\
		-Wl,--wrap=recv \
		-Wl,--wrap=accept \
		-Wl,--wrap=socket \
		-Wl,--wrap=bind \
		-Wl,--wrap=close \
		-Wl,--wrap=event_register \
		-Wl,--wrap=event_deregister \
		-Wl,--wrap=timed_intf_init \
		$< ${LDFLAGS}
	./$@

test_mx_cert_lib: test_mx_cert_lib.c 
	gcc -o $@ ${CFLAGS} $< -lssl -l crypto -lmx-net -lmxtimed -L../platform/laputa/build -L/usr/lib
	./$@
