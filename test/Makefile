INCLUDE_PATH := \
	-I../src \
	-I../include

SRC_DIR := ../src

COVERAGE := -fprofile-arcs -ftest-coverage

CFLAGS := -Wall -O0 ${INCLUDE_PATH} ${COVERAGE}

LDFLAGS := -lcmocka

TARGETS := \
	test_mx_timed_list \
	test_mx_timed_event \
	test_mx_timed_db \

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

