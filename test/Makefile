INCLUDE_PATH := \
	-I../src \
	-I../include

BUILD_DIR = build

SRC_DIR := ../src

COVERAGE := -fprofile-arcs -ftest-coverage -fprofile-dir=${BUILD_DIR}

CFLAGS := -Wall -O0 ${INCLUDE_PATH} ${COVERAGE}

LDFLAGS := -lcmocka

TARGETS := \
	test_mx_timed_list \
	test_mx_timed_event

.PHONY: all
all: ${BUILD_DIR} $(addprefix ${BUILD_DIR}/, ${TARGETS})
	mv *.gcno ${BUILD_DIR}/
	gcovr -r .

.PHONY: clean
clean:
	rm -rf ${BUILD_DIR}
	rm -f *.gcov *.gcds *.gcno

${BUILD_DIR}:
	mkdir -p $@

${BUILD_DIR}/test_mx_timed_event: test_mx_timed_event.c ${SRC_DIR}/mx_timed_event.c
	gcc -o $@ ${CFLAGS} -Wl,--wrap=calloc $< ${LDFLAGS}
	./$@

${BUILD_DIR}/test_mx_timed_list: test_mx_timed_list.c ${SRC_DIR}/mx_timed_list.h
	gcc -o $@ ${CFLAGS} $< ${LDFLAGS}
	./$@

