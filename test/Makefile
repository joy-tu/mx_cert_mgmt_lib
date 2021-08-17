INCLUDE_PATH := \
	-I../src \
	-I../include

COVERAGE := -fprofile-arcs -ftest-coverage

CFLAGS := -Wall ${INCLUDE_PATH}

LDFLAGS := -lcmocka

TARGETS := \
	test_mx_timed_list

BUILD_DIR := build

.PHONY: all
all: ${BUILD_DIR} $(addprefix ${BUILD_DIR}/, ${TARGETS})

.PHONY: clean
clean:
	rm -rf ${BUILD_DIR}

${BUILD_DIR}:
	mkdir -p $@

${BUILD_DIR}/test_%: test_%.c
	gcc -o $@ ${CFLAGS} $< ${LDFLAGS}
	./$@

