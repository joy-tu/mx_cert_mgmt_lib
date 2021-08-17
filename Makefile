BUILD_DIR ?= build

.PHONY: all clean distclean tests
all: ${BUILD_DIR}
	cd $< && cmake ../platform/laputa
	cd $< && make

${BUILD_DIR}:
	mkdir -p $@

clean: ${BUILD_DIR}
	cd ${BUILD_DIR} && make clean
	cd test && make clean

distclean:
	rm -rf ${BUILD_DIR}

tests:
	cd test && make clean && make
