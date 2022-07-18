BUILD_DIR ?= build

DOCS_DIR ?= docs

.PHONY: all clean distclean tests docs
all: ${BUILD_DIR}
	cd $< && cmake -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCMAKE_BUILD_TYPE=release ../platform/laputa
	cd $< && make

debug: ${BUILD_DIR}
	cd $< && cmake -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCMAKE_BUILD_TYPE=debug ../platform/laputa
	cd $< && make

${BUILD_DIR} ${DOCS_DIR}:
	mkdir -p $@

clean: ${BUILD_DIR}
	cd ${BUILD_DIR} && make clean
	cd test && make clean

distclean:
	rm -rf ${BUILD_DIR} ${DOCS_DIR}

tests:
	cd test && make clean && make

docs:
	doxygen
