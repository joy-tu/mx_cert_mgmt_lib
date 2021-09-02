BUILD_DIR ?= build

DOCS_DIR ?= docs

.PHONY: all clean distclean tests docs
all: ${BUILD_DIR}
	cd $< && cmake ../platform/laputa
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
