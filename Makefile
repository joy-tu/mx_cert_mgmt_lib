BUILD_DIR ?= build

.PHONY: all clean
all: ${BUILD_DIR}
	cd $< && cmake ../platform/laputa
	cd $< && make

${BUILD_DIR}:
	mkdir -p $@

clean:
	cd ${BUILD_DIR} && make clean
