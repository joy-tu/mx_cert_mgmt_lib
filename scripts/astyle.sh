#!/bin/bash

cd $(dirname $0)

ASTYLE_RULE="-A1 -c -f -n -p -s4 -w -H -U -xg -k3 -W3 -j -z2"
ASTYLE_FILES="../*.c ../*.h"

! astyle --dry-run -r ${ASTYLE_FILES} ${ASTYLE_RULE} | grep Formatted
