#!/bin/bash

cd $(dirname $0)

cppcheck .. --error-exitcode=1
