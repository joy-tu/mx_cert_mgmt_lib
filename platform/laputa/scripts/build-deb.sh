#!/bin/bash

cd $(dirname $0)

./build.sh
mkdir -p ../staging
cd ../staging
cp -r ../bin ../debian ../../../include .
dpkg-buildpackage -b -us -uc
