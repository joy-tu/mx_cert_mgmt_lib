#!/bin/bash

rm -rf endentity.*
cd $(dirname $0)
cd ..
rm -rf bin
rm -rf build
rm -rf staging
rm -rf *.deb
rm -rf *.buildinfo
rm -rf *.changes
rm CMakeCache.txt
rm -rf CMakeFiles
rm -rf CPackConfig.cmake
rm -rf CPackSourceConfig.cmake
rm -rf Makefile
rm -rf _CPack_Packages
rm -rf cmake_install.cmake
rm -rf install*
rm -rf *.deb
rm -rf libmx*
