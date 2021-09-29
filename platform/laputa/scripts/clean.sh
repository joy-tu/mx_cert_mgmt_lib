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
