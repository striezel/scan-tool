#!/bin/bash

# License: GNU General Public License 3+

# This script contains the commands for the build process on drone.io.
# drone.io currently uses Ubuntu 12.04 LTS.

git submodule update --init --recursive
sudo apt-add-repository -y "ppa:ubuntu-toolchain-r/test"
sudo apt-get update
sudo apt-get install -y iputils-ping libcurl3-gnutls libcurl4-gnutls-dev libjsoncpp-dev libzip-dev g++-4.8 gcc-4.8
export CXX="g++-4.8"
export CC="gcc-4.8"
mkdir ./build
cd ./build
cmake ../
if [[ $? -ne 0 ]]
then
  echo "CMake failed!"
  exit 1
fi

make -j2
if [[ $? -ne 0 ]]
then
  echo "Could not build binary files with make!"
  exit 1
fi

ctest -V
if [[ $? -ne 0 ]]
then
  echo "Some test cases failed!"
  exit 1
fi
