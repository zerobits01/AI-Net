#!/bin/bash

set -e


apt-get install -y vim curl python-cffi python-pycparser python-ply build-essential git



# git clone https://gitlab.com/flexiwangroup/flexiroutersb.git
cp -r ./originals/flexiroutersb .
mv flexiroutersb vppsb
# git clone https://github.com/FDio/vpp
cp -r ./originals/vpp .


cd vpp

git checkout stable/2101

make install-dep
make install-ext-deps

VPP_PATH=`pwd`

VPP_PATH_BINARIES=$VPP_PATH/build-root/build-vpp-native/vpp

make build-release


cd -

cd vppsb

git checkout compile_problem

cd netlink

sed -i 's/AM_CFLAGS += -O2.*/AM_CFLAGS += -O2 -DCLIB_VEC64=0/g' Makefile.am

libtoolize
aclocal
autoconf
automake --add-missing
ENABLE_DEBUG=--enable-debug


./configure VPP_DIR=$VPP_PATH $ENABLE_DEBUG

make

if [ -d $VPP_PATH_BINARIES/lib/ ]; then
  ln -sfn $(pwd)/.libs/librtnl.so $VPP_PATH_BINARIES/lib/librtnl.so
  ln -sfn $(pwd)/.libs/librtnl.so.0 $VPP_PATH_BINARIES/lib/librtnl.so.0
fi

cd -

cd router

cmd="sed -i 's#AM_CFLAGS = -Wall -I@TOOLKIT_INCLUDE@.*#AM_CFLAGS = -Wall -I@TOOLKIT_INCLUDE@ -DCLIB_DEBUG -DCLIB_VEC64=0 -I../../vpp/src -I$VPP_PATH_BINARIES -I../netlink -L../netlink/.libs#g' Makefile.am"
echo $smd
eval $cmd


libtoolize
aclocal
autoconf
automake --add-missing
./configure

make

if [ -d $VPP_PATH_BINARIES/lib/ ]; then
  ln -sfn $(pwd)/.libs/router.so $VPP_PATH_BINARIES/lib/vpp_plugins/router.so
fi

cd $VPP_PATH
cd ..
