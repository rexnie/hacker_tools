#!/bin/bash
set -x

tag=`date +%Y%m%d-%H%M`
comitid=$(git log --oneline |head -n 1|awk '{print $1}')
flags=-evb-${comitid}-${tag}

make distclean
make defconfig
make -j16 LOCALVERSION=$flags
#make -j16 rpm-pkg LOCALVERSION=$flags
make modules_install
make install
