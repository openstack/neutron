#!/bin/bash
ALIEN=`which alien`
if [ $? -ne 0 ]; then
	echo "You must have alien installed to build debian packages"
	exit 1
fi
FAKEROOT=""
if [ `id -u` != 0 ]; then
	FAKEROOT=`which fakeroot`
	if [ $? -ne 0 ]; then
		echo "You must be root or have fakeroot installed to build debian packages"
		exit 1
	fi
fi

ls $@/dist/*.rpm >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "You must build rpms before building debian packages"
	exit 1
fi

cd $@
if [ $? -ne 0 ]; then
	echo "Directory $@ doesn't exist -- what do you want me to build?"
	exit 1
fi
$FAKEROOT $ALIEN -c -v -d dist/*.noarch.rpm
