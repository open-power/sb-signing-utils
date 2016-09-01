#!/bin/sh

# get things started by running autoreconf 
AUTORECONF=`which autoreconf`

if [ $? != 0 ]
then
    echo "Install autoconf package and run this command again"
    exit 1
fi

$AUTORECONF -i
