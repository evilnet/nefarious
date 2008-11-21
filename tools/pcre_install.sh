#!/bin/sh
# 
# This installs PCRE in $HOME, 

PCRE_VERSION=7.2
MAKE="make"

OLD_DIR=`pwd`
SELF_DIR=`dirname $0`

cd $SELF_DIR
tar -zxf pcre.tar.gz

cd $OLD_DIR/$SELF_DIR/pcre-$PCRE_VERSION
./configure --disable-shared --disable-system-abi --disable-utf8 --prefix=$HOME
$MAKE || exit 1
$MAKE install || exit 1
cd $OLD_DIR

echo ""
echo "PCRE is now installed in $HOME/include and $HOME/lib. You may now configure Nefarious."

