#!/bin/sh

./autoclean.sh

rm -f configure

rm -f Makefile.in

rm -f config.guess
rm -f config.sub
rm -f install-sh
rm -f missing
rm -f depcomp

if [ 0 = 1 ]; then
autoscan
else
#cd pflib && ./autogen.sh && cd ..

touch NEWS
touch README
touch AUTHORS
touch ChangeLog
touch config.h.in

libtoolize --copy --force --install
aclocal
automake -a -c
autoconf

autoreconf # run twice to get rid of 'ltmain.sh not found'
autoreconf


#./configure --enable-debug --enable-fmtwmmdic --enable-fmtpowerword --enable-fmtbabylonbdc --without-icu4c
#./configure --enable-debug --enable-fmtwmmdic --enable-fmtpowerword --enable-fmtbabylonbdc
if [ 1 = 1 ]; then
./configure --enable-debug
else
./configure
fi
make clean
make

fi
