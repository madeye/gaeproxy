#!/bin/sh
# AUTO-GENERATED FILE, DO NOT EDIT!
if [ -f $1.org ]; then
  sed -e 's!^D:/cygwin/lib!/usr/lib!ig;s! D:/cygwin/lib! /usr/lib!ig;s!^D:/cygwin/bin!/usr/bin!ig;s! D:/cygwin/bin! /usr/bin!ig;s!^D:/cygwin/!/!ig;s! D:/cygwin/! /!ig;s!^O:!/cygdrive/o!ig;s! O:! /cygdrive/o!ig;s!^L:!/cygdrive/l!ig;s! L:! /cygdrive/l!ig;s!^E:!/cygdrive/e!ig;s! E:! /cygdrive/e!ig;s!^D:!/cygdrive/d!ig;s! D:! /cygdrive/d!ig;s!^C:!/cygdrive/c!ig;s! C:! /cygdrive/c!ig;' $1.org > $1 && rm -f $1.org
fi
