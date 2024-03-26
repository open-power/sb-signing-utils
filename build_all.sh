#!/bin/bash

[ "$#" -gt "1" ] && echo "Too many args." && exit 1
[ "$#" -lt "1" ] && set -- "$@" "lite"

case "$(echo "$1" | tr "[:upper:]" "[:lower:]")" in
  lite|light)
    cp -p config.h.lite config.h
    cp -p Makefile.lite Makefile
    make
    ;;
  v2)
      if [ "X$MLCA_PATH" = "X" ]; then
          echo "Must set MLCA_PATH env variable to point to mlca_framework repository"
          exit 1
      fi
    cp -p config.h.lite config.h
    cp -p Makefile.v2 Makefile
    make
    ;;
  gnu)
    autoreconf -i -Wno-unsupported && \
    ./configure && \
    make
    ;;
  aix)
    cp -p config.h.aix config.h
    cp -p Makefile.aix Makefile
    gnu-make
    ;;
  gnuv2)
      if [ "X$MLCA_PATH" = "X" ]; then
          echo "Must set MLCA_PATH env variable to point to mlca_framework repository"
          exit 1
      fi
    autoreconf -i -Wno-unsupported && \
    ./configure --enable-sign-v2 && \
    make
    ;;
  *)
    echo "Unknown build type: $1"
    exit 1
    ;;
esac
