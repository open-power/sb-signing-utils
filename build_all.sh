[ "$#" -gt "1" ] && echo "Too many args." && exit 1
[ "$#" -lt "1" ] && set -- "$@" "lite"

case "`echo $1 | tr A-Z a-z`" in
  lite|light)
    cp -p config.h.lite config.h
    cp -p Makefile.lite Makefile
    make
    ;;
  gnu)
    autoreconf -i -Wno-unsupported && \
    ./configure && \
    make
    ;;
  aix)
    autoreconf -i -Wno-unsupported && \
    ./configure && \
    gmake
    ;;
  *)
    echo "Unknown build type: $1"
    exit 1
    ;;
esac
