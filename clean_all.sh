[ "$#" -gt "1" ] && echo "Too many args." && exit 1
[ "$#" -lt "1" ] && set -- "$@" "lite"

case "`echo $1 | tr A-Z a-z`" in
  lite|light)
    make clean
    ;;
  gnu)
    make clean
    rm -f compile config.guess config.sub COPYING depcomp INSTALL install-sh ltmain.sh missing
    rm -rf m4/ autom4te.cache/ *.m4 config.status config.h config.h.in* config.log configure Makefile.in Makefile stamp-h1
    rm -f NEWS README AUTHORS ChangeLog
    ;;
  *)
    echo "Unknown build type: $1"
    exit 1
    ;;
esac
