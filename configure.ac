#-------------------------------------------------------------------------
# 
# Licensed Materials - Property of IBM.
# 
# (C) Copyright IBM Corporation 2007,2013
# 
# All Rights Reserved.
# 
# US Government Users Restricted Rights -
# Use, duplication or disclosure restricted by
# GSA ADP Schedule Contract with IBM Corporation.
#---------------------------------------------------------------------------
AC_INIT(SecureAndTrustedBoot, 1.0.0, subras@us.ibm.com)
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([-Wall -Werror foreign -Wno-portability])
AM_SILENT_RULES([yes])

# not using config.h yet
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_CXX

# Checks for libraries.
 # FIXME: Replace `main' with a function in `-lrt':
 #AC_CHECK_LIB([rt], [main])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
 #AC_C_CONST
 #AC_TYPE_PID_T
 #AC_HEADER_TIME
 #AC_STRUCT_TM
 #AC_TYPE_UINT16_T
 #AC_TYPE_UINT32_T
 #AC_TYPE_UINT8_T

# Checks for library functions.
 #AC_FUNC_FORK
 #AC_PROG_GCC_TRADITIONAL
 #AC_FUNC_MALLOC
 #AC_HEADER_STDC
 #AC_TYPE_SIGNAL
 #AC_FUNC_VPRINTF
 #AC_CHECK_FUNCS([gettimeofday memset strchr])

#--------------------------------------------------------------------
# set top level dir, export dir and config dir
#--------------------------------------------------------------------
# the upper level dir
project_dir="\$(top_srcdir)"
AC_SUBST(project_dir)

# exported files destination
EXPORT_DIR="\$(project_dir)/export"
AC_SUBST(EXPORT_DIR)

# initialize name of library directory
if test "x$host_cpu" != "x"; then
   EXPORT_LIBDIR=$EXPORT_DIR/lib/$(host_cpu)
else
   # assume x86
   EXPORT_LIBDIR=$EXPORT_DIR/lib/x86
fi
AC_SUBST(EXPORT_LIBDIR)


# Check host for build type
AM_CONDITIONAL(BLD_X86,  [test x${host}  = x] )

# Set #define in config.h
AH_TEMPLATE([__X86], [Defined if compiling for x86])
AC_DEFINE(__X86,1)

# initialize name of include directory
EXPORT_INCDIR=$EXPORT_DIR/include
AC_SUBST(EXPORT_INCDIR)

#--------------------------------------------------------------------
# compiler stuff
#--------------------------------------------------------------------
MY_CFLAGS="-Wall -Wno-sign-compare  -include config.h  -I \$(EXPORT_INCDIR)"

AM_CPPFLAGS="$MY_CFLAGS"

AC_SUBST(AM_CPPFLAGS)

AM_CFLAGS="-I \$(EXPORT_INCDIR)"

AC_SUBST(AM_CFLAGS)

# extra config/make files
config_dir="\$(project_dir)/config"
AC_SUBST(config_dir)


AC_CONFIG_FILES([
   Makefile 
   src/Makefile
   src/signtool/Makefile
])

AC_OUTPUT
