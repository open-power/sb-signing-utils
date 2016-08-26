#-------------------------------------------------------------------------
#
# Licensed Materials - Property of IBM.
#
# (C) Copyright IBM Corporation 2007,2011
#
# All Rights Reserved.
#
# US Government Users Restricted Rights -
# Use, duplication or disclosure restricted by
# GSA ADP Schedule Contract with IBM Corporation.
#---------------------------------------------------------------------------


#---------------------------------------------------------------------------
# Export directory setup
#
#  EXPORTS     - the list of header file(s) to export
#  EXPORT_COMP - componentname - the subdirectory of the include dir
#  EXPORTS_LIBRARY the name of the library file(s) to export
#  EXPORT_STUB_LIBRARY - 'stub' library - only used for building when full source is not available
#
#  export
#        /include
#            /ipmi
#            /sysserv
#        /lib
#            /mips
#            /x86
#
# To use include files
#    add -I $(EXPORT_INCDIR) to the compiler flags.
#    add #include <componentname/file.h> to source files
#
# To use library files
#    add -Wl,-L$(EXPORT_LIBDIR) to linker flags, for example,
#        bmc_app_LDFLAGS = -Wl,-L$(EXPORT_LIBDIR)
#
#---------------------------------------------------------------------------

ifeq ($(INSTALL),)
INSTALL=install
endif

ifeq ($(SDR2BIN),)
SDR2BIN=sdr2bin
endif

ifeq ($(SDRLINT),)
SDRLINT=sdrlint
endif

ifeq ($(STRICT),1)
#AM_CPPFLAGS	=	-Werror -Wshadow
AM_CPPFLAGS	=	-Werror
endif
AM_CPPFLAGS	+=	-Wformat-security -Wformat-nonliteral -Wformat=2
AM_CPPFLAGS	+=	-fstack-protector -D_FORTIFY_SOURCE=2 -Wall

AM_VERBOSE_INSTALL = $(if $(V),,@echo " INSTALL " $@;)

# initialize name of library directory
# host_alias is set by 'configure' type builds if --host is specified

EXPORT_LIBDIR=$(EXPORT_DIR)/lib/x86
ARCH_BLDDIR=bld-x86/

ifeq ($(host_alias),uc_mips-linux)
   EXPORT_LIBDIR=$(EXPORT_DIR)/lib/mips
endif

ifeq ($(host_alias),sh4-linux-gnu)
   EXPORT_LIBDIR=$(EXPORT_DIR)/lib/sh4
endif

ifeq ($(host_alias),sh4-linux)
   EXPORT_LIBDIR=$(EXPORT_DIR)/lib/sh4
endif

# initialize name of include directory
EXPORT_INCDIR=$(EXPORT_DIR)/include

ifneq ($(EXPORT_COMP),)
   EXPORT_COMP_INCDIR=$(EXPORT_DIR)/include/$(EXPORT_COMP)
else
   EXPORT_COMP_INCDIR=$(EXPORT_DIR)/include
endif

# create export include dir if it does not exist
$(EXPORT_INCDIR)::
	@if test ! -d $@; then echo Creating $@; rm -rf $@; $(INSTALL) -d $@; else true; fi

# create export include component dir if it does not exist
$(EXPORT_COMP_INCDIR)::
	@if test ! -d $@; then echo Creating $@; rm -rf $@; $(INSTALL) -d $@; else true; fi

# create export lib dir if it does not exist
$(EXPORT_LIBDIR)::
	@if test ! -d $@; then echo Creating $@; rm -rf $@; $(INSTALL) -d $@; else true; fi

# export subdirectories
export::
	@list='$(SUBDIRS)'; for subdir in $$list; do \
	  test "$$subdir" = . || (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) export); \
	done

# install exports in export dir
ifneq ($(EXPORTS),)
export:: $(EXPORTS) $(EXPORT_COMP_INCDIR)
	$(AM_VERBOSE_INSTALL)$(INSTALL) $(IFLAGS1) -p $^
endif

# install exports in export dir
# use cp -d instead of install so links are copied (x.so, x.so.1, etc)
ifneq ($(EXPORT_LIBRARY),)
export:: $(EXPORT_LIBRARY) $(EXPORT_LIBDIR)
	@list='$(EXPORT_LIBRARY)'; for explib in $$list; do \
	  cp -d $$explib* $(EXPORT_LIBDIR); \
	done
endif

# install stub libraries in export dir
# don't install stub if there is already one in the export dir to prevent overwriting the non-stub version
ifneq ($(EXPORT_STUB_LIBRARY),)
export:: $(EXPORT_STUB_LIBRARY) $(EXPORT_LIBDIR)
	@list='$(EXPORT_STUB_LIBRARY)'; for explib in $$list; do \
	  test -e $(EXPORT_LIBDIR)/$$explib || cp -d $$explib* $(EXPORT_LIBDIR); \
	done
endif


#---------------------------------------------------------------------------
# shared library
#
# automake does not directly support building shared libraries.
# It requires libtool, which seemed to have a lot of undesireable side effects.
# These settings will allow building a shared library from the static library of the same name.
#
# These settings are for all shared libraries in a single make file
#   SHARED_LIBS		  - name of the shared libraries to create (libx.so)
#   SHARED_LIBS_MAP        - if set, create map file
#   SHARED_LIBS_CXX        - if set, uses g++ as linker.  default is gcc.
#   SHARED_LIBS_STANDALONE - if set, requires that all symbols must be defined at link time
#
# These settings are per shared library.  Create the static library and use the 'canonical'
# name of the shared object to set extra libraries and flags.
#
# *** NOTE USE OF LFLAGS, NOT LDFLAGS - automake gives errors for variables usings its suffixes
#
#  'prog'_LIBS
#  'prog'_LFLAGS
#
# libplatform_common_so_LIBS = # use -lname format for extra libs
# libplatform_common_so_LFLAGS = -Wl,--soname=plat_comm
#
#---------------------------------------------------------------------------

DSO_CFLAGS = -fpic

DSO_LDOPTS = -shared
DSO_LDOPTS += -Wl,-O1      # turn on LINKER optimization
DSO_LDOPTS += -Wl,-fpic    # use Position Independent Code
DSO_LDOPTS += -Wl,-z,now   # bind all symbols at init time
DSO_LDOPTS += -Wl,-z,relro # make sections read only after they are loaded,

DSO_MAP = -Wl,-Map=$@.map # make a map
DSO_STANDALONE = -Wl,-z,defs # specifies that all symbols must be defined so the dso is self contained.

#---------------------------------------------------------------------------
#
#  The security CFLAGS turn on compiler specific directives that enhance
#  runtime security.
#
#---------------------------------------------------------------------------

DSO_SECURITY_CFLAGS = -fstack-protector -D_FORTIFY_SOURCE="2"
#DSO_CFLAGS = $(DSO_CFLAGS) $(DSO_SECURITY_CFLAGS)


ifdef SHARED_LIBS_STANDALONE
   DSO_LDOPTS += $(DSO_STANDALONE)
endif

ifdef SHARED_LIBS_MAP
   DSO_LDOPTS += $(DSO_MAP)
endif

ifneq (,$(SHARED_LIBS_CXX))
   AM_VERBOSE_MKSHLIB = $(if $(V),,@echo "  CXXLD   " $$@;)
   MKSHLIB=$(AM_VERBOSE_MKSHLIB)$(CXX) $(CXXFLAGS)
else
   AM_VERBOSE_MKSHLIB = $(if $(V),,@echo "  CCLD    " $$@;)
   MKSHLIB=$(AM_VERBOSE_MKSHLIB)$(CC) $(CFLAGS)
endif

#---------------------------------------------------------------------------------
# create a template for building shared libs
#  $1= libx.so
#  $2= libx_so
#---------------------------------------------------------------------------------
define SHARED_LIBS_template
$(eval $(2)_opts = $$(DSO_LDOPTS) -Wl,--whole-archive $(1:.so=.a) -Wl,--no-whole-archive $$($(2)_LFLAGS) $$($(2)_LIBS))
$(1) : $(1:.so=.a)
	$(MKSHLIB)  -o $$@ $($(2)_opts)
endef

$(foreach lib,$(SHARED_LIBS),$(eval $(call SHARED_LIBS_template,$(lib),$(subst .,_,$(lib)))))


#---------------------------------------------------------------------------
#
# create a sdr data file from the sdr file of the same name
#     USAGE: sdr2bin <machine.sdr> [-b outfile.bin]
#
#---------------------------------------------------------------------------

vpath %.sdr $(srcdir)

%.sdrdat : %.sdr
	$(SDR2BIN) $< -b $@

#---------------------------------------------------------------------------
#
# remove unused header files from source
#
#---------------------------------------------------------------------------

%.clnd : %.cpp
	cleanincs.tcl -f $< -o $@

# cleanincs for subdirectories
cleanincs::
	@list='$(SUBDIRS)'; for subdir in $$list; do \
	  test "$$subdir" = . || (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) cleanincs); \
	done


# cleanincs for single directory
cleanincs:: $(SOURCES:.cpp=.clnd)
	
#---------------------------------------------------------------------------
#
# handle orange files
#
# files that are classified as 'orange' go into a separate directory
# next to the top level project.
# the ORANGE_DIR can be changed in the environment
#---------------------------------------------------------------------------
ORANGE_DIR ?= $(project_dir)/../imm.orange

ifneq ($(ORANGE_FILES),)
ORANGE_OBJS1 = $(addsuffix .$(OBJEXT),$(basename $(ORANGE_FILES)))
ORANGE_OBJS = $(wildcard $(addprefix *, $(ORANGE_OBJS1) ) )
endif

#---------------------------------------------------------------------------
# create links to orange files
#---------------------------------------------------------------------------
orange_file_links : Makefile
ifeq ($(USE_ORANGE),yes)
	@if [ -e $(ORANGE_DIR) ]; then \
	   for file in $(ORANGE_FILES); do \
	      if [ -e $(ORANGE_DIR)/$(ORANGE_SUBDIR)/$$file ]; then \
                  echo "setting up link for orange $$file"; \
                  ln -sf $(ORANGE_DIR)/$(ORANGE_SUBDIR)/$$file . ; \
                  touch orange_file_found  ; \
              fi; \
	   done; \
	fi 
else
	@for file in $(ORANGE_FILES); do \
	   if [ -L $$file ]; then \
	      rm $$file ; \
	   fi; \
	   rm -f orange_file_found; \
	done
endif
	@touch orange_file_links

# clean-orange for subdirectories
clean-orange::
	@list='$(SUBDIRS)'; for subdir in $$list; do \
	  test "$$subdir" = . || (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) clean-orange); \
	done


# clean-orange for single directory
clean-orange::
	@for file in $(ORANGE_FILES); do \
	   if [ -L $$file ]; then \
	      rm $$file ; \
	   fi; \
	done
	@rm -f orange_file_links orange_file_found $(ORANGE_OBJS)
