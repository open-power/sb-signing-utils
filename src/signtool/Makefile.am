#/* IBM_PROLOG_BEGIN_TAG                                                   */
#/* This is an automatically generated prolog.                             */
#/*                                                                        */
#/* $Source: src/signtool/Makefile.am $                                    */
#/*                                                                        */
#/* OpenPOWER sb-signing-utils Project                                     */
#/*                                                                        */
#/* Contributors Listed Below - COPYRIGHT 2016                             */
#/* [+] International Business Machines Corp.                              */
#/*                                                                        */
#/*                                                                        */
#/* Licensed under the Apache License, Version 2.0 (the "License");        */
#/* you may not use this file except in compliance with the License.       */
#/* You may obtain a copy of the License at                                */
#/*                                                                        */
#/*     http://www.apache.org/licenses/LICENSE-2.0                         */
#/*                                                                        */
#/* Unless required by applicable law or agreed to in writing, software    */
#/* distributed under the License is distributed on an "AS IS" BASIS,      */
#/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or        */
#/* implied. See the License for the specific language governing           */
#/* permissions and limitations under the License.                         */
#/*                                                                        */
#/* IBM_PROLOG_END_TAG           

bin_PROGRAMS = signtool

signtool_SOURCES = \
        IBM_Container.cpp \
        IBM_Exception.cpp \
        IBM_Utils.cpp  \
        IBM_Crypto.cpp  \
        signtool.cpp

signtool_CPPFLAGS = -I. -I -g3 -std=c++11
signtool_LDFLAGS = 
signtool_LDADD = -lcrypto
 
install-data-local:
	$(INSTALL) -dv   $(localstatedir)/rca

install-exec-local:
	$(INSTALL) -dv $(bindir) 
