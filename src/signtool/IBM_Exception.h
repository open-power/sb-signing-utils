/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/signtool/IBM_Exception.h $                                */
/*                                                                        */
/* OpenPOWER sb-signing-utils Project                                     */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2016                             */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* Licensed under the Apache License, Version 2.0 (the "License");        */
/* you may not use this file except in compliance with the License.       */
/* You may obtain a copy of the License at                                */
/*                                                                        */
/*     http://www.apache.org/licenses/LICENSE-2.0                         */
/*                                                                        */
/* Unless required by applicable law or agreed to in writing, software    */
/* distributed under the License is distributed on an "AS IS" BASIS,      */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or        */
/* implied. See the License for the specific language governing           */
/* permissions and limitations under the License.                         */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */

#ifndef __IBM_EXCEPTION_H_
#define __IBM_EXCEPTION_H_

#include <string>
#include <stdexcept>

class IBM_Exception : public std::exception
{
public:
    IBM_Exception( const char *p_errorMsg, ... );

    virtual ~IBM_Exception() throw();

    /*
     * Returns this object's error string.
     */
    virtual const char* what() const throw();

private:
    std::string m_what;
};


#define THROW_EXCEPTION(condition) \
    if (condition) \
    { \
        throw IBM_Exception( "Exception thrown at %s [%d] %s", __FILE__, __LINE__, #condition ); \
    }

#define THROW_EXCEPTION_STR(str) \
    throw IBM_Exception( "Exception thrown at %s [%d] %s", __FILE__, __LINE__, str );


#endif  //  __IBM_EXCEPTION_H_
