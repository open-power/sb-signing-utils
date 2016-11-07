/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/signtool/IBM_Exception.cpp $                              */
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

#include <stdio.h>
#include <cstdarg>
#include <cstring>

#include <vector>

#include "IBM_Exception.h"


IBM_Exception::~IBM_Exception() throw() 
{
}


IBM_Exception::IBM_Exception( const char *format, ... ) 
{ 
    const int bufSize = static_cast<int>(std::max((size_t)2048, strlen(format) * 2)); 
    
    std::vector<char> buffer(bufSize, '\0'); 
    
    va_list vargs; 
    va_start(vargs, format); 
    int size = vsnprintf(&buffer[0], bufSize, format, vargs); 
    va_end(vargs); 
    
    if ( size > (bufSize - 1) ) 
    {
        // replace tail of msg with "..."
        size = bufSize - 1; 
        for ( int i = (bufSize - 4); i < (bufSize - 1); ++i ) 
        {
            buffer[i] = '.';
        }
    }
    buffer[size] = '\0'; 
    
    m_what = std::string(&buffer[0], (&buffer[0] + size));
}


const char* IBM_Exception::what() const throw() 
{ 
    return m_what.c_str();
}
