/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/signtool/IBM_HexString.h $                                */
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

#ifndef __IBM_HEXSTRING_H_
#define __IBM_HEXSTRING_H_

#include <stdint.h>

#include <string>
#include <vector>
#include <istream>
#include <ostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <iostream>


//  A hex string object.

typedef unsigned char byte;

typedef std::vector<byte> IBM_HexBytes;

class IBM_HexString
{
    friend std::ostream& operator<< ( std::ostream& strm,
                                      const IBM_HexString& hs );

public:
    inline void setWidth( uint8_t width )
    { 
        m_width = width;
    }

    inline void setLeadSpace( uint8_t leadSpace )
    { 
        m_leadSpace = leadSpace;
    }

    inline bool isValid() const
    {
        return m_valid;
    }

    inline std::string getAscii() const
    {
        return m_ascii;
    }

    inline std::vector<uint8_t> getBinary () const
    {
        return m_bytes;
    }

    //  Constructors
    inline IBM_HexString (std::string       hexInAscii );
    inline IBM_HexString (std::vector<byte> byteArray  );

private:
    uint8_t         m_width;
    uint8_t         m_leadSpace;
    bool            m_valid;
    std::string     m_ascii;
    IBM_HexBytes    m_bytes;
};


inline IBM_HexString::IBM_HexString ( std::string hexInAscii )
   : m_width(0),
     m_leadSpace(0),
     m_valid(true)
{
    //  Size must be divisible by 2.
    if (hexInAscii.size() % 2)
    {
        return;
    }

    //  Must be the right kind of char.
    size_t found = hexInAscii.find_first_not_of("0123456789abcdefABCDEF ");

    if (found != std::string::npos)
    {
        return;
    }
    
    // Prepare for conversion.
    m_ascii = hexInAscii;

    // Convert each pair of digits into a byte.
    for( std::string::const_iterator i =  m_ascii.begin();
                                     i != m_ascii.end();
                                     i += 2 )
    {
        unsigned b;

        std::string temp( i, i + 2 );

        std::stringstream conv( temp, std::istringstream::in );

        conv >> std::hex >> b;

        m_bytes.push_back((uint8_t)b);
    }

    m_valid = true;
}



inline IBM_HexString::IBM_HexString( std::vector<byte> byteArray )
   : m_width(0),
     m_leadSpace(0),
     m_valid(true),
     m_bytes(byteArray)
{
    std::stringstream conv(std::istringstream::out);

    conv << std::hex << std::setfill('0') << std::uppercase;

    // Convert each byte into a pair of hexadecimal characters.
    for( std::vector<uint8_t>::const_iterator i = m_bytes.begin();
         i != m_bytes.end();
         ++i )
    {
        conv << std::setw(2) << (unsigned) * i;
    }

    // Store the converted value.
    m_ascii = conv.str();
}


inline std::ostream& operator<< ( std::ostream& strm, const IBM_HexString& hc )
{
    unsigned int count = 0;

    int width = hc.m_width;

    if (width == 0)
    {
        width = 128;
    }

    for( std::string::const_iterator it =  hc.m_ascii.begin();
                                     it != hc.m_ascii.end();
                                     it++ )
    {
        ++count;

        strm << *it;

        if ((count % width) == 0)
        {
            strm << std::endl;
            if (hc.m_leadSpace)
            {
                strm << std::string( hc.m_leadSpace, ' ' );
            }
        }
    }

    if ((count % width) != 0)
    {
        strm << std::endl;
    }

    return strm;
}

#endif // __IBM_HEXSTRING_H_
