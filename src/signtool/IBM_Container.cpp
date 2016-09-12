/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/signtool/IBM_Container.cpp $                              */
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

#include <string.h>
#include <stddef.h>

#include <endian.h>

#include <sstream>
#include <fstream>
#include <iostream>
#include <algorithm>

#include "IBM_Crypto.h"
#include "IBM_Exception.h"
#include "IBM_HexString.h"
#include "IBM_Container.h"
#include "IBM_Utils.h"

namespace
{
    const static uint32_t g_COL_WIDTH = 24;

    const static uint32_t g_COMPRESSED_PUBKEY_FORMAT = 0x04;

    const static std::string g_HASH_ALGO_SHA512_NAME   = "SHA-512";
    const static std::string g_SIGN_ALGO_ECDSA521_NAME = "ECDSA521";

    template<typename T_PAIR>
    struct GetKey: public std::unary_function<T_PAIR, typename T_PAIR::first_type>
    {
        const typename T_PAIR::first_type& operator()(const T_PAIR& item) const
        {
            return item.first;
        }
    };

    uint16_t getUint16( const uint8_t *data )
    {
        uint16_t value = 0;

        value = data[1] | (data[0] << 8);

        return value;
    }

    uint32_t getUint32( const uint8_t *data )
    {
        uint32_t value = 0;

        value = (data[3] | (data[2] << 8) | (data[1] << 16) | (data[0] << 24));

        return value;
    }

    uint64_t getUint64( const uint8_t *data )
    {
        uint64_t value = 0;

        value = (            data[7]        | ((uint16_t)data[6] << 8)  | 
                  ((uint32_t)data[5] << 16) | ((uint32_t)data[4] << 24) |
                  ((uint64_t)data[3] << 32) | ((uint64_t)data[2] << 40) |
                  ((uint64_t)data[1] << 48) | ((uint64_t)data[0] << 56) );

        return value;
    }

    void printHexBytes( const uint8_t* bytes, size_t size, size_t leadSpace )
    {
        std::vector<uint8_t> byteArray;

        byteArray.assign(bytes, bytes+size);

        IBM_HexString hStr( byteArray );

        hStr.setWidth(36);
        hStr.setLeadSpace(leadSpace);

        std::cout << hStr;
    }

  
    const char* GetHashAlgoName( int p_hashAlgoNum )
    {
        static std::map<int, std::string> s_hashAlgoNames;

        if (s_hashAlgoNames.empty() == 0)
        {
            s_hashAlgoNames[HASH_ALG_SHA512] = g_HASH_ALGO_SHA512_NAME;
        }

        std::string hashAlgoName = "Unknown";

        std::map<int, std::string>::const_iterator itr = s_hashAlgoNames.find(p_hashAlgoNum);
        if (itr != s_hashAlgoNames.end())
        {
            hashAlgoName = itr->second.c_str();
        }

        return hashAlgoName.c_str();
    };

  
    const char* GetSignAlgoName( int p_signAlgoNum )
    {
        static std::map<int, std::string> s_signAlgoNames;

        if (s_signAlgoNames.empty() == 0)
        {
            s_signAlgoNames[SIG_ALG_ECDSA521] = g_SIGN_ALGO_ECDSA521_NAME;
        }

        std::string signAlgoName = "Unknown";

        std::map<int, std::string>::const_iterator itr = s_signAlgoNames.find((int) p_signAlgoNum);
        if (itr != s_signAlgoNames.end())
        {
            signAlgoName = itr->second.c_str();
        }

        return signAlgoName.c_str();
    };

    
    void ReadPublicKeyFromFile( const std::string&    p_mode,
                                const std::string&    p_keyFileName,
                                std::vector<uint8_t>& p_buffer )
    {
        IBM_Utils* pUtils = IBM_Utils::get();
        THROW_EXCEPTION(pUtils == NULL);

        if (p_mode == IBM_Utils::g_MODE_PRODUCTION)
        {
            pUtils->ReadFromFile( p_keyFileName,
                                  p_buffer,
                                  ECDSA521_KEY_SIZE + 1 ); // since keyfile is 133 bytes with 0x04
                                                           // at the begining

            if (p_buffer[0] != g_COMPRESSED_PUBKEY_FORMAT)
            {
                std::stringstream ss;
                ss << "File <" 
                   << p_keyFileName 
                   << "> is not a vaid p521 public key file"
                   << std::endl;

                THROW_EXCEPTION_STR(ss.str().c_str());
            }
            
            // public key file OK, delete the first byte
            p_buffer.erase( p_buffer.begin() );
        }
        else if (p_mode == IBM_Utils::g_MODE_DEVELOPMENT)
        {
            pUtils->GetPublicKeyBytes( p_keyFileName.c_str(), p_buffer );
        }
        else
        {
            // should never get here
            std::stringstream ss;
            ss << "mode <" << p_mode << "> is not supported, must be one of "
               << IBM_Utils::g_MODE_PRODUCTION << " or " << IBM_Utils::g_MODE_DEVELOPMENT;

            THROW_EXCEPTION_STR(ss.str().c_str());
        }

        THROW_EXCEPTION(p_buffer.size() != ECDSA521_KEY_SIZE);
    }


    void ReadSignatureFromFile( const std::string&    p_mode,
                                const std::string&    p_sigFileName,
                                std::vector<uint8_t>& p_buffer )
    {
        IBM_Utils* pUtils = IBM_Utils::get();
        THROW_EXCEPTION(pUtils == NULL);

        if (p_mode == IBM_Utils::g_MODE_PRODUCTION)
        {
            pUtils->ReadFromFile( p_sigFileName, p_buffer, ECDSA521_SIG_SIZE );
        }
        else if (p_mode == IBM_Utils::g_MODE_DEVELOPMENT)
        {
            pUtils->GetSignatureBytes( p_sigFileName.c_str(), p_buffer );
        }
        else
        {
            // should never get here
            std::stringstream ss;
            ss << "mode <" << p_mode << "> is not supported, must be one of "
               << IBM_Utils::g_MODE_PRODUCTION << " or " << IBM_Utils::g_MODE_DEVELOPMENT;

            THROW_EXCEPTION_STR(ss.str().c_str());
        } 

        THROW_EXCEPTION(p_buffer.size() != ECDSA521_SIG_SIZE);
    } 
}



// ContainerHdr C'tor
ContainerHdr::ContainerHdr()
   : m_magicNumber( ROM_MAGIC_NUMBER ),
     m_version( CONTAINER_VERSION ),
     m_containerSize(0),
     m_targetHrmor(0),
     m_stackPointer(0),
     m_hwPkeyA(),
     m_hwPkeyB(),
     m_hwPkeyC()
{
}


/**
 * @brief   Get the Container Header message as a byte stream
 *
 * @param[out]  packet  -  A reference to a vector of type uint8_t
 */
void ContainerHdr::GetHeaderBytes( std::vector<uint8_t>& packet ) const
{
    packet.clear();

    // insert the magic nummber field
    packet.push_back((m_magicNumber >> 24) & 0xFF);
    packet.push_back((m_magicNumber >> 16) & 0xFF);
    packet.push_back((m_magicNumber >> 8) & 0xFF);
    packet.push_back(m_magicNumber & 0xFF);

    // insert the version field
    packet.push_back((m_version >> 8) & 0xFF);
    packet.push_back(m_version & 0xFF);

    // insert the container size field
    packet.push_back((m_containerSize >> 56) & 0xFF);
    packet.push_back((m_containerSize >> 48) & 0xFF);
    packet.push_back((m_containerSize >> 40) & 0xFF);
    packet.push_back((m_containerSize >> 32) & 0xFF);
    packet.push_back((m_containerSize >> 24) & 0xFF);
    packet.push_back((m_containerSize >> 16) & 0xFF);
    packet.push_back((m_containerSize >> 8) & 0xFF);
    packet.push_back(m_containerSize & 0xFF);

    // insert the target Hrmor field
    packet.push_back((m_targetHrmor >> 56) & 0xFF);
    packet.push_back((m_targetHrmor >> 48) & 0xFF);
    packet.push_back((m_targetHrmor >> 40) & 0xFF);
    packet.push_back((m_targetHrmor >> 32) & 0xFF);
    packet.push_back((m_targetHrmor >> 24) & 0xFF);
    packet.push_back((m_targetHrmor >> 16) & 0xFF);
    packet.push_back((m_targetHrmor >> 8) & 0xFF);
    packet.push_back(m_targetHrmor & 0xFF);
    
    // insert the stack Pointer field
    packet.push_back((m_stackPointer >> 56) & 0xFF);
    packet.push_back((m_stackPointer >> 48) & 0xFF);
    packet.push_back((m_stackPointer >> 40) & 0xFF);
    packet.push_back((m_stackPointer >> 32) & 0xFF);
    packet.push_back((m_stackPointer >> 24) & 0xFF);
    packet.push_back((m_stackPointer >> 16) & 0xFF);
    packet.push_back((m_stackPointer >> 8) & 0xFF);
    packet.push_back(m_stackPointer & 0xFF);
    
    // insert the HW Public Key-A field
    packet.insert( packet.end(),
                   m_hwPkeyA,
                   (m_hwPkeyA + sizeof(m_hwPkeyA)) );
    
    // insert the HW Public Key-B field
    packet.insert( packet.end(),
                   m_hwPkeyB,
                   (m_hwPkeyB + sizeof(m_hwPkeyB)) );
    
    // insert the HW Public Key-C field
    packet.insert( packet.end(),
                   m_hwPkeyC,
                   (m_hwPkeyC + sizeof(m_hwPkeyC)) );
}


/**
 *  @brief   print the Container Header
 */
void ContainerHdr::PrintHeader() const
{
    std::cout << "-----------------------------------------------------------------"
              << std::endl
              << " Container Header"
              << std::endl
              << "-----------------------------------------------------------------"
              << std::endl
              << "   m_magicNumber      = " << std::hex << std::setfill('0') << std::setw(8) << m_magicNumber
              << std::endl
              << "   m_version          = " << std::hex << std::setfill('0') << std::setw(4) << m_version
              << std::endl;

    std::cout << "   m_containerSize    = " << std::hex << std::setfill('0') << std::setw(16) << m_containerSize
              << std::endl;

    std::cout << "   m_targetHrmor      = " << std::hex << std::setfill('0') << std::setw(16) << m_targetHrmor
              << std::endl;

    std::cout << "   m_stackPointer     = " << std::hex << std::setfill('0') << std::setw(16) << m_stackPointer
              << std::endl;

    std::cout << "   m_hwPkeyA          = ";
    printHexBytes( m_hwPkeyA, ECDSA521_KEY_SIZE, g_COL_WIDTH );

    std::cout << "   m_hwPkeyB          = ";
    printHexBytes( m_hwPkeyB, ECDSA521_KEY_SIZE, g_COL_WIDTH );

    std::cout << "   m_hwPkeyC          = ";
    printHexBytes( m_hwPkeyC, ECDSA521_KEY_SIZE, g_COL_WIDTH );
    std::cout << std::endl;
}


// PrefixHdr C'tor
PrefixHdr::PrefixHdr()
   : m_version( HEADER_VERSION ),
     m_hashAlg( HASH_ALG_SHA512 ),
     m_sigAlg( SIG_ALG_ECDSA521 ),
     m_codeStartOffset(0),
     m_reserved(),
     m_flags( 0 ),
     m_swKeyCount( 0 ),
     m_payloadSize(0),
     m_payloadHash(),
     m_ecidCount( 0 ),
     m_ecid()
{
}


/**
 * @brief   Get the Prefix Header message as a byte stream
 *
 * @param[out]  packet  -  A reference to a vector of type uint8_t
 */
void PrefixHdr::GetHeaderBytes( std::vector<uint8_t>& packet ) const
{
    packet.clear();

    // insert the version field
    packet.push_back( (m_version >> 8) & 0xFF );
    packet.push_back( m_version & 0xFF );

    // insert the hash algorithm field
    packet.push_back( m_hashAlg );

    // insert the signature algorithm field
    packet.push_back( m_sigAlg );

    // insert the code start offset field
    packet.push_back((m_codeStartOffset >> 56) & 0xFF);
    packet.push_back((m_codeStartOffset >> 48) & 0xFF);
    packet.push_back((m_codeStartOffset >> 40) & 0xFF);
    packet.push_back((m_codeStartOffset >> 32) & 0xFF);
    packet.push_back((m_codeStartOffset >> 24) & 0xFF);
    packet.push_back((m_codeStartOffset >> 16) & 0xFF);
    packet.push_back((m_codeStartOffset >> 8) & 0xFF);
    packet.push_back(m_codeStartOffset & 0xFF);
    
    // insert the reserved bytes field
    packet.insert( packet.end(), 
                   m_reserved,
                   (m_reserved + sizeof(m_reserved)) );
    
    // insert the flags field
    packet.push_back((m_flags >> 24) & 0xFF );
    packet.push_back((m_flags >> 16) & 0xFF );
    packet.push_back((m_flags >> 8) & 0xFF );
    packet.push_back(m_flags & 0xFF );

    // insert the sw key count field
    packet.push_back(m_swKeyCount);

    // insert the payload size field
    packet.push_back((m_payloadSize >> 56) & 0xFF);
    packet.push_back((m_payloadSize >> 48) & 0xFF);
    packet.push_back((m_payloadSize >> 40) & 0xFF);
    packet.push_back((m_payloadSize >> 32) & 0xFF);
    packet.push_back((m_payloadSize >> 24) & 0xFF);
    packet.push_back((m_payloadSize >> 16) & 0xFF);
    packet.push_back((m_payloadSize >> 8) & 0xFF);
    packet.push_back(m_payloadSize & 0xFF);
    
    // insert the payload hash field
    packet.insert( packet.end(),
                   m_payloadHash,
                   (m_payloadHash + sizeof(m_payloadHash)) );
    
    // insert the ECID count field
    packet.push_back( m_ecidCount );

    // insert ECID data if exists
    if (m_ecidCount > 0)
    {
        packet.insert( packet.end(),
                       m_ecid,
                       (m_ecid + sizeof(m_ecid)) );
    }
}



/**
 *  @brief   print the Prefix Header
 */
void PrefixHdr::PrintHeader() const
{
    std::cout << "-----------------------------------------------------------------"
              << std::endl
              << " Prefix Header"
              << std::endl
              << "-----------------------------------------------------------------"
              << std::endl
              << "   m_version          = " << std::hex << std::setfill('0') << std::setw(4) << m_version
              << std::endl
              << "   m_hashAlg          = " << GetHashAlgoName( (int) m_hashAlg )
              << std::endl
              << "   m_sigAlg           = " << GetSignAlgoName( (int) m_sigAlg )
              << std::endl;

    std::cout << "   m_codeStartOffset  = " << std::hex << std::setfill('0') << std::setw(16) << m_codeStartOffset
              << std::endl;

    std::cout << "   m_reserved         = ";
    printHexBytes( m_reserved, 8, g_COL_WIDTH );

    std::cout << "   m_flags            = " << std::hex << std::setfill('0') << std::setw(8) << m_flags
              << std::endl
              << "   m_swKeyCount       = " << (int) m_swKeyCount
              << std::endl;

    std::cout << "   m_payloadSize      = " << std::hex << std::setfill('0') << std::setw(16) << m_payloadSize
              << std::endl;

    std::cout << "   m_payloadHash      = ";
    printHexBytes( m_payloadHash, SHA512_DIGEST_SIZE, g_COL_WIDTH );

    std::cout << "   m_ecidCount        = " <<  (int) m_ecidCount
              << std::endl;

    for (int j = 0; j < m_ecidCount; j++)
    {
        std::cout << "   m_ecid[" << j << "]         = ";
        printHexBytes( (const uint8_t *) &m_ecid[(j*ECID_SIZE)], ECID_SIZE, 24 );
    }
    std::cout << std::endl;
}


// PrefixData C'tor
PrefixData::PrefixData()
   : m_hwSigA(),
     m_hwSigB(),
     m_hwSigC(),
     m_swPkeyP(),
     m_swPkeyQ(),
     m_swPkeyR()
{
}


/**
 * @brief   Get the Prefix Data Header message as a byte stream
 *
 * @param[out]  packet  -  A reference to a vector of type uint8_t
 */
void PrefixData::GetHeaderBytes( std::vector<uint8_t>& packet ) const
{
    packet.clear();

    // insert the HW Signature-A field
    packet.insert( packet.end(),
                   m_hwSigA,
                   (m_hwSigA + sizeof(m_hwSigA)) );
    
    // insert the HW Signature-B field
    packet.insert( packet.end(),
                   m_hwSigB,
                   (m_hwSigB + sizeof(m_hwSigB)) );
    
    // insert the HW Signature-C field
    packet.insert( packet.end(),
                   m_hwSigC,
                   (m_hwSigC + sizeof(m_hwSigC)) );

    uint8_t zeroKey[ECDSA521_KEY_SIZE];
    memset( zeroKey, 0, ECDSA521_KEY_SIZE );

    // insert the SW Public Key-P field only if its valid
    if (memcmp( m_swPkeyP, zeroKey, ECDSA521_KEY_SIZE) != 0)
    {
        packet.insert( packet.end(),
                       m_swPkeyP,
                       (m_swPkeyP + sizeof(m_swPkeyP)) );
    }
    
    // insert the SW Public Key-Q field only if its valid
    if (memcmp( m_swPkeyQ, zeroKey, ECDSA521_KEY_SIZE) != 0)
    {
        packet.insert( packet.end(),
                       m_swPkeyQ,
                       (m_swPkeyQ + sizeof(m_swPkeyQ)) );
    }
    
    // insert the SW Public Key-R field only if its valid
    if (memcmp( m_swPkeyR, zeroKey, ECDSA521_KEY_SIZE) != 0)
    {
        packet.insert( packet.end(),
                       m_swPkeyR,
                       (m_swPkeyR + sizeof(m_swPkeyR)) );
    }
}



/**
 *  @brief   print the Prefix Data
 */
void PrefixData::PrintHeader() const
{
    std::cout << "-----------------------------------------------------------------"
              << std::endl
              << " Prefix Data"
              << std::endl
              << "-----------------------------------------------------------------"
              << std::endl;

    std::cout << "   m_hwSigA           = ";
    printHexBytes( m_hwSigA, ECDSA521_SIG_SIZE, g_COL_WIDTH );

    std::cout << "   m_hwSigB           = ";
    printHexBytes( m_hwSigB, ECDSA521_SIG_SIZE, g_COL_WIDTH );

    std::cout << "   m_hwSigC           = ";
    printHexBytes( m_hwSigC, ECDSA521_SIG_SIZE, g_COL_WIDTH );

    std::cout << "   m_swPkeyP          = ";
    printHexBytes( m_swPkeyP, ECDSA521_KEY_SIZE, g_COL_WIDTH );

    std::cout << "   m_swPkeyQ          = ";
    printHexBytes( m_swPkeyQ, ECDSA521_KEY_SIZE, g_COL_WIDTH );

    std::cout << "   m_swPkeyR          = ";
    printHexBytes( m_swPkeyR, ECDSA521_KEY_SIZE, g_COL_WIDTH );
    std::cout << std::endl;
}


/**
 *  @brief   Get Number of valid Software keys
 */
int PrefixData::GetSwKeyCount() const
{
    int swKeyCount = 0; 

    uint8_t zeroKey[ECDSA521_KEY_SIZE];
    memset( zeroKey, 0, ECDSA521_KEY_SIZE );

    if (memcmp( m_swPkeyP, zeroKey, ECDSA521_KEY_SIZE) != 0)
    {
        ++swKeyCount;
    }

    if (memcmp( m_swPkeyQ, zeroKey, ECDSA521_KEY_SIZE) != 0)
    {
        ++swKeyCount;
    }

    if (memcmp( m_swPkeyR, zeroKey, ECDSA521_KEY_SIZE) != 0)
    {
        ++swKeyCount;
    }

    return swKeyCount;
}



// SoftwareHdr C'tor
SoftwareHdr::SoftwareHdr()
   : m_version( HEADER_VERSION ),
     m_hashAlg( HASH_ALG_SHA512 ),
     m_unused( 0 ),
     m_codeStartOffset(),
     m_reserved(),
     m_flags( 0 ),
     m_reserved0( 0 ),
     m_payloadSize(),
     m_payloadHash(),
     m_ecidCount( 0 ),
     m_ecid()
{
}


/**
 * @brief   Get the Software Header message as a byte stream
 *
 * @param[out]  packet  -  A reference to a vector of type uint8_t
 */
void SoftwareHdr::GetHeaderBytes( std::vector<uint8_t>& packet ) const
{
    packet.clear();

    // insert the version field
    packet.push_back((m_version >> 8) & 0xFF );
    packet.push_back(m_version & 0xFF );

    // insert the hash algorithm field
    packet.push_back( m_hashAlg );

    // insert the unused field
    packet.push_back( m_unused );

    // insert the code start offset field
    packet.push_back((m_codeStartOffset >> 56) & 0xFF);
    packet.push_back((m_codeStartOffset >> 48) & 0xFF);
    packet.push_back((m_codeStartOffset >> 40) & 0xFF);
    packet.push_back((m_codeStartOffset >> 32) & 0xFF);
    packet.push_back((m_codeStartOffset >> 24) & 0xFF);
    packet.push_back((m_codeStartOffset >> 16) & 0xFF);
    packet.push_back((m_codeStartOffset >> 8) & 0xFF);
    packet.push_back(m_codeStartOffset & 0xFF);
    
    // insert the reserved bytes field
    packet.insert( packet.end(), 
                   m_reserved,
                   (m_reserved + sizeof(m_reserved)) );
    
    // insert the flags field
    packet.push_back((m_flags >> 24) & 0xFF );
    packet.push_back((m_flags >> 16) & 0xFF );
    packet.push_back((m_flags >> 8) & 0xFF );
    packet.push_back(m_flags & 0xFF );

    // insert the reserved0 field
    packet.push_back(m_reserved0);

    // insert the payload size field
    packet.push_back((m_payloadSize >> 56) & 0xFF);
    packet.push_back((m_payloadSize >> 48) & 0xFF);
    packet.push_back((m_payloadSize >> 40) & 0xFF);
    packet.push_back((m_payloadSize >> 32) & 0xFF);
    packet.push_back((m_payloadSize >> 24) & 0xFF);
    packet.push_back((m_payloadSize >> 16) & 0xFF);
    packet.push_back((m_payloadSize >> 8) & 0xFF);
    packet.push_back(m_payloadSize & 0xFF);
    
    // insert the payload hash field
    packet.insert( packet.end(),
                   m_payloadHash,
                   (m_payloadHash + sizeof(m_payloadHash)) );
    
    // insert the ECID count field
    packet.push_back( m_ecidCount );

    // insert ECID data if exists
    if (m_ecidCount > 0)
    {
        packet.insert( packet.end(),
                       m_ecid,
                       (m_ecid + sizeof(m_ecid)) );
    }
}



/**
 *  @brief   print the Software Header
 */
void SoftwareHdr::PrintHeader() const
{
    std::cout << "-----------------------------------------------------------------"
              << std::endl
              << " Software Header"
              << std::endl
              << "-----------------------------------------------------------------"
              << std::endl
              << "   m_version          = " << std::hex << std::setfill('0') << std::setw(4) << m_version
              << std::endl
              << "   m_hashAlg          = " << GetHashAlgoName( (int) m_hashAlg )
              << std::endl
              << "   m_unused           = "  << (int) m_unused
              << std::endl;

    std::cout << "   m_codeStartOffset  = " << std::hex << std::setfill('0') << std::setw(16) << m_codeStartOffset
              << std::endl;

    std::cout << "   m_reserved         = ";
    printHexBytes( m_reserved, 8, g_COL_WIDTH );

    std::cout << "   m_flags            = " << std::hex << std::setfill('0') << std::setw(8) << std::hex << m_flags
              << std::endl
              << "   m_reserved0        = " << (int) m_reserved0
              << std::endl;

    std::cout << "   m_payloadSize      = " << std::hex << std::setfill('0') << std::setw(16) << m_payloadSize
              << std::endl;

    std::cout << "   m_payloadHash      = ";
    printHexBytes( m_payloadHash, SHA512_DIGEST_SIZE, g_COL_WIDTH );

    std::cout << "   m_ecidCount        = " <<  (int) m_ecidCount
              << std::endl;

    for (int j = 0; j < m_ecidCount; j++)
    {
        std::cout << "   m_ecid[" << j << "]         = ";
        printHexBytes( (const uint8_t *) &m_ecid[(j*ECID_SIZE)], ECID_SIZE, g_COL_WIDTH );
    }
    std::cout << std::endl;
}




// SoftwareSig C'tor
SoftwareSig::SoftwareSig()
   : m_swSigP(),
     m_swSigQ(),
     m_swSigR()
{
}


/**
 * @brief   Get the Prefix Data Header message as a byte stream
 *
 * @param[out]  packet  -  A reference to a vector of type uint8_t
 */
void SoftwareSig::GetHeaderBytes( std::vector<uint8_t>& packet ) const
{
    packet.clear();

    uint8_t zeroKey[ECDSA521_KEY_SIZE];
    memset( zeroKey, 0, ECDSA521_KEY_SIZE );

    // insert the SW Signature-P field only if its valid
    if (memcmp( m_swSigP, zeroKey, ECDSA521_KEY_SIZE) != 0)
    {
        packet.insert( packet.end(),
                       m_swSigP,
                       (m_swSigP + sizeof(m_swSigP)) );
    }

    // insert the SW Signature-Q field only if its valid
    if (memcmp( m_swSigQ, zeroKey, ECDSA521_KEY_SIZE) != 0)
    {
        packet.insert( packet.end(),
                       m_swSigQ,
                       (m_swSigQ + sizeof(m_swSigQ)) );
    }

    // insert the SW Signature-R field only if its valid
    if (memcmp( m_swSigR, zeroKey, ECDSA521_KEY_SIZE) != 0)
    {
        packet.insert( packet.end(),
                       m_swSigR,
                       (m_swSigR + sizeof(m_swSigR)) );
    }
}

    

/**
 *  @brief   print the Software Signature
 */
void SoftwareSig::PrintHeader() const
{
    std::cout << "-----------------------------------------------------------------"
              << std::endl
              << " Software Signature"
              << std::endl
              << "-----------------------------------------------------------------"
              << std::endl;

    std::cout <<  "   m_swSigP           = ";
    printHexBytes( m_swSigP, ECDSA521_SIG_SIZE, g_COL_WIDTH );

    std::cout <<  "   m_swSigQ           = ";
    printHexBytes( m_swSigQ, ECDSA521_SIG_SIZE, g_COL_WIDTH );

    std::cout <<  "   m_swSigR           = ";
    printHexBytes( m_swSigR, ECDSA521_SIG_SIZE, g_COL_WIDTH );
    std::cout << std::endl;
}


// default C'tor
IBM_Container::IBM_Container( std::string p_mode )
   : m_containerHdr(),
     m_prefixHdr(),
     m_prefixData(),
     m_softwareHdr(),
     m_softwareSig(),
     m_mode( p_mode )
{
    if ( !((m_mode == IBM_Utils::g_MODE_PRODUCTION) || 
           (m_mode == IBM_Utils::g_MODE_DEVELOPMENT))  )
    {
        std::stringstream ss;
        ss << "*** Invalid value for mode" << std::endl
           << "--- Expecting <" << IBM_Utils::g_MODE_PRODUCTION 
           << "> or <" << IBM_Utils::g_MODE_DEVELOPMENT << ">, got <"
           << p_mode << ">" << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    initializeMap();
}



// Given a filename, read its contents, parse the data and constuct the container
IBM_Container::IBM_Container( std::string p_mode,
                              std::string p_containerFileName )
   : m_containerHdr(),
     m_prefixHdr(),
     m_prefixData(),
     m_softwareHdr(),
     m_softwareSig(),
     m_mode( p_mode )
{
    if ( !((m_mode == IBM_Utils::g_MODE_PRODUCTION) || 
           (m_mode == IBM_Utils::g_MODE_DEVELOPMENT))  )
    {
        std::stringstream ss;
        ss << "*** Invalid value for mode" << std::endl
           << "--- Expecting <" << IBM_Utils::g_MODE_PRODUCTION 
           << "> or <" << IBM_Utils::g_MODE_DEVELOPMENT << ">, got <"
           << p_mode << ">" << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    initializeMap();

    std::vector<uint8_t> buffer;

    IBM_Utils* pUtils = IBM_Utils::get();

    pUtils->ReadFromFile( p_containerFileName, buffer, 2048 );
                               
    ParseContainer( buffer );
}


// default D'tor
IBM_Container::~IBM_Container()
{
}


int IBM_Container::Validate()
{
}


void IBM_Container::Print() const
{
    m_containerHdr.PrintHeader();
    m_prefixHdr.PrintHeader();
    m_prefixData.PrintHeader();
    m_softwareHdr.PrintHeader();
    m_softwareSig.PrintHeader();
}


bool IBM_Container::Save( const std::string p_fileName )
{
    // update the software key count
    m_prefixHdr.m_swKeyCount = m_prefixData.GetSwKeyCount();

    std::ofstream outfile( p_fileName.c_str(), std::ofstream::binary );
    if (outfile.fail() )
    {
        std::stringstream ss;
        ss << "!-> Failed to open file: " << p_fileName << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    int padLen = 4096;

    std::vector<uint8_t> hdrBytes;

    // write the Container Header bytes
    m_containerHdr.GetHeaderBytes( hdrBytes );
    outfile.write( (char *) &hdrBytes[0], hdrBytes.size() );

    padLen -= hdrBytes.size();

    // write the Prefix Header bytes
    m_prefixHdr.GetHeaderBytes( hdrBytes );
    outfile.write( (char *) &hdrBytes[0], hdrBytes.size() );

    padLen -= hdrBytes.size();

    // write the Prefix Data bytes
    m_prefixData.GetHeaderBytes( hdrBytes );
    outfile.write( (char *) &hdrBytes[0], hdrBytes.size() );

    padLen -= hdrBytes.size();

    // write the Software Header Data bytes
    m_softwareHdr.GetHeaderBytes( hdrBytes );
    outfile.write( (char *) &hdrBytes[0], hdrBytes.size() );

    padLen -= hdrBytes.size();

    // write the Software Signature bytes
    m_softwareSig.GetHeaderBytes( hdrBytes );
    outfile.write( (char *) &hdrBytes[0], hdrBytes.size() );

    padLen -= hdrBytes.size();

    // see if we need to add padding bytes
    if (padLen < 0)
    {
        std::stringstream ss;
        ss << "!-> Wrong container length, must be <= 4096 bytes, it is <" 
           << (4096 - padLen) << "> bytes" << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    std::vector<char> padBytes(padLen, 0);

    outfile.write( &padBytes[0], padBytes.size() );

    outfile.close();

    return true;
}


bool IBM_Container::UpdateField( const std::string p_fldName, const std::string p_value )
{
    ContainerFldMap::iterator itr = m_contFldMap.find(p_fldName);
    if (itr == m_contFldMap.end())
    {
        std::stringstream ss;
        ss << "Invalid field name <" << p_fldName << "> specified, issue \"help\" command"
           << std::endl 
           << "to get the list of supported fields."
           << std::endl << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    bool retVal = true;

    IBM_ContainerFld eFldType = itr->second;
    switch (eFldType)
    {
        case e_CONTAINER_VERSION:
        {
            uint16_t version;

            std::stringstream ss(p_value);
            if (!(ss >> version))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_containerHdr.m_version = version;
            }

            break;
        }

        case e_CONTAINER_SIZE:
        {
            uint64_t containerSize;

            std::stringstream ss(p_value);
            if (!(ss >> std::hex >> containerSize))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_containerHdr.m_containerSize = containerSize;
            }

            break;
        }

        case e_TARGET_HRMOR:
        {
            uint64_t targetHrmor;

            std::stringstream ss(p_value);
            if (!(ss >> std::hex >> targetHrmor))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_containerHdr.m_targetHrmor = targetHrmor;
            }

            break;
        }

        case e_STACK_POINTER:
        {
            uint64_t stackPointer;

            std::stringstream ss(p_value);
            if (!(ss >> std::hex >> stackPointer))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_containerHdr.m_stackPointer = stackPointer;
            }

            break;
        }

        case e_HW_PUBLIC_KEY_A:
        {
            std::vector<uint8_t> buffer;

            ReadPublicKeyFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_containerHdr.m_hwPkeyA, &buffer[0], buffer.size() );

            break;
        }

        case e_HW_PUBLIC_KEY_B:
        {
            std::vector<uint8_t> buffer;

            ReadPublicKeyFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_containerHdr.m_hwPkeyB, &buffer[0], buffer.size() );

            break;
        }

        case e_HW_PUBLIC_KEY_C:
        {
            std::vector<uint8_t> buffer;

            ReadPublicKeyFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_containerHdr.m_hwPkeyC, &buffer[0], buffer.size() );

            break;
        }

        case e_PRE_HDR_VERSION:
        {
            uint16_t version;

            std::stringstream ss(p_value);
            if (!(ss >> version))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_prefixHdr.m_version = version;
            }

            break;
        }

        case e_PRE_HDR_HASH_ALGORITHM:
        {
            uint16_t hashAlg;

            std::stringstream ss(p_value);
            if (!(ss >> hashAlg))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_prefixHdr.m_hashAlg = (uint8_t) hashAlg;
            }
            break;
        }

        case e_PRE_HDR_SIGNING_ALGORITHM:
        {
            uint16_t sigAlg;

            std::stringstream ss(p_value);
            if (!(ss >> sigAlg))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_prefixHdr.m_sigAlg = (uint8_t) sigAlg;
            }

            break;
        }

        case e_PRE_HDR_CODE_START_OFFSET:
        {
            uint64_t codeStartOffset;

            std::stringstream ss(p_value);
            if (!(ss >> std::hex >> codeStartOffset))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_prefixHdr.m_codeStartOffset = codeStartOffset;
            }

            break;
        }

        case e_PRE_HDR_FLAGS:
        {
            uint32_t flags;

            std::stringstream ss(p_value);
            if (!(ss >> std::hex >> flags))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_prefixHdr.m_flags = flags;
            }

            break;
        }

        case e_PRE_HDR_PAYLOAD_SIZE:
        {
            uint64_t payloadSize;

            std::stringstream ss(p_value);
            if (!(ss >> std::hex >> payloadSize))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_prefixHdr.m_payloadSize = payloadSize;
            }

            break;
        }

        case e_PRE_HDR_PAYLOAD_HASH:
        {
            IBM_HexString hexString(p_value);

            IBM_HexBytes hexBytes = hexString.getBinary();

            memcpy( m_prefixHdr.m_payloadHash,
                    (void *) &hexBytes[0],
                    hexBytes.size() );

            break;
        }

        case e_HW_SIGNATURE_A:
        {
            std::vector<uint8_t> buffer;

            ReadSignatureFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_prefixData.m_hwSigA, &buffer[0], buffer.size() );

            break;
        }

        case e_HW_SIGNATURE_B:
        {
            std::vector<uint8_t> buffer;

            ReadSignatureFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_prefixData.m_hwSigB, &buffer[0], buffer.size() );

            break;
        }

        case e_HW_SIGNATURE_C:
        {
            std::vector<uint8_t> buffer;

            ReadSignatureFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_prefixData.m_hwSigC, &buffer[0], buffer.size() );

            break;
        }

        case e_SW_PUBLIC_KEY_P:
        {
            std::vector<uint8_t> buffer;

            ReadPublicKeyFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_prefixData.m_swPkeyP, &buffer[0], buffer.size() );

            break;
        }

        case e_SW_PUBLIC_KEY_Q:
        {
            std::vector<uint8_t> buffer;

            ReadPublicKeyFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_prefixData.m_swPkeyQ, &buffer[0], buffer.size() );

            break;
        }

        case e_SW_PUBLIC_KEY_R:
        {
            std::vector<uint8_t> buffer;

            ReadPublicKeyFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_prefixData.m_swPkeyR, &buffer[0], buffer.size() );

            break;
        }

        case e_SW_HDR_VERSION:
        {
            uint16_t version;

            std::stringstream ss(p_value);
            if (!(ss >> version))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_softwareHdr.m_version = version;
            }

            break;
        }

        case e_SW_HDR_HASH_ALGORITHM:
        {
            uint16_t hashAlg;

            std::stringstream ss(p_value);
            if (!(ss >> hashAlg))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_softwareHdr.m_hashAlg = (uint8_t) hashAlg;
            }

            break;
        }

        case e_SW_HDR_CODE_START_OFFSET:
        {
            uint64_t codeStartOffset;

            std::stringstream ss(p_value);
            if (!(ss >> std::hex >> codeStartOffset))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_softwareHdr.m_codeStartOffset = codeStartOffset;
            }

            break;
        }

        case e_SW_HDR_FLAGS:
        {
            uint32_t flags;

            std::stringstream ss(p_value);
            if (!(ss >> std::hex >> flags))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_softwareHdr.m_flags = flags;
            }

            break;
        }

        case e_SW_HDR_PAYLOAD_SIZE:
        {
            uint64_t payloadSize;

            std::stringstream ss(p_value);
            if (!(ss >> std::hex >> payloadSize))
            {
                std::cout << "Option  <" << p_fldName << "> requires decimal integers only"
                          << std::endl;

                retVal = false;
            }
            else
            {
                m_softwareHdr.m_payloadSize = payloadSize;
            }

            break;
        }

        case e_SW_HDR_PAYLOAD_HASH:
        {
            IBM_HexString hexString(p_value);

            IBM_HexBytes hexBytes = hexString.getBinary();

            memcpy( m_softwareHdr.m_payloadHash,
                    (void *) &hexBytes[0],
                    hexBytes.size() );

            break;
        }

        case e_SW_SIGNATURE_P:
        {
            std::vector<uint8_t> buffer;

            ReadSignatureFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_softwareSig.m_swSigP, &buffer[0], buffer.size() );

            break;
        }

        case e_SW_SIGNATURE_Q:
        {
            std::vector<uint8_t> buffer;

            ReadSignatureFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_softwareSig.m_swSigQ, &buffer[0], buffer.size() );

            break;
        }

        case e_SW_SIGNATURE_R:
        {
            std::vector<uint8_t> buffer;

            ReadSignatureFromFile( m_mode,
                                   p_value,
                                   buffer );

            memcpy( m_softwareSig.m_swSigR, &buffer[0], buffer.size() );

            break;
        }
    }

    return retVal;
}


bool IBM_Container::ComputeHash( std::string  p_hdrFldType,
                                 std::string  p_hashAlgo,
                                 std::string& p_digestStr )
{
    // check input fields
    HdrFldTypeMap::iterator itr = m_hdrFldTypeMap.find(p_hdrFldType);
    if (itr == m_hdrFldTypeMap.end())
    {
        std::stringstream ss;
        ss << "Invalid header field type <" << p_hdrFldType << "> specified, issue \"help\" command"
           << std::endl 
           << "to get the list of supported header fields."
           << std::endl << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    HashAlgoMap::iterator itr1 = m_hashAlgoMap.find(p_hashAlgo);
    if (itr1 == m_hashAlgoMap.end())
    {
        std::stringstream ss;
        ss << "Invalid hash algorithm <" << p_hashAlgo << "> specified, issue \"help\" command"
           << std::endl 
           << "to get the list of supported hash slgorithms."
           << std::endl << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    std::vector<uint8_t> data;

    IBM_HdrFldType hdrFldType = itr->second;
    switch (hdrFldType)
    {
        case e_FLD_PREFIX_HDR:
        {
            m_prefixHdr.GetHeaderBytes(data);
            break;
        }

        case e_FLD_SOFTWARE_HDR:
        {
            m_softwareHdr.GetHeaderBytes(data);
            break;
        }
    }

    THROW_EXCEPTION( data.size() == 0 );

    IBM_HashAlgo hashAlgo = itr1->second;

    IBM_Crypto crypto(m_mode);
 
    return crypto.ComputeHash( hashAlgo, (const unsigned char*) &data[0], data.size(), p_digestStr );
}


void IBM_Container::initializeMap()
{
    m_contFldMap["container-version"]      =  e_CONTAINER_VERSION;
    m_contFldMap["container-size"]         =  e_CONTAINER_SIZE;
    m_contFldMap["target-hrmor"]           =  e_TARGET_HRMOR;
    m_contFldMap["stack-pointer"]          =  e_STACK_POINTER;
    m_contFldMap["hw-keya"]                =  e_HW_PUBLIC_KEY_A;
    m_contFldMap["hw-keyb"]                =  e_HW_PUBLIC_KEY_B;
    m_contFldMap["hw-keyc"]                =  e_HW_PUBLIC_KEY_C;

    m_contFldMap["hdr-version"]            =  e_PRE_HDR_VERSION;
    m_contFldMap["hdr-hash-algo"]          =  e_PRE_HDR_HASH_ALGORITHM;
    m_contFldMap["hdr-sign-algo"]          =  e_PRE_HDR_SIGNING_ALGORITHM;
    m_contFldMap["hdr-code-start-offset"]  =  e_PRE_HDR_CODE_START_OFFSET;
    m_contFldMap["hdr-flags"]              =  e_PRE_HDR_FLAGS;
    m_contFldMap["hdr-payload-size"]       =  e_PRE_HDR_PAYLOAD_SIZE;
    m_contFldMap["hdr-payload-hash"]       =  e_PRE_HDR_PAYLOAD_HASH;

    m_contFldMap["hw-signa"]               =  e_HW_SIGNATURE_A;
    m_contFldMap["hw-signb"]               =  e_HW_SIGNATURE_B;
    m_contFldMap["hw-signc"]               =  e_HW_SIGNATURE_C;
    m_contFldMap["sw-keyp"]                =  e_SW_PUBLIC_KEY_P;
    m_contFldMap["sw-keyq"]                =  e_SW_PUBLIC_KEY_Q;
    m_contFldMap["sw-keyr"]                =  e_SW_PUBLIC_KEY_R;

    m_contFldMap["sw-version"]             =  e_SW_HDR_VERSION;
    m_contFldMap["sw-hash-algo"]           =  e_SW_HDR_HASH_ALGORITHM;
    m_contFldMap["sw-code-start-offset"]   =  e_SW_HDR_CODE_START_OFFSET;
    m_contFldMap["sw-flags"]               =  e_SW_HDR_FLAGS;
    m_contFldMap["sw-payload-size"]        =  e_SW_HDR_PAYLOAD_SIZE;
    m_contFldMap["sw-payload-hash"]        =  e_SW_HDR_PAYLOAD_HASH;

    m_contFldMap["sw-signp"]               =  e_SW_SIGNATURE_P;
    m_contFldMap["sw-signq"]               =  e_SW_SIGNATURE_Q;
    m_contFldMap["sw-signr"]               =  e_SW_SIGNATURE_R;

    m_hdrFldTypeMap["prefix_hdr"]          =  e_FLD_PREFIX_HDR;
    m_hdrFldTypeMap["software_hdr"]        =  e_FLD_SOFTWARE_HDR;

    m_hashAlgoMap["sha1"]                  =  e_SHA1_ALGO;
    m_hashAlgoMap["sha256"]                =  e_SHA256_ALGO;
    m_hashAlgoMap["sha384"]                =  e_SHA384_ALGO;
    m_hashAlgoMap["sha512"]                =  e_SHA512_ALGO;
}


void IBM_Container::GetFieldNameList( std::vector<std::string>& p_fldNameList )
{
    p_fldNameList.clear();

    std::transform( m_contFldMap.begin(), 
                    m_contFldMap.end(),
                    std::inserter( p_fldNameList, p_fldNameList.begin() ),
                    GetKey<ContainerFldMap::value_type>() );
}


// Given a stream of bytes, parse the data and to extract the container fields
void IBM_Container::ParseContainer( const std::vector<uint8_t>& p_rawData )
{
    const uint8_t* pRawData = &p_rawData[0];

    THROW_EXCEPTION( pRawData == NULL );

    int keyCount = 0;

    // Parse the ContainerHdr
    m_containerHdr.m_magicNumber = getUint32( pRawData );
    pRawData += 4;
   
    m_containerHdr.m_version = getUint16( pRawData );
    pRawData += 2;

    m_containerHdr.m_containerSize = getUint64( pRawData );
    pRawData += 8;
   
    m_containerHdr.m_targetHrmor = getUint64( pRawData );
    pRawData += 8;
   
    m_containerHdr.m_stackPointer = getUint64( pRawData );
    pRawData += 8;
   
    memcpy( &m_containerHdr.m_hwPkeyA, pRawData, ECDSA521_KEY_SIZE );
    pRawData += ECDSA521_KEY_SIZE;
   
    memcpy( &m_containerHdr.m_hwPkeyB, pRawData, ECDSA521_KEY_SIZE );
    pRawData += ECDSA521_KEY_SIZE;
   
    memcpy( &m_containerHdr.m_hwPkeyC, pRawData, ECDSA521_KEY_SIZE );
    pRawData += ECDSA521_KEY_SIZE;

    // Parse the PrefixHdr
    m_prefixHdr.m_version = getUint16( pRawData );
    pRawData += 2;

    m_prefixHdr.m_hashAlg = *pRawData++;
    m_prefixHdr.m_sigAlg  = *pRawData++;

    m_prefixHdr.m_codeStartOffset = getUint64( pRawData );
    pRawData += 8;
   
    memcpy( m_prefixHdr.m_reserved, pRawData, 8 );
    pRawData += 8;
   
    m_prefixHdr.m_flags = getUint32( pRawData );
    pRawData += 4;
   
    m_prefixHdr.m_swKeyCount  = *pRawData++;
    keyCount = m_prefixHdr.m_swKeyCount;

    m_prefixHdr.m_payloadSize = getUint64( pRawData );
    pRawData += 8;
   
    memcpy( m_prefixHdr.m_payloadHash, pRawData, SHA512_DIGEST_SIZE );
    pRawData += SHA512_DIGEST_SIZE;
   
    m_prefixHdr.m_ecidCount = *pRawData++;

    for (int i = 0; i < m_prefixHdr.m_ecidCount; i++)
    {
        memcpy( (void *) &m_prefixHdr.m_ecid[i*ECID_SIZE], pRawData, ECID_SIZE );
        pRawData += ECID_SIZE;
    } 

    // Parse the PrefixData
    memcpy( m_prefixData.m_hwSigA, pRawData, ECDSA521_SIG_SIZE );
    pRawData += ECDSA521_SIG_SIZE;
   
    memcpy( m_prefixData.m_hwSigB, pRawData, ECDSA521_SIG_SIZE );
    pRawData += ECDSA521_SIG_SIZE;

    memcpy( m_prefixData.m_hwSigC, pRawData, ECDSA521_SIG_SIZE );
    pRawData += ECDSA521_SIG_SIZE;
   
    if (keyCount > 0) 
    {
        memcpy( m_prefixData.m_swPkeyP, pRawData, ECDSA521_KEY_SIZE );
        pRawData += ECDSA521_KEY_SIZE;

        --keyCount;
    }
    else
    {
        memset( m_prefixData.m_swPkeyP, 0, ECDSA521_KEY_SIZE );
    }

    if (keyCount > 0) 
    {
        memcpy( m_prefixData.m_swPkeyQ, pRawData, ECDSA521_KEY_SIZE );
        pRawData += ECDSA521_KEY_SIZE;

        --keyCount;
    }
    else
    {
        memset( m_prefixData.m_swPkeyQ, 0, ECDSA521_KEY_SIZE );
    }

    if (keyCount > 0) 
    {
        memcpy( m_prefixData.m_swPkeyR, pRawData, ECDSA521_KEY_SIZE );
        pRawData += ECDSA521_KEY_SIZE;

        --keyCount;
    }
    else
    {
        memset( m_prefixData.m_swPkeyR, 0, ECDSA521_KEY_SIZE );
    }

    // Parse the SoftwareHdr
    m_softwareHdr.m_version = getUint16( pRawData );
    pRawData += 2;

    m_softwareHdr.m_hashAlg = *pRawData++;
    m_softwareHdr.m_unused  = *pRawData++;

    m_softwareHdr.m_codeStartOffset = getUint64( pRawData );
    pRawData += 8;

    memcpy( m_softwareHdr.m_reserved, pRawData, 8 );
    pRawData += 8;

    m_softwareHdr.m_flags = getUint32( pRawData );
    pRawData += 4;

    m_softwareHdr.m_reserved0  = *pRawData++;

    m_softwareHdr.m_payloadSize = getUint64( pRawData );
    pRawData += 8;

    memcpy( m_softwareHdr.m_payloadHash, pRawData, SHA512_DIGEST_SIZE );
    pRawData += SHA512_DIGEST_SIZE;

    m_softwareHdr.m_ecidCount = *pRawData++;

    for (int i = 0; i < m_softwareHdr.m_ecidCount; i++)
    {
        memcpy( (void *) &m_softwareHdr.m_ecid[i*ECID_SIZE], pRawData, ECID_SIZE );
        pRawData += ECID_SIZE;
    } 

    // Parse the SoftwareSig
    keyCount = m_prefixHdr.m_swKeyCount;

    if (keyCount > 0)
    {
        memcpy( m_softwareSig.m_swSigP, pRawData, ECDSA521_SIG_SIZE );
        pRawData += ECDSA521_SIG_SIZE;

        --keyCount;
    }
    else
    {
        memset( m_softwareSig.m_swSigP, 0, ECDSA521_SIG_SIZE );
    }

    if (keyCount > 0)
    {
        memcpy( m_softwareSig.m_swSigQ, pRawData, ECDSA521_SIG_SIZE );
        pRawData += ECDSA521_SIG_SIZE;

        --keyCount;
    }
    else
    {
        memset( m_softwareSig.m_swSigQ, 0, ECDSA521_SIG_SIZE );
    }

    if (keyCount > 0)
    {
        memcpy( m_softwareSig.m_swSigR, pRawData, ECDSA521_SIG_SIZE );
        pRawData += ECDSA521_SIG_SIZE;

        --keyCount;
    }
    else
    {
        memset( m_softwareSig.m_swSigR, 0, ECDSA521_SIG_SIZE );
    }
}
