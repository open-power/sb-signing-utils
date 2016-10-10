/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/signtool/IBM_Utils.cpp $                                  */
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

#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "IBM_Exception.h"
#include "IBM_Utils.h"


IBM_Utils::IBM_Utils()
{
}


IBM_Utils::~IBM_Utils()
{
}

    
IBM_Utils* IBM_Utils::get()
{
    static IBM_Utils utils;
    return &utils;
}
    

void IBM_Utils::ReadFromFile( const std::string& p_fileName,
                              std::vector<byte>& p_buffer )
{
    std::ifstream ifs( p_fileName, std::ifstream::binary );
    if (!ifs.is_open() )
    {
        std::stringstream ss;
        ss << "!-> Failed to open file: " << p_fileName << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    // get length of file
    ifs.seekg( 0, std::ios_base::end );
    std::streampos fileSize = ifs.tellg();

    p_buffer.clear();
    p_buffer.resize(fileSize);

    ifs.seekg( 0, std::ios_base::beg );
    ifs.read( (char *) &p_buffer[0], fileSize );

    ifs.close();
}


void IBM_Utils::ReadFromFile( const std::string& p_fileName,
                              std::vector<byte>& p_buffer,
                              int                p_readSize )
{
    std::ifstream ifs( p_fileName, std::ifstream::binary );
    if (!ifs.is_open() )
    {
        std::stringstream ss;
        ss << "!-> Failed to open file: " << p_fileName << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    // get length of file
    ifs.seekg( 0, std::ios_base::end );
    std::streampos fileSize = ifs.tellg();
    
    if (fileSize < p_readSize)
    {
        std::stringstream ss;
        ss << "!-> Specified container file <"
           << p_fileName
           << "> has invalid size of <"
           << fileSize
           << "> bytes, must be atleast "
           << p_readSize 
           << " bytes"
           << std::endl;
    
        THROW_EXCEPTION_STR(ss.str().c_str());
    }
    
    p_buffer.clear();
    p_buffer.resize(p_readSize);
    
    ifs.seekg( 0, std::ios_base::beg );
    ifs.read( (char *) &p_buffer[0], p_readSize );
    
    ifs.close();
}


bool IBM_Utils::WriteToFile( const std::string& p_fileName,
                             std::vector<byte>& p_buffer )
{
    std::ofstream outfile( p_fileName, std::ios_base::binary );

    if (outfile.fail())
    {
        return false;
    }

    //  Write the data to disk.
    outfile.write( (const char *) p_buffer.data(), p_buffer.size() );

    outfile.close();

    return true;
}


void IBM_Utils::GetPublicKeyBytes( const std::string& p_fileName,
                                   std::vector<byte>& p_buffer )
{
    FILE *fp = fopen( p_fileName.c_str(), "r" );
    if (fp == NULL)
    {
        std::stringstream ss;
        ss << "Failed to open private key file <"
           << p_fileName
           << ">"
           << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    EVP_PKEY*  pkey    = NULL;

    try
    {
        pkey = PEM_read_PUBKEY( fp, NULL, NULL, NULL );
        if (pkey == NULL)
        {
            std::stringstream ss;
            ss << "Failed to read public key from file <"
               << p_fileName
               << ">"
               << std::endl;

            THROW_EXCEPTION_STR(ss.str().c_str());
        }

        EC_KEY *key = EVP_PKEY_get1_EC_KEY(pkey);
        THROW_EXCEPTION(key == NULL);

        const EC_GROUP *ecgrp = EC_KEY_get0_group(key);
        THROW_EXCEPTION(ecgrp == NULL);

        const EC_POINT *ecpoint = EC_KEY_get0_public_key(key);
        THROW_EXCEPTION(ecpoint == NULL);

        char* pubkey = EC_POINT_point2hex( ecgrp,
                                           ecpoint,
                                           POINT_CONVERSION_UNCOMPRESSED,
                                           NULL );

        IBM_HexString pubKeyHexString(pubkey);

        IBM_HexBytes dgstBytes = pubKeyHexString.getBinary();

        // remove the first byte
        dgstBytes.erase( dgstBytes.begin() );

        p_buffer.clear();
        std::copy( dgstBytes.begin(), dgstBytes.end(), std::back_inserter(p_buffer) );
    
        EC_KEY_free(key);
        EVP_PKEY_free(pkey);
        OPENSSL_free(pubkey);
        fclose(fp);
    }
    catch ( IBM_Exception& e )
    {
        if (pkey)
        {
            EVP_PKEY_free(pkey);
        }

        if (fp)
        {
            fclose( fp );
        }

        // rethrow exception
        throw;
    }

    return;
}


void IBM_Utils::GetSignatureBytes( const std::string& p_fileName,
                                   std::vector<byte>& p_buffer )
{
    std::vector<uint8_t> sigBytes;

    this->ReadFromFile( p_fileName.c_str(), sigBytes );

    const uint8_t* p_sigBytes = &sigBytes[0];

    // convert the read data to a signature object
    ECDSA_SIG* signature = d2i_ECDSA_SIG( NULL, &p_sigBytes, sigBytes.size() );

    byte sBuf[ECDSA521_SIG_SIZE];
    memset( &sBuf, 0, sizeof(sBuf) );

    int rLen = BN_num_bytes(signature->r);
    int rOff = (rLen == 66) ? 0 : 1;

    BN_bn2bin(signature->r, &sBuf[rOff]);

    int sLen = BN_num_bytes(signature->s);
    int sOff = (sLen == 66) ? 66 : 67;

    BN_bn2bin(signature->s, &sBuf[sOff]);

    p_buffer.clear();
    p_buffer.resize(ECDSA521_SIG_SIZE);
    memcpy( &p_buffer[0], sBuf, ECDSA521_SIG_SIZE );

    return;
}


uint16_t IBM_Utils::getUint16( const uint8_t *data )
{
    uint16_t value = 0;

    value = data[1] | (data[0] << 8);

    return value;
}

uint32_t IBM_Utils::getUint32( const uint8_t *data )
{
    uint32_t value = 0;

    value = (data[3] | (data[2] << 8) | (data[1] << 16) | (data[0] << 24));

    return value;
}

uint64_t IBM_Utils::getUint64( const uint8_t *data )
{
    uint64_t value = 0;

    value = (            data[7]        | ((uint16_t)data[6] << 8)  |
              ((uint32_t)data[5] << 16) | ((uint32_t)data[4] << 24) |
              ((uint64_t)data[3] << 32) | ((uint64_t)data[2] << 40) |
              ((uint64_t)data[1] << 48) | ((uint64_t)data[0] << 56) );

    return value;
}
