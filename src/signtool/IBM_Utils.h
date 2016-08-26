/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/signtool/IBM_Utils.h $                                    */
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

#ifndef __IBM_UTILS_H_
#define __IBM_UTILS_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "IBM_HexString.h"

#define CONTAINER_VERSION   1
#define HEADER_VERSION      1
#define HASH_ALG_SHA512     1
#define SIG_ALG_ECDSA521    1

#define HBI_BASE_SIGNING_KEY 0x80000000

#define ROM_MAGIC_NUMBER     0x17082011

#define SHA512_DIGEST_SIZE   64
#define ECDSA521_KEY_SIZE   132
#define ECDSA521_SIG_SIZE   132
#define ECID_SIZE            16

enum IBM_HashAlgo
{
    e_SHA1_ALGO,
    e_SHA256_ALGO,
    e_SHA384_ALGO,
    e_SHA512_ALGO
};


class IBM_Utils
{
public:
    static const std::string g_MODE_PRODUCTION;
    static const std::string g_MODE_DEVELOPMENT;
 
    ~IBM_Utils(); 
    
    static IBM_Utils* get(); 
    
    void ReadFromFile( const char*        p_fileName,
                       std::vector<byte>& p_buffer );

    void ReadFromFile( const char*        p_fileName,
                       std::vector<byte>& p_buffer,
                       int                p_readSize );

    bool WriteToFile( const char*        p_fileName,
                      std::vector<byte>& p_buffer );

    void GetPublicKeyBytes( const char*        p_fileName,
                            std::vector<byte>& p_buffer );

    void GetSignatureBytes( const char*        p_fileName,
                            std::vector<byte>& p_buffer );

private:
    IBM_Utils();                                //!< disallow 
    IBM_Utils( IBM_Utils& );                    //!< disallow
    IBM_Utils& operator = ( const IBM_Utils& ); //!< disallow
}; 

#endif //  __IBM_UTILS_H_
