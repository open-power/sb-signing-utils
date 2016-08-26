/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/signtool/IBM_Container.h $                                */
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

#ifndef __IBM_CONTAINER_H_
#define __IBM_CONTAINER_H_

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "IBM_Utils.h"

struct ContainerHdr
{
    uint32_t  m_magicNumber;                    // (17082011)
    uint16_t  m_version;                        // (1: see versions above)
    uint64_t  m_containerSize;                  // filled by caller
    uint64_t  m_targetHrmor;                    // filled by caller
    uint64_t  m_stackPointer;                   // filled by caller
    uint8_t   m_hwPkeyA[ECDSA521_KEY_SIZE];
    uint8_t   m_hwPkeyB[ECDSA521_KEY_SIZE];
    uint8_t   m_hwPkeyC[ECDSA521_KEY_SIZE];

    ContainerHdr();

    void PrintHeader();
    void GetHeaderBytes( std::vector<uint8_t>& packet );

}  __attribute__ ((packed));


struct PrefixHdr
{
    uint16_t  m_version;                         // (1: see versions above)
    uint8_t   m_hashAlg;                         // (1: SHA-512)
    uint8_t   m_sigAlg;                          // (1: SHA-512/ECDSA-521)
    uint64_t  m_codeStartOffset;
    uint8_t   m_reserved[8];
    uint32_t  m_flags;
    uint8_t   m_swKeyCount;
    uint64_t  m_payloadSize;
    uint8_t   m_payloadHash[SHA512_DIGEST_SIZE];
    uint8_t   m_ecidCount;
    uint8_t   m_ecid[ECID_SIZE];                 // optional ecid place 
                                                 // holder ecid_count * szeof(ecids)
    PrefixHdr();
                                                 
    void PrintHeader();
    void GetHeaderBytes( std::vector<uint8_t>& packet );

} __attribute__ ((packed));


struct PrefixData
{
    uint8_t   m_hwSigA[ECDSA521_SIG_SIZE];
    uint8_t   m_hwSigB[ECDSA521_SIG_SIZE];
    uint8_t   m_hwSigC[ECDSA521_SIG_SIZE];
    uint8_t   m_swPkeyP[ECDSA521_KEY_SIZE];
    uint8_t   m_swPkeyQ[ECDSA521_KEY_SIZE];
    uint8_t   m_swPkeyR[ECDSA521_KEY_SIZE];

    PrefixData();

    void PrintHeader();
    int  GetSwKeyCount();
    void GetHeaderBytes( std::vector<uint8_t>& packet );

} __attribute__ ((packed));


struct SoftwareHdr
{
    uint16_t  m_version;                         // (1: see versions above)
    uint8_t   m_hashAlg;                         // (1: SHA-512)
    uint8_t   m_unused;
    uint64_t  m_codeStartOffset;
    uint8_t   m_reserved[8];
    uint32_t  m_flags;
    uint8_t   m_reserved0;
    uint64_t  m_payloadSize;
    uint8_t   m_payloadHash[SHA512_DIGEST_SIZE];
    uint8_t   m_ecidCount;
    uint8_t   m_ecid[ECID_SIZE];                 // optional ecid place 
                                                 // holder ecid_count * szeof(ecids)
    SoftwareHdr();
                                             
    void PrintHeader();
    void GetHeaderBytes( std::vector<uint8_t>& packet );

} __attribute__ ((packed));


struct SoftwareSig
{
    uint8_t   m_swSigP[ECDSA521_SIG_SIZE];
    uint8_t   m_swSigQ[ECDSA521_SIG_SIZE];
    uint8_t   m_swSigR[ECDSA521_SIG_SIZE];

    SoftwareSig();
                                             
    void PrintHeader();
    void GetHeaderBytes( std::vector<uint8_t>& packet );

} __attribute__ ((packed));




/* The Container Layout consists of the following 5 blocks 
 *   ContainerHdr
 *   PrefixHdr
 *   PrefixData
 *   SoftwareHdr
 *   SoftwareSig
 */
class IBM_Container
{
public:
    enum IBM_HdrFldType
    {
        e_FLD_PREFIX_HDR,
        e_FLD_SOFTWARE_HDR
    };

    enum IBM_ContainerFld
    {
        // these are the fields in Container Header
        e_CONTAINER_VERSION,
        e_CONTAINER_SIZE,
        e_TARGET_HRMOR,
        e_STACK_POINTER,
        e_HW_PUBLIC_KEY_A,
        e_HW_PUBLIC_KEY_B,
        e_HW_PUBLIC_KEY_C,
   
        // these are the fields in Prefix Header
        e_PRE_HDR_VERSION,
        e_PRE_HDR_HASH_ALGORITHM,
        e_PRE_HDR_SIGNING_ALGORITHM,
        e_PRE_HDR_CODE_START_OFFSET,
        e_PRE_HDR_FLAGS,
        e_PRE_HDR_PAYLOAD_SIZE,
        e_PRE_HDR_PAYLOAD_HASH,

        // these are the fields in Prefix Data
        e_HW_SIGNATURE_A,
        e_HW_SIGNATURE_B,
        e_HW_SIGNATURE_C,
        e_SW_PUBLIC_KEY_P,
        e_SW_PUBLIC_KEY_Q,
        e_SW_PUBLIC_KEY_R,

        // these are the fields in Software Header
        e_SW_HDR_VERSION,
        e_SW_HDR_HASH_ALGORITHM,
        e_SW_HDR_CODE_START_OFFSET,
        e_SW_HDR_FLAGS,
        e_SW_HDR_PAYLOAD_SIZE,
        e_SW_HDR_PAYLOAD_HASH,

        // these are the fields in Software Signature
        e_SW_SIGNATURE_P,
        e_SW_SIGNATURE_Q,
        e_SW_SIGNATURE_R
    };

    // default C'tor
    IBM_Container( std::string p_mode );

    // Given a filename, read its contents, parse the data and constuct the container
    IBM_Container( std::string p_mode,
                   std::string p_containerFileName );

    // Given a stream of bytes, parse the data and constuct the container
    IBM_Container( uint8_t *p_rawData );

    ~IBM_Container();

    int  Validate();

    void Print();

    bool Save( const std::string p_fileName ); 

    bool UpdateField( const std::string p_fldName, const std::string p_value ); 

    void GetFieldNameList( std::vector<std::string>& p_fldNameList );

    bool ComputeHash( std::string  p_hashHdrType,
                      std::string  p_hashAlgo,
                      std::string& p_digestStr );

private:
    // Disallow Copy Constructor and Assignment Operator
    IBM_Container( IBM_Container& ); 
    IBM_Container operator = ( IBM_Container& );
    
    void initializeMap();

    void ParseContainer( const std::vector<uint8_t>& p_rawData );

    /* The Container Layout consists of the following 5 blocks 
     *   ContainerHdr
     *   PrefixHdr
     *   PrefixData
     *   SoftwareHdr
     *   SoftwareSig
     */
    ContainerHdr m_containerHdr;
    PrefixHdr    m_prefixHdr;
    PrefixData   m_prefixData;
    SoftwareHdr  m_softwareHdr;
    SoftwareSig  m_softwareSig;

    std::string  m_mode;

    typedef std::map<std::string, IBM_ContainerFld> ContainerFldMap;

    typedef std::map<std::string, IBM_HdrFldType> HdrFldTypeMap;
    typedef std::map<std::string, IBM_HashAlgo>   HashAlgoMap;

    HashAlgoMap      m_hashAlgoMap;
    HdrFldTypeMap    m_hdrFldTypeMap;

    ContainerFldMap  m_contFldMap;
};

#endif // __IBM_CONTAINER_H_
