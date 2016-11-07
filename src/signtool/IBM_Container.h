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


/*
   The following paragraph describess the OpenPower container layout, it consists of 5 parts

      * Contaner Header
      * Prefix Header
      * Prefix Data
      * Software Header
      * Software Signature

   The total length of the container is 4k including padding bytes appended to the end after the
   softwre signature. The container supports 3 Hardware keys and signature and for upto 3 software
   keys and signature. Details about each header is described below.

        |-----------------------------------------------------| 0x00000000
        |                                                     |
        |      Container Header (0x1AA or 426 bytes)          |
        |                                                     |
        |---------------------------|                         |
        |                           |-------------------------| 0x000001AC   
        |             Prefix Header (0x62 or 98 bytes)        |
        |-----------------------------------------------------| 0x0000020C                           
        |                                                     |            
        |            Prefix Data (0x318 or 792 bytes)         |
        |                                                     |
        |-----------------------------------------------------| 0x00000524
        |        Software Header (0x62 or 98 bytes)           |
        |---------------------------|                         |
        |                           |-------------------------| 0x00000588
        |                                                     |
        |       Software Signature (0x18C or 396 bytes)       |
        |                                                     |
        |-----------------------------------------------------| 0x00000712
        |                                                     |
        |                                                     |
        |          padding (0x8EE or 2286 bytes)              |
        |                                                     |
        |                                                     |
        |-----------------------------------------------------| 0x00000FFC
*/


struct ContainerHdr
{
    /*
        |-----------------------------------------------------| 0x00000000
        |            Magic Number (0x17082011)                |
        |---------------------------|-------------------------| 0x00000004
        |                           |     Version             |
        |                           |-------------------------| 0x00000008
        |              Container Size (8 Bytes)               |
        |---------------------------|                         | 
        |                           |-------------------------| 0x00000010
        |                Target HRMOR (8 Bytes)               |
        |---------------------------|                         | 
        |                           |-------------------------| 0x00000018                    
        |                Stack Pointer (8 Bytes)              |
        |---------------------------|                         | 
        |                           |-------------------------| 0x00000020
        |                                                     |
        |            Hardware Public Key-A (132 bytes)        |
        |                                                     |
        |---------------------------|                         | 
        |                           |-------------------------| 0x000000A4
        |                                                     |
        |            Hardware Public Key-B (132 bytes)        |
        |                                                     |
        |---------------------------|                         | 
        |                           |-------------------------| 0x00000128
        |                                                     |
        |            Hardware Public Key-B (132 bytes)        |
        |                                                     |
        |---------------------------|                         | 
                                    |-------------------------| 0x000001AB
    */

    uint32_t  m_magicNumber                = ROM_MAGIC_NUMBER;
    uint16_t  m_version                    = CONTAINER_VERSION;
    uint64_t  m_containerSize              = 0;
    uint64_t  m_targetHrmor                = 0;
    uint64_t  m_stackPointer               = 0;
    uint8_t   m_hwPkeyA[ECDSA521_KEY_SIZE] = {0};
    uint8_t   m_hwPkeyB[ECDSA521_KEY_SIZE] = {0};
    uint8_t   m_hwPkeyC[ECDSA521_KEY_SIZE] = {0};

    ContainerHdr() = default;

    void PrintHeader() const;
    void GetHeaderBytes( std::vector<uint8_t>& packet ) const;

}  __attribute__ ((packed));



struct PrefixHdr
{
    /*
        |---------------------------|                         | 0x000001A8
        |      Version              |                         |   
        |---------------------------|------------|------------| 0x000001AC                         
        |                           | Sign Algo  | Hash Algo  |            
        |                           |------------|------------| 0x000001B0
        |                 Code Offset Start (8 bytes)         |
        |---------------------------|                         |
        |                           |-------------------------| 0x000001B8
        |                  Reserved (8 bytes)                 |
        |---------------------------|                         |
        |         flags             |                         |
        |-------------|-------------|-------------------------| 0x000001C0
        |             |SW Key Count |       flags             | 
        |             |-------------|-------------------------| 0x000001C4
        |                                                     |
        |               Payload Size (8 bytes)                |
        |-------------|                                       |
        |             |---------------------------------------| 0x000001CC
        |                                                     |
        |              Payload Hash (64 bytes)                |
        |                                                     |
        |-------------|                                       |
        |ECID count=0 |                                       |
        |-------------|---------------------------------------| 0x00000208
    */

    uint16_t  m_version                         = HEADER_VERSION;
    uint8_t   m_hashAlg                         = HASH_ALG_SHA512;
    uint8_t   m_sigAlg                          = SIG_ALG_ECDSA521;
    uint64_t  m_codeStartOffset                 = 0;
    uint8_t   m_reserved[8]                     = {0};
    uint32_t  m_flags                           = 0;
    uint8_t   m_swKeyCount                      = 0;
    uint64_t  m_payloadSize                     = 0 ;
    uint8_t   m_payloadHash[SHA512_DIGEST_SIZE] = {0};
    uint8_t   m_ecidCount                       = 0;
    uint8_t   m_ecid[ECID_SIZE]                 = {0};
                                        
    PrefixHdr() = default;
                                                 
    void PrintHeader() const;
    void GetHeaderBytes( std::vector<uint8_t>& packet ) const;

} __attribute__ ((packed));



struct PrefixData
{
    /*
        |-----------------------------------------------------| 0x0000020C
        |                                                     |
        |           HW Signature-A (132 bytes)                |
        |                                                     |
        |-----------------------------------------------------| 0x00000290
        |                                                     |
        |           HW Signature-B (132 bytes)                |
        |                                                     |
        |-----------------------------------------------------| 0x00000314
        |                                                     |
        |           HW Signature-C (132 bytes)                |
        |                                                     |
        |-----------------------------------------------------| 0x00000398
        |                                                     |
        |           SW Public Key-P (132 bytes)               |
        |                                                     |
        |-----------------------------------------------------| 0x0000041C
        |                                                     |
        |           SW Public Key-Q (132 bytes) (Optional)    |
        |                                                     | 
        |-----------------------------------------------------| 0x000004A0
        |                                                     |
        |           SW Public Key-R (132 bytes) (Optional)    |
        |                                                     |
        |-----------------------------------------------------|
    */

    uint8_t   m_hwSigA[ECDSA521_SIG_SIZE]  = {0};
    uint8_t   m_hwSigB[ECDSA521_SIG_SIZE]  = {0};
    uint8_t   m_hwSigC[ECDSA521_SIG_SIZE]  = {0};
    uint8_t   m_swPkeyP[ECDSA521_KEY_SIZE] = {0};
    uint8_t   m_swPkeyQ[ECDSA521_KEY_SIZE] = {0};
    uint8_t   m_swPkeyR[ECDSA521_KEY_SIZE] = {0};

    PrefixData() = default;

    void PrintHeader() const;
    int  GetSwKeyCount() const;
    void GetHeaderBytes( std::vector<uint8_t>& packet ) const;

} __attribute__ ((packed));



struct SoftwareHdr
{
    /*
        |-------------|-------------|-------------------------| 0x00000524
        |   reserved  |  Hash Algo  |        Version          |   
        |-------------|-------------|-------------------------| 0x00000528                         
        |                 Code Offset Start (8 bytes)         |
        |                                                     |
        |-----------------------------------------------------| 0x00000530
        |                  Reserved (8 bytes)                 |
        |                                                     |
        |-----------------------------------------------------| 0x00000538
        |                      flags (4 bytes)                | 
        |----------------------------------------|------------| 0x0000053C
        |                                        |  reserved  |
        |               Payload Size (8 bytes)   |------------| 0x00000540
        |                                                     |
        |----------------------------------------|            |
        |                                        |------------| 0x00000548
        |                                                     |
        |              Payload Hash (64 bytes)                |
        |                                                     |
        |---------------------------|------------|            |
                                    |ECID count=0|            |
                                    |------------|------------| 0x00000584
    */

    uint16_t  m_version                         = HEADER_VERSION;
    uint8_t   m_hashAlg                         = HASH_ALG_SHA512;
    uint8_t   m_unused                          = 0;
    uint64_t  m_codeStartOffset                 = 0;
    uint8_t   m_reserved[8]                     = {0};
    uint32_t  m_flags                           = 0;
    uint8_t   m_reserved0                       = 0;
    uint64_t  m_payloadSize                     = 0;
    uint8_t   m_payloadHash[SHA512_DIGEST_SIZE] = {0};
    uint8_t   m_ecidCount                       = 0;
    uint8_t   m_ecid[ECID_SIZE]                 = {0};
                                                
    SoftwareHdr() = default;
                                             
    void PrintHeader() const;
    void GetHeaderBytes( std::vector<uint8_t>& packet ) const;

} __attribute__ ((packed));



struct SoftwareSig
{
    /*
        |---------------------------|                           0x00000584
        |                           |-------------------------| 0x00000588
        |                                                     |
        |           SW Signature-P (132 bytes)                |
        |                                                     |
        |---------------------------|                         |
        |                           |-------------------------| 0x0000060C
        |                                                     |
        |           SW Signature-Q (132 bytes) (Optional)     |
        |                                                     |
        |---------------------------|                         |
        |                           |-------------------------| 0x00000690
        |                                                     |
        |           SW Signature-R (132 bytes) (Optional)     |
        |                                                     |
        |---------------------------|                         |
                                    |-------------------------| 0x00000710
    */

    uint8_t   m_swSigP[ECDSA521_SIG_SIZE] = {0};
    uint8_t   m_swSigQ[ECDSA521_SIG_SIZE] = {0};
    uint8_t   m_swSigR[ECDSA521_SIG_SIZE] = {0};

    SoftwareSig() = default;
                                             
    void PrintHeader() const;
    void GetHeaderBytes( std::vector<uint8_t>& packet ) const;

} __attribute__ ((packed));




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
    IBM_Container( IBM_Mode p_mode );

    // Given a filename, read its contents, parse the data and constuct the container
    IBM_Container( IBM_Mode    p_mode,
                   std::string p_containerFileName );

    // Given a stream of bytes, parse the data and constuct the container
    IBM_Container( uint8_t *p_rawData );

    // Disallow Move Constructor, Copy Constructor and  Assignment Operator
    IBM_Container( IBM_Container& ) = delete; 
    IBM_Container( IBM_Container&& ) = delete;
    IBM_Container operator = ( IBM_Container& ) = delete;
    
    ~IBM_Container();

    int  Validate();

    void Print() const;

    bool Save( const std::string p_fileName ); 

    bool UpdateField( const std::string p_fldName, const std::string p_value ); 

    void GetFieldNameList( std::vector<std::string>& p_fldNameList );

    bool ComputeHash( std::string  p_hashHdrType,
                      std::string  p_hashAlgo,
                      std::string& p_digestStr );

private:
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

    IBM_Mode     m_mode;

    typedef std::map<std::string, IBM_ContainerFld> ContainerFldMap;
    typedef std::map<std::string, IBM_HdrFldType>   HdrFldTypeMap;
    typedef std::map<std::string, IBM_HashAlgo>     HashAlgoMap;

    ContainerFldMap  m_contFldMap;
    HashAlgoMap      m_hashAlgoMap;
    HdrFldTypeMap    m_hdrFldTypeMap;
};

#endif // __IBM_CONTAINER_H_
