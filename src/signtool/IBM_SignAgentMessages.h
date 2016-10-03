/* -------------------------------------------------------------------------
 *
 * Licensed Materials - Property of IBM.
 *
 * (C) Copyright IBM Corporation 2016
 *
 * All Rights Reserved.
 *
 * US Government Users Restricted Rights - Use, duplication or disclosure
 * restricted by GSA ADP Schedule Contract with IBM Corporation.
 *
 *---------------------------------------------------------------------------*/

#ifndef IBM_SIGNAGENT_MESSAGES_H_
#define IBM_SIGNAGENT_MESSAGES_H_

#include <cstdint>
#include <vector>


const uint32_t e_GET_PUBLIC_KEY_REQ = 0x80000000;
const uint32_t e_GET_PUBLIC_KEY_RSP = (e_GET_PUBLIC_KEY_REQ + 1);
const uint32_t e_SIGN_MESSAGE_REQ   = 0x80000002;
const uint32_t e_SIGN_MESSAGE_RSP   = (e_SIGN_MESSAGE_REQ + 1);

const uint32_t e_CMD_RSP_SUCCESS = 0x00000000;
const uint32_t e_CMD_RSP_FAILURE = 0x00000001;

struct SignMessageReq
{
    SignMessageReq() {}
    SignMessageReq( const std::vector<uint8_t>& p_data );

    void GetMessageBytes( std::vector<uint8_t>& p_rawData );

    uint8_t     m_projectName[32];
    uint8_t     m_digestBytes[64]; // sha-512
};
 

struct SignMessageRsp
{
    SignMessageRsp() {}
    SignMessageRsp( const std::vector<uint8_t>& p_data );

    void GetMessageBytes( std::vector<uint8_t>& p_rawData );

    uint32_t    m_status;
    uint8_t     m_errorMsg[256];
    uint8_t     m_signBytes[132];    
};


struct GetPublicKeyReq
{
    GetPublicKeyReq() {}
    GetPublicKeyReq( const std::vector<uint8_t>& p_data );

    void GetMessageBytes( std::vector<uint8_t>& p_rawData );

    uint8_t     m_projectName[32];
};


struct GetPublicKeyRsp
{
    GetPublicKeyRsp() {}
    GetPublicKeyRsp( const std::vector<uint8_t>& p_data );

    void GetMessageBytes( std::vector<uint8_t>& p_rawData );

    uint32_t    m_status;
    uint8_t     m_errorMsg[256];
    uint8_t     m_publicKey[133];
};


#endif //  IBM_SIGNAGENT_MESSAGES_H_
