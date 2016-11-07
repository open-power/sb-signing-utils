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
    uint8_t     m_projectName[32] = {0};
    uint8_t     m_digestBytes[64] = {0}; // sha-512

    SignMessageReq() = default;
    SignMessageReq( const std::vector<uint8_t>& p_data );

    void GetMessageBytes( std::vector<uint8_t>& p_rawData );
};
 

struct SignMessageRsp
{
    uint32_t    m_status = e_CMD_RSP_FAILURE;

    uint8_t     m_errorMsg[256]  = {0};
    uint8_t     m_signBytes[132] = {0};    

    SignMessageRsp() = default;
    SignMessageRsp( const std::vector<uint8_t>& p_data );

    void GetMessageBytes( std::vector<uint8_t>& p_rawData );
};


struct GetPublicKeyReq
{
    uint8_t     m_projectName[32] = {0};

    GetPublicKeyReq() = default;
    GetPublicKeyReq( const std::vector<uint8_t>& p_data );

    void GetMessageBytes( std::vector<uint8_t>& p_rawData );
};


struct GetPublicKeyRsp
{
    uint32_t    m_status = e_CMD_RSP_FAILURE;

    uint8_t     m_errorMsg[256]  = {0};
    uint8_t     m_publicKey[133] = {0};

    GetPublicKeyRsp() = default;
    GetPublicKeyRsp( const std::vector<uint8_t>& p_data );

    void GetMessageBytes( std::vector<uint8_t>& p_rawData );
};


#endif //  IBM_SIGNAGENT_MESSAGES_H_
