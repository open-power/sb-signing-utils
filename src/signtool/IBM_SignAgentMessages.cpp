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

#include <cstring>

#include "IBM_Utils.h"
#include "IBM_Exception.h"

#include "IBM_SignAgentMessages.h"

SignMessageReq::SignMessageReq( const std::vector<uint8_t>& p_rawData )
{
    const uint8_t* pRawData = &p_rawData[0];
    THROW_EXCEPTION( pRawData == NULL );

    size_t dataSize = p_rawData.size();

    size_t projNameSize  = sizeof(m_projectName);
    size_t dgstBytesSize = sizeof(m_digestBytes);
    
    THROW_EXCEPTION(dataSize < (projNameSize + dgstBytesSize));

    memcpy( m_projectName, pRawData, projNameSize );
    memcpy( m_digestBytes, pRawData+projNameSize, dgstBytesSize );
}



void SignMessageReq::GetMessageBytes( std::vector<uint8_t>& p_rawData )
{
    p_rawData.clear();

    p_rawData.insert( p_rawData.end(), ((e_SIGN_MESSAGE_REQ >> 24) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((e_SIGN_MESSAGE_REQ >> 16) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((e_SIGN_MESSAGE_REQ >> 8) & 0xff) );
    p_rawData.insert( p_rawData.end(), (e_SIGN_MESSAGE_REQ & 0xff) );

    p_rawData.insert( p_rawData.end(),
                      m_projectName,
                      m_projectName+sizeof(m_projectName) );

    p_rawData.insert( p_rawData.end(),
                      m_digestBytes,
                      m_digestBytes+sizeof(m_digestBytes) );
}
 

SignMessageRsp::SignMessageRsp( const std::vector<uint8_t>& p_rawData )
{
    const uint8_t* pRawData = &p_rawData[0];
    THROW_EXCEPTION( pRawData == NULL );

    IBM_Utils* pUtils = IBM_Utils::get();
    THROW_EXCEPTION( pUtils == NULL );

    size_t dataSize = p_rawData.size();

    size_t statusSize    = sizeof(m_status);
    size_t errorMsgSize  = sizeof(m_errorMsg);
    size_t signBytesSize = sizeof(m_signBytes);
    
    THROW_EXCEPTION(dataSize < (statusSize + errorMsgSize + signBytesSize));

    m_status = pUtils->getUint32(pRawData);
    pRawData += 4;
    memcpy( m_errorMsg, pRawData, errorMsgSize );
    pRawData += errorMsgSize;
    memcpy( m_signBytes, pRawData, signBytesSize );
}


void SignMessageRsp::GetMessageBytes( std::vector<uint8_t>& p_rawData )
{
    p_rawData.clear();

    p_rawData.insert( p_rawData.end(), ((e_SIGN_MESSAGE_RSP >> 24) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((e_SIGN_MESSAGE_RSP >> 16) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((e_SIGN_MESSAGE_RSP >> 8) & 0xff) );
    p_rawData.insert( p_rawData.end(), (e_SIGN_MESSAGE_RSP & 0xff) );

    p_rawData.insert( p_rawData.end(), ((m_status >> 24) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((m_status >> 16) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((m_status >> 8) & 0xff) );
    p_rawData.insert( p_rawData.end(), (m_status & 0xff) );

    p_rawData.insert( p_rawData.end(),
                      m_errorMsg, 
                      m_errorMsg+sizeof(m_errorMsg) );

    p_rawData.insert( p_rawData.end(),
                      m_signBytes, 
                      m_signBytes+sizeof(m_signBytes) );
}


GetPublicKeyReq::GetPublicKeyReq( const std::vector<uint8_t>& p_rawData )
{
    const uint8_t* pRawData = &p_rawData[0];
    THROW_EXCEPTION( pRawData == NULL );

    size_t dataSize = p_rawData.size();

    size_t projNameSize  = sizeof(m_projectName);
    
    THROW_EXCEPTION(dataSize < projNameSize);

    memcpy( m_projectName, pRawData, projNameSize );
}


void GetPublicKeyReq::GetMessageBytes( std::vector<uint8_t>& p_rawData )
{
    p_rawData.clear();

    p_rawData.insert( p_rawData.end(), ((e_GET_PUBLIC_KEY_REQ >> 24) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((e_GET_PUBLIC_KEY_REQ >> 16) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((e_GET_PUBLIC_KEY_REQ >> 8) & 0xff) );
    p_rawData.insert( p_rawData.end(), (e_GET_PUBLIC_KEY_REQ & 0xff) );

    p_rawData.insert( p_rawData.end(),
                      m_projectName,
                      m_projectName+sizeof(m_projectName) );
}



GetPublicKeyRsp::GetPublicKeyRsp( const std::vector<uint8_t>& p_rawData )
{
    const uint8_t* pRawData = &p_rawData[0];
    THROW_EXCEPTION( pRawData == NULL );

    IBM_Utils* pUtils = IBM_Utils::get();
    THROW_EXCEPTION( pUtils == NULL );

    size_t dataSize = p_rawData.size();

    size_t statusSize    = sizeof(m_status);
    size_t errorMsgSize  = sizeof(m_errorMsg);
    size_t pubKeySize    = sizeof(m_publicKey);
    
    THROW_EXCEPTION(dataSize < (statusSize + errorMsgSize + pubKeySize));

    m_status = pUtils->getUint32(pRawData);
    pRawData += 4;
    memcpy( m_errorMsg, pRawData, errorMsgSize );
    pRawData += errorMsgSize;
    memcpy( m_publicKey, pRawData, pubKeySize );
}


void GetPublicKeyRsp::GetMessageBytes( std::vector<uint8_t>& p_rawData )
{
    p_rawData.clear();

    p_rawData.insert( p_rawData.end(), ((e_GET_PUBLIC_KEY_RSP >> 24) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((e_GET_PUBLIC_KEY_RSP >> 16) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((e_GET_PUBLIC_KEY_RSP >> 8) & 0xff) );
    p_rawData.insert( p_rawData.end(), (e_GET_PUBLIC_KEY_RSP & 0xff) );

    p_rawData.insert( p_rawData.end(), ((m_status >> 24) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((m_status >> 16) & 0xff) );
    p_rawData.insert( p_rawData.end(), ((m_status >> 8) & 0xff) );
    p_rawData.insert( p_rawData.end(), (m_status & 0xff) );

    p_rawData.insert( p_rawData.end(),
                      m_errorMsg, 
                      m_errorMsg+sizeof(m_errorMsg) );

    p_rawData.insert( p_rawData.end(),
                      m_publicKey,
                      m_publicKey+sizeof(m_publicKey) );
}
