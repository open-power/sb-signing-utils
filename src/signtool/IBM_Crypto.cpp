/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/signtool/IBM_Crypto.cpp $                                 */
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

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <algorithm>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "IBM_Socket.h"
#include "IBM_Utils.h"
#include "IBM_HexString.h"
#include "IBM_Exception.h"
#include "IBM_SignAgentMessages.h"

#include "IBM_Crypto.h"


IBM_Crypto::IBM_Crypto( IBM_Mode p_mode )
   : m_mode(p_mode)
{
    switch (m_mode)
    {
        case e_MODE_IBM_PRODUCTION:
        case e_MODE_DEVELOPMENT:
        {
            // supported modes
            break;
        }

        default:
        {
            std::stringstream ss;
            ss << "*** Invalid value for mode" << std::endl
               << "--- Expecting <" << (int) e_MODE_IBM_PRODUCTION 
               << "> or <" << (int) e_MODE_DEVELOPMENT << ">, got <"
               << m_mode << ">" << std::endl;

            THROW_EXCEPTION_STR(ss.str().c_str());
        }
    }

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}


IBM_Crypto::~IBM_Crypto()
{
    ERR_free_strings();
    EVP_cleanup();
}


bool IBM_Crypto::CreateKeyPair( const std::string& p_privKeyFileName,
                                const std::string& p_pubKeyFileName )
{
    int eccgrp = OBJ_txt2nid("secp521r1");

    EC_KEY* key = EC_KEY_new_by_curve_name(eccgrp);
    THROW_EXCEPTION(key == NULL);

    EC_KEY_set_asn1_flag( key, OPENSSL_EC_NAMED_CURVE );

    // Create the public/private EC key pair
    if (!EC_KEY_generate_key(key))
    {
        THROW_EXCEPTION_STR("Error generating the ECC key.\n");
    }
  
    // Converting the EC key into a PKEY structure let's
    // us handle the key just like any other key pair.
    EVP_PKEY* pkey = EVP_PKEY_new();
    THROW_EXCEPTION(pkey == NULL);

    if (!EVP_PKEY_assign_EC_KEY( pkey, key ))
    {
        THROW_EXCEPTION_STR("Error assigning ECC key to EVP_PKEY structure.\n");
    }

    // write the private key data in PEM format
    FILE* privFp = fopen( p_privKeyFileName.c_str(), "w" );
    if (privFp == NULL)
    {
        std::stringstream ss;
        ss << "Failed to open private key file <" 
           << p_privKeyFileName
           << ">"
           << std::endl;
        
        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    BIO* privKeyOut = BIO_new(BIO_s_file());
    THROW_EXCEPTION(privKeyOut == NULL);

    BIO_set_fp( privKeyOut, privFp, BIO_NOCLOSE );

    if (!PEM_write_bio_PrivateKey( privKeyOut, pkey, NULL, NULL, 0, 0, NULL ))
    {
        THROW_EXCEPTION_STR("Error writing private key data in PEM format.\n");
    }
    BIO_free(privKeyOut);

    // write the public key data in PEM format
    FILE* pubFp = fopen( p_pubKeyFileName.c_str(), "w" );
    if (pubFp == NULL)
    {
        std::stringstream ss;
        ss << "Failed to open public key file <" 
           << p_pubKeyFileName
           << ">"
           << std::endl;
        
        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    BIO* pubKeyOut = BIO_new(BIO_s_file());
    THROW_EXCEPTION(privKeyOut == NULL);

    BIO_set_fp( pubKeyOut, pubFp, BIO_NOCLOSE );

    if(!PEM_write_bio_PUBKEY( pubKeyOut, pkey))
    {
        THROW_EXCEPTION_STR("Error writing public key data in PEM format.\n");
    }
    BIO_free(pubKeyOut);

    EVP_PKEY_free(pkey);
    EC_KEY_free(key);

    return true;
}


bool IBM_Crypto::Sign( const std::string& p_pKeyName,
                       const std::string& p_digest,
                       const std::string& p_signFileName,
                       const std::string& p_saHostName,
                       uint16_t           p_saPortNum )
{
    //  Make sure the signature is in upper case.
    std::string digest = p_digest;

    std::transform( digest.begin(), digest.end(), digest.begin(), ::toupper );

    // convert the digest string to hex byte array
    IBM_HexString hexString(digest);

    IBM_HexBytes dgstBytes = hexString.getBinary();

    // supports only sha-256, sha-384 and sha-512 signatures
    switch (dgstBytes.size())
    {
        case 32:     // sha-256
        case 48:     // sha-384
        case 64:     // sha-512
        {
            break;
        }

        default:
        {
            std::stringstream ss;
            ss << "*** Invalid digest string size" << std::endl
               << "--- Expected sha-256(32), sha-384(48), or sha-512(64)"
               << " bytes, got : " << dgstBytes.size() << std::endl;

            THROW_EXCEPTION_STR(ss.str().c_str());
        }
    }

    // structure to receive signature bytes
    IBM_HexBytes signBytes;

    int rv = -1;

    switch (m_mode)
    {
        case e_MODE_DEVELOPMENT:
        {
            rv = doOpensslSign( p_pKeyName, dgstBytes, signBytes );
            break;
        }

        case e_MODE_IBM_PRODUCTION:
        {
            rv = doCcaSign( p_pKeyName, dgstBytes, signBytes, p_saHostName, p_saPortNum );
            break;
        }
    }

    std::cout << "signature :" << IBM_HexString(signBytes) << std::endl;

    IBM_Utils* pUtils = IBM_Utils::get();
    THROW_EXCEPTION(pUtils == NULL);

    pUtils->WriteToFile( p_signFileName.c_str(), signBytes );

    return true;
}


int IBM_Crypto::Verify( const std::string& p_pubKeyFileName,
                        const std::string& p_digest,
                        const std::string& p_signFileName )
{
    int rv = -1;

    // convert the digest string to hex byte array
    IBM_HexString hexString(p_digest);

    IBM_HexBytes dgstBytes = hexString.getBinary();

    // supports only sha-256, sha-384 and sha-512 signatures
    switch (dgstBytes.size())
    {
        case 32:      // Sha-256
        case 48:      // Sha-384
        case 64:      // Sha-512
        {
            break;
        }

        default:
        {
            std::stringstream ss;
            ss << "*** Invalid digest string size" << std::endl
               << "--- Expected sha-256(32), sha-384(48), or sha-512(64)"
               << " bytes, got : " << dgstBytes.size() << std::endl;

            THROW_EXCEPTION_STR(ss.str().c_str());
        }
    }

    switch (m_mode)
    {
        case e_MODE_IBM_PRODUCTION:
        {
            rv = doOpensslVerify( p_pubKeyFileName, dgstBytes, p_signFileName );
            break;
        }

        case e_MODE_DEVELOPMENT:
        {
            rv = doCcaVerify( p_pubKeyFileName, dgstBytes, p_signFileName );
            break;
        }
    }

    return rv;
}


bool IBM_Crypto::ComputeHash( IBM_HashAlgo         p_hashAlgo,
                              const unsigned char* p_data,
                              size_t               p_dataLen,
                              std::string&         p_digestStr )
{
    IBM_HexBytes dgstBytes;

    switch (p_hashAlgo)
    {
        case e_SHA1_ALGO:
        {
            dgstBytes.resize(SHA_DIGEST_LENGTH);

            SHA1( p_data, p_dataLen, (unsigned char *) &dgstBytes[0] );
            break;
        }

        case e_SHA256_ALGO:
        {
            dgstBytes.resize(SHA256_DIGEST_LENGTH);

            SHA256( p_data, p_dataLen, (unsigned char *) &dgstBytes[0] );
            break;
        }

        case e_SHA384_ALGO:
        {
            dgstBytes.resize(SHA384_DIGEST_LENGTH);

            SHA384( p_data, p_dataLen, (unsigned char *) &dgstBytes[0] );
            break;
        }
        case e_SHA512_ALGO:
        {
            dgstBytes.resize(SHA512_DIGEST_LENGTH);

            SHA512( p_data, p_dataLen, (unsigned char *) &dgstBytes[0] );
            break;
        }
    }

    p_digestStr = IBM_HexString(dgstBytes).getAscii();

    return true;
}


int IBM_Crypto::doCcaSign( const std::string&  p_pKeyName,
                           const IBM_HexBytes& p_dgstBytes,
                           IBM_HexBytes&       p_signBytes,
                           const std::string&  p_serverHost,
                           uint16_t            p_serverPort )
{
    struct sockaddr_in server_addr;

    /* fill in sign agent packet */
    SignMessageReq reqPkt;

    if (p_pKeyName.length() >= sizeof(reqPkt.m_projectName))
    {
        std::stringstream ss;
        ss << "*** Length of keyname is too long for use with CCA" << std::endl
           << "--- Passed in keyname length is " << p_pKeyName.length() 
           << " bytes, must be <= 32 bytes." << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    memcpy( reqPkt.m_projectName, p_pKeyName.c_str(), p_pKeyName.length() );
    memcpy( reqPkt.m_digestBytes, &p_dgstBytes[0], p_dgstBytes.size() );

    std::vector<uint8_t> rawReqData;
    reqPkt.GetMessageBytes( rawReqData );

    std::cout << "CCA sign: key:" << p_pKeyName << " data:" << IBM_HexString(p_dgstBytes) << std::endl;

    /* create a socket and connect to the signer */
    IBM_Socket clientSocket;

    std::cout << "Connecting to address " << p_serverHost << " port " << p_serverPort << std::endl;

    if (!clientSocket.Initialize(IBM_Socket::TCP_CLIENT))
    {
        throw IBM_Exception("Failed to Initialize TCP Client socket");
    }
    
    if (!clientSocket.Connect(p_serverHost.c_str(), p_serverPort))
    {
        std::stringstream ss;
        ss << "*** Unable to connect to sign_agent" << std::endl
           << "--- Socket connect to " << p_serverHost << "@" << p_serverPort
           << " failed." << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }
    clientSocket.SetLinger(true, 1);

    uint32_t msgLen = rawReqData.size();
    if (!clientSocket.WriteInt(msgLen))
    {
        THROW_EXCEPTION_STR("Unable to send data to sign_agent.\n");
    }

    if (!clientSocket.Write((const char*) &rawReqData[0], rawReqData.size()))
    {
        THROW_EXCEPTION_STR("Unable to send data to sign_agent.\n");
    }

    // first read 4 bytes to get the length of the response 
    msgLen = 0;
    if (!clientSocket.ReadInt(msgLen))
    {
        THROW_EXCEPTION_STR("Unable to read data from sign_agent.\n");
    }

    uint32_t command;
    if (!clientSocket.ReadInt(command))
    {
        THROW_EXCEPTION_STR("Unable to read data from sign_agent.\n");
    }
    THROW_EXCEPTION( command != e_SIGN_MESSAGE_RSP );

    uint8_t buffer[msgLen - 4];
    memset( buffer, 0, sizeof(buffer) );

    size_t rspLen = sizeof(buffer);
    if (!clientSocket.Read((char *)buffer, &rspLen))
    {
        THROW_EXCEPTION_STR("Unable to read data from sign_agent.\n");
    }

    std::vector<uint8_t> rawRspData;
    rawRspData.assign( buffer, buffer + rspLen );

    SignMessageRsp rspPkt(rawRspData);
    if (rspPkt.m_status == e_CMD_RSP_SUCCESS)
    {
        p_signBytes.assign( rspPkt.m_signBytes, 
                            rspPkt.m_signBytes + sizeof(rspPkt.m_signBytes) );
    }
    else
    {
        THROW_EXCEPTION_STR((char *) rspPkt.m_errorMsg );
    }

    return 0;
}


int IBM_Crypto::doOpensslSign( const std::string&  p_privKeyFileName,
                               const IBM_HexBytes& p_dgstBytes,
                               IBM_HexBytes&       p_signBytes )
{
    FILE *fp = fopen( p_privKeyFileName.c_str(), "r" );
    if (fp == NULL)
    {
        std::stringstream ss; 
        ss << "Failed to open private key file <"
           << p_privKeyFileName
           << ">"
           << std::endl;
        
        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    ECDSA_SIG *eccSig = NULL;
    EVP_PKEY* pkey = PEM_read_PrivateKey( fp, NULL, NULL, NULL );
    if (pkey == NULL)
    {
        std::stringstream ss; 
        ss << "Failed to read public key from file <"
           << p_privKeyFileName
           << ">"
           << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    try
    {
        EC_KEY *key = EVP_PKEY_get1_EC_KEY(pkey);

        const EC_GROUP *ecgrp = EC_KEY_get0_group(key);

        std::cout << "ECC Key type: "
                  << OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)) 
                  << std::endl;

        eccSig = ECDSA_do_sign( &p_dgstBytes[0], p_dgstBytes.size(), key );
        if (eccSig == NULL)
        {
            THROW_EXCEPTION_STR("Failed to generate ECC Signature.\n");
        }

        int sigSize = i2d_ECDSA_SIG( eccSig, NULL );
   
        p_signBytes.resize(sigSize);

        byte* pSigBytes = &p_signBytes[0];

        i2d_ECDSA_SIG( eccSig, &pSigBytes );

        ECDSA_SIG_free(eccSig);
        EVP_PKEY_free(pkey);
        fclose( fp );
    }
    catch ( IBM_Exception& e )
    {
        if (eccSig)
        {
            ECDSA_SIG_free(eccSig);
        }

        if (pkey)
        {
            EVP_PKEY_free(pkey);
        }

        if (fp)
        {
            fclose(fp);
        }

        // rethrow the exception
        throw;
    }

    return 0;
}


int IBM_Crypto::doCcaVerify( const std::string&  p_pubKeyFileName,
                             const IBM_HexBytes& p_dgstBytes,
                             const std::string&  p_signFileName )
{
    // The private key is a random integer (0 < priv_key < order, where order is
    // the order of the EC_GROUP object). The public key is an EC_POINT on the
    // curve calculated by multiplying the generator for the curve by the private key.
    
    // The public key value is an uncompressed point. It is defined
    // by value 04, which is an identifier for an uncompressed point,
    // followed by the X and Y coordinate, where the X and Y are encoded
    // as unsigned big endian octet strings that have the same size as
    // the key size (same as the size of the order of the curve in the
    // parameters).
    
    // the IBM public key is not DER formated but just the X and Y 
    // points on the named EC curve as mentioned above, so we need to
    // convert this to a DER format that OpenSSL APIs can work with

    // read the public key file
    IBM_Utils* pUtils = IBM_Utils::get();
    THROW_EXCEPTION(pUtils == NULL);

    IBM_HexBytes pkBytes;
    
    pUtils->ReadFromFile( p_pubKeyFileName, pkBytes, (ECDSA521_KEY_SIZE+1) );
    
    // The first byte should have the value 0x04, else its an invalid public key file
    if (pkBytes[0] != 0x04)
    {
        std::stringstream ss;
        ss << "File <" 
           << p_pubKeyFileName 
           << "> is not a vaid p521 public key file"
           << std::endl;
    
        THROW_EXCEPTION_STR(ss.str().c_str());
    }
    
    // public key file OK, delete the first byte
    pkBytes.erase( pkBytes.begin() );

    BIGNUM* X = NULL;
    BIGNUM* Y = NULL;
    BIGNUM* r = NULL;
    BIGNUM* s = NULL;

    EC_KEY* key    = NULL;

    int status = -1;

    try
    {
        X = BN_new();
        THROW_EXCEPTION(X == NULL);

        Y = BN_new();
        THROW_EXCEPTION(Y == NULL);

        BN_bin2bn( &pkBytes[0], 66, X );
        BN_bin2bn( &pkBytes[66], 66, Y );

        int eccgrp = OBJ_txt2nid("secp521r1");

        key = EC_KEY_new_by_curve_name(eccgrp);
        THROW_EXCEPTION(key == NULL);

        EC_KEY_set_asn1_flag( key, OPENSSL_EC_NAMED_CURVE );

        EC_KEY_set_public_key_affine_coordinates( key, X, Y );

        // the IBM signature file consists of a sequence of 2 Integers r and s 
        // is not DER formated, so we need to convert this to a DER format that
        // OpenSSL APIs can work with

        // read the Signature file
        IBM_HexBytes sigBytes;
    
        pUtils->ReadFromFile( p_signFileName, sigBytes, ECDSA521_SIG_SIZE );

        r = BN_new();
        THROW_EXCEPTION(r == NULL);

        s = BN_new();
        THROW_EXCEPTION(s == NULL);

        BN_bin2bn( &sigBytes[0], 66, r );
        BN_bin2bn( &sigBytes[66], 66, s );

        ECDSA_SIG signature;
        signature.r = r;
        signature.s = s;

        int sigSize = i2d_ECDSA_SIG( &signature, NULL );
       
        uint8_t derBytes[sigSize];

        uint8_t* derCopy = &derBytes[0];

        i2d_ECDSA_SIG( &signature, &derCopy );

        status = ECDSA_do_verify( &p_dgstBytes[0],
                                  p_dgstBytes.size(),
                                  &signature,
                                  key );

        BN_free(r);
        BN_free(s);
        BN_free(X);
        BN_free(Y);
        EC_KEY_free(key);
    }
    catch ( IBM_Exception& e )
    {
        if (r)
        {
            BN_free(r);
        }

        if (s)
        {
            BN_free(s);
        }

        if (X)
        {
            BN_free(X);
        }

        if (Y)
        {
            BN_free(Y);
        }

        if (key)
        {
            EC_KEY_free(key);
        }

        // rethrow the exception
        throw;
    }

    return status;
}


int IBM_Crypto::doOpensslVerify( const std::string&   p_pubKeyFileName,
                                 const IBM_HexBytes&  p_dgstBytes,
                                 const std::string&   p_signFileName )
{
    // read the public key file
    FILE *fp = fopen( p_pubKeyFileName.c_str(), "r" );
    if (fp == NULL)
    {
        std::stringstream ss;
        ss << "Failed to open public key file <" 
           << p_pubKeyFileName
           << ">"
           << std::endl;
    
        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY( fp, NULL, NULL, NULL );
    if (pkey == NULL)
    {
        std::stringstream ss; 
        ss << "Failed to read public key from file <"
           << p_pubKeyFileName
           << ">"
           << std::endl;

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    ECDSA_SIG* eccsig = NULL;

    int status = -1;
    try
    {
        EC_KEY* key = EVP_PKEY_get1_EC_KEY(pkey);
        THROW_EXCEPTION(key == NULL);

        const EC_GROUP* ecgrp = EC_KEY_get0_group(key);
        THROW_EXCEPTION(ecgrp == NULL);

        // read the Signature file
        IBM_HexBytes sigBytes;
    
        IBM_Utils* pUtils = IBM_Utils::get();
        THROW_EXCEPTION(pUtils == NULL);

        pUtils->ReadFromFile( p_signFileName, sigBytes );
    
        // construct signature object from the signature bytes
        const byte* p_sigBytes = &sigBytes[0];

        ECDSA_SIG* eccsig = d2i_ECDSA_SIG( NULL, &p_sigBytes, sigBytes.size() );
        THROW_EXCEPTION(eccsig == NULL);

        status = ECDSA_do_verify( &p_dgstBytes[0],
                                  p_dgstBytes.size(),
                                  eccsig,
                                  key );
        ECDSA_SIG_free(eccsig);
        EVP_PKEY_free(pkey);
        fclose( fp );
    }
    catch ( IBM_Exception& e )
    {
        if (eccsig)
        {
            ECDSA_SIG_free(eccsig);
        }

        if (pkey)
        {
            EVP_PKEY_free(pkey);
        }

        if (fp)
        {
            fclose( fp );
        }

        // rethrow the exception
        throw;
    }

    return status;
}
