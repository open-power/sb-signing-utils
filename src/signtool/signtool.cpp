/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/signtool/signtool.cpp $                                   */
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

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <sstream>
#include <iostream>
#include <string>
#include <algorithm>

#include "IBM_CfgManager.h"
#include "IBM_Crypto.h"
#include "IBM_Exception.h"
#include "IBM_Container.h"
#include "IBM_HexString.h"
#include "IBM_Utils.h"

namespace
{
    constexpr uint32_t s_SIGN_VERIFY_FAILURE = 0;
    constexpr uint32_t s_SIGN_VERIFY_SUCCESS = 1;

    static bool s_verbose = false;

    // assume "development" build by default
    static IBM_Mode s_mode = e_MODE_DEVELOPMENT;

    static std::string s_devMode = "development";
    static std::string s_ibmProdMode = "ibm-production";

    static std::string s_configFileName;
    static std::string s_projectToken;

    static std::string s_modeStr;
    static std::string s_output;

    static std::string s_shaDigest;
    static std::string s_signFileName;
    static std::string s_pubkeyFileName;
    static std::string s_privkeyOrProjName;

    static std::string s_hashHdrType;
    static std::string s_hashAlgo = "sha512";

    // assume sign_agent running locally by default
    static std::string s_saHostName = "127.0.0.1";

    // sign_agent listens on port 8001 by default
    static std::string s_saPortNum = "8001";

    static std::string s_fldName;
    static std::string s_fldValue;
    static std::string s_imgFileName;

    static std::string  s_PROGRAM_NAME;

    const char* getProgramName()
    {
        return s_PROGRAM_NAME.c_str();
    }

    static std::string  s_VERSION = "1.0.0";

 
    int PrintVerifyStatus( int verStatus )
    {
        int retVal;

        std::cout << "ECC Signature ";
        switch (verStatus)
        {
            case s_SIGN_VERIFY_SUCCESS:
            {
                std::cout << "Verified OK";
                retVal = 0;
                break;
            }

            case s_SIGN_VERIFY_FAILURE:
            {
                std::cout << "Verification Failure";
                retVal = 1;
                break;
            }

            default:
            {
                std::cout << "encountered Openssl Error";
                retVal = verStatus;
                break;
            }
        }
        std::cout << std::endl;

        return retVal;
    }

    std::string getAppVersion(bool version)
    {
        std::string s_version;
        if (version)
        {
            const char *pgmName = basename(s_PROGRAM_NAME.c_str()); 

            s_version = std::string( pgmName ) + 
                        " app Version " + s_VERSION + "\n" +
                        "(C) Copyright IBM Corporation 2016" + "\n" +
                        "built on " + __DATE__ + " " +  __TIME__ + "\n";
        }
        else
        {   
            s_version = s_VERSION;
        }

        return s_version;
    }


    //
    //  Display the application usage.
    //
    void ShowUsage()
    {
        std::cout << std::endl;
        std::cout << getAppVersion(true) << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "   --help                    Signtool help."
                  << std::endl;
        std::cout << "   --version                 Signtool version."
                  << std::endl;
        std::cout << "   --verbose                 Print verbose messages."
                  << std::endl << std::endl;
        std::cout << "   --mode                    Signing mode 'production' or 'development'"
                  << std::endl;
        std::cout << "   --get_pubkey              Get public key from specified private key or project name."
                  << std::endl << std::endl;
        std::cout << "   --sign                    Sign the input data."
                  << std::endl;
        std::cout << "   --verify                  Verify the signature."
                  << std::endl;
        std::cout << "   --create_key              Create ECDSA 521 Key (PEM format)."
                  << std::endl;
        std::cout << "   --sigfile                 Output path for saving signature."
                  << std::endl;
        std::cout << "   --privkeyfile             Path name containing ECDSA private key."
                  << std::endl;
        std::cout << "   --pubkeyfile              Path name containing ECDSA public key."
                  << std::endl;
        std::cout << "   --digest                  digest string to be signed."
                  << std::endl;
        std::cout << "   --projname                Name of Signing project (production mode)."
                  << std::endl;
        std::cout << "   --sa_hostname             Hostname or IP Address of sign_agent."
                  << std::endl;
        std::cout << "   --sa_portnum              Port number of sign_agent."
                  << std::endl << std::endl;
        std::cout << "   --configfile              Config file to use for sign and getting public key."
                  << std::endl;
        std::cout << "   --projecttoken            Specify project to operate in the given config file."
                  << std::endl;
        std::cout << "   --calchash                Calculate hash for the specified field type."
                  << std::endl;
        std::cout << "   --fldtype                 Field type, must be one of prefix_hdr or software_hdr."
                  << std::endl;
        std::cout << "   --hashalgo                hash algortihm to use sha1, sha256, sha384 or sha512, default is sha512."
                  << std::endl << std::endl;
        std::cout << "   --create-container        Create a default container."
                  << std::endl;
        std::cout << "   --imagefile               Path name for container operation."
                  << std::endl;
        std::cout << "   --print-container         Print the contents of container."
                  << std::endl;
        std::cout << "   --fldname                 Container field to change."
                  << std::endl;
        std::cout << "   --fldvalue                Value for specified container field."
                  << std::endl << std::endl << std::endl;
        std::cout << "   The following values are accepted for option <--fldname>" << std::endl;

        IBM_Container junk(e_MODE_DEVELOPMENT);

        std::vector<std::string> fldNamesList;
        junk.GetFieldNameList( fldNamesList );

        for (uint32_t i = 0; i < fldNamesList.size(); i++)
        {
             std::cout << "          " << fldNamesList[i] << std::endl;
        }
        std::cout << std::endl << std::endl;
    }

    
    static const int s_CMD_NONE(0x00);
    static const int s_CMD_HELP(0x01);
    static const int s_CMD_VERSION(0x02);
    static const int s_CMD_SIGN(0x04);
    static const int s_CMD_VERIFY(0x08);
    static const int s_CMD_CREATE_KEY(0x10);
    static const int s_CMD_PRINT_CONTAINER(0x20);
    static const int s_CMD_CREATE_CONTAINER(0x40);
    static const int s_CMD_UPD_CONTAINER_FLD(0x80);
    static const int s_CMD_CALCULATE_HASH(0x100);
    static const int s_CMD_GET_PUBLIC_KEY(0x200);

    int ParseArguments( int argc, char* argv[] )
    {
        static const struct option longopts[] =
        {
            { "mode",                     required_argument, NULL, 'm' },

            { "sign",                     no_argument,       NULL, 's' },
            { "verify",                   no_argument,       NULL, 't' },
            { "create_key",               no_argument,       NULL, 'u' },
            { "get_pubkey",               no_argument,       NULL, 'g' },

            { "projname",                 required_argument, NULL, 'N' },
            { "sigfile",                  required_argument, NULL, 'S' },
            { "pubkeyfile",               required_argument, NULL, 'K' },
            { "privkeyfile",              required_argument, NULL, 'L' },
            { "digest",                   required_argument, NULL, 'D' },
            { "sa_hostname",              required_argument, NULL, 'H' },
            { "sa_portnum",               required_argument, NULL, 'P' },

            { "configfile",               required_argument, NULL, 'C' },
            { "projecttoken",             required_argument, NULL, 'E' },

            { "create-container",         no_argument,       NULL, 'c' },
            { "print-container",          no_argument,       NULL, 'p' },
            { "imagefile",                required_argument, NULL, 'I' },
            { "fldname",                  required_argument, NULL, 'F' },
            { "fldvalue",                 required_argument, NULL, 'V' },

            { "calchash",                 no_argument,       NULL, 'd' },
            { "fldtype",                  required_argument, NULL, 'T' },
            { "hashalgo",                 required_argument, NULL, 'A' },

            { "help",                     no_argument,       NULL, 'h' },
            { "version",                  no_argument,       NULL, 'v' },
            { "verbose",                  no_argument,       NULL, 'x' },

            { NULL,                       0,                 NULL,  0  }
        };


        int startFlags = s_CMD_NONE;

        int opt = 0;
        int long_index=0;

        while ((opt = getopt_long_only (argc, argv, "", longopts, &long_index)) != -1)
        {
            switch (opt)
            {
                case 'm':   // Production or Development Mode
                {
                    s_modeStr = std::string ( optarg );
                    break;
                }

                case 's':   // Sign given digest
                {
                    startFlags = s_CMD_SIGN;
                    break;
                }

                case 't':   // Verify signature, given digest, public key and signature
                {
                    startFlags = s_CMD_VERIFY;
                    break;
                }

                case 'u':   // Create ec curve 521 Key
                {
                    startFlags = s_CMD_CREATE_KEY;
                    break;
                }

                case 'g':   // Get Public Key for the given project
                {
                    startFlags = s_CMD_GET_PUBLIC_KEY;
                    break;
                }

                case 'C':
                {
                    s_configFileName = std::string(optarg);
                    break;
                }

                case 'E':
                {
                    s_projectToken = std::string(optarg);
                    break;
                }

                case 'N':   // Signing Project Name
                case 'L':   // key filename for signing/verifying/create key operations
                {
                    s_privkeyOrProjName = std::string ( optarg );
                    break;
                }

                case 'K':   // key filename for signing/verifying/create key operations
                {
                    s_pubkeyFileName = std::string ( optarg );
                    break;
                }

                case 'S':   // signature filename for signing/verifying operations
                {
                    s_signFileName = std::string ( optarg );
                    break;
                }

                case 'D':   // sha-256, sha-384 or sha-512 digest that needs to be signed
                {
                    s_shaDigest = std::string ( optarg );
                    break;
                }

                case 'H':   // Hostname or IP Address of sign_agent
                {
                    s_saHostName = std::string ( optarg );
                    break;
                }

                case 'P':   // Portnum of sign_agent
                {
                    s_saPortNum = std::string( optarg );
                    break;
                }

                case 'c':
                {
                    startFlags = s_CMD_CREATE_CONTAINER;
                    break;
                }

                case 'p':
                {
                    startFlags = s_CMD_PRINT_CONTAINER;
                    break;
                }

                case 'I':
                {
                    s_imgFileName = std::string( optarg );
                    break;
                }

                case 'F':
                {
                    startFlags = s_CMD_UPD_CONTAINER_FLD;

                    s_fldName = std::string( optarg );
                    break;
                }

                case 'V':
                {
                    s_fldValue = std::string( optarg );
                    break;
                }

                case 'd':
                {
                    startFlags = s_CMD_CALCULATE_HASH;
                    break;
                }

                case 'T':
                {
                    s_hashHdrType = std::string( optarg );
                    break;
                }

                case 'A':
                {
                    s_hashAlgo = std::string( optarg );
                    break;
                }

                case 'h':
                {
                    startFlags = s_CMD_HELP;
                    break;
                }

                case 'v':
                {
                    startFlags = s_CMD_VERSION;
                    break;
                }

                case 'x':   // --verbose
                {
                    s_verbose = true;
                    break;
                }

                default:
                {
                    startFlags = -1;
                    break;
                }
            }
        }

        return startFlags;
    }
}



//
//  Signtool.  Multi-purpose signature generation / validation utility.
//

int main ( int argc, char** argv )
{
    int rc = 0;

    s_PROGRAM_NAME=argv[0];

    int flags = ParseArguments( argc, argv );

    if (flags < 0)
    {
        ShowUsage();
        return 1;
    }

    if (flags == s_CMD_NONE)
    {
         std::cout << std::endl
                   << "No operation specified, issue \""
                   << basename(s_PROGRAM_NAME.c_str()) 
                   << " --help\" for more info on usage." 
                   << std::endl << std::endl;

         return 2;
    }
    
    if (flags & s_CMD_VERSION)
    {
        std::cout << getAppVersion( s_verbose ) << std::endl;
        return 0;
    }
    else if (flags & s_CMD_HELP)
    {
        ShowUsage();
        return 0;
    }

    try
    {
        // check what mode we are asked to use
        if (!s_modeStr.empty())
        {
            if (s_modeStr == s_ibmProdMode)
            {
                s_mode = e_MODE_IBM_PRODUCTION;
            }
            else if (s_modeStr == s_devMode)
            {
                s_mode = e_MODE_DEVELOPMENT;
            }
            else
            {
                std::stringstream ss;
                ss << "*** Invalid value for mode" << std::endl
                   << "--- Expecting <" << s_ibmProdMode << "> or <" << s_devMode
                   << ">, got <" << s_modeStr << ">" << std::endl;

                THROW_EXCEPTION_STR(ss.str().c_str());
            }
        }

        if (flags & s_CMD_CREATE_CONTAINER)
        {
            if (s_imgFileName.size() == 0)
            {
                THROW_EXCEPTION_STR( "misssing --imagefile parameter." );
            }

            //  create a default container and save it in the specfied filename
            IBM_Container contObj(s_mode);

            THROW_EXCEPTION( contObj.Save( s_imgFileName ) == false );
        }
        else if (flags & s_CMD_UPD_CONTAINER_FLD)
        {
            if (s_imgFileName.size() == 0)
            {
                THROW_EXCEPTION_STR( "misssing --imagefile parameter." );
            }
 
            if (s_fldName.size() == 0)
            {
                THROW_EXCEPTION_STR( "missing --fldname parameter." );
            }

            if (s_fldValue.size() == 0)
            {
                THROW_EXCEPTION_STR( "missing --fldvalue parameter." );
            }

            // Open the container and update the specified field
            IBM_Container contObj(s_mode, s_imgFileName);

            THROW_EXCEPTION( contObj.UpdateField( s_fldName, s_fldValue ) == false );
            THROW_EXCEPTION( contObj.Save( s_imgFileName ) == false );
        }
        else if (flags & s_CMD_PRINT_CONTAINER)
        {
            if (s_imgFileName.size() == 0)
            {
                THROW_EXCEPTION_STR( "misssing --imagefile parameter." );
            }

            // Open the container and print its contents
            IBM_Container contObj(s_mode, s_imgFileName);

            contObj.Print();
        }
        else if (flags & s_CMD_SIGN)
        {
            // construct the Crypto Object
            IBM_Crypto crypto(s_mode);

            // digest parameter is common to both invocations
            if (s_shaDigest.empty())
            {
                THROW_EXCEPTION_STR( "missing --digest parameter." );
            }

            // check if we are given a config file, if so use that
            if (s_configFileName.empty())
            {
                if (s_privkeyOrProjName.empty())
                {
                    if (s_mode == e_MODE_IBM_PRODUCTION)
                    {
                        THROW_EXCEPTION_STR( "missing --projname parameter." );
                    }
                    else
                    {
                        THROW_EXCEPTION_STR( "missing --privkeyfile parameter." );
                    }
                }

                if (s_signFileName.empty())
                {
                    THROW_EXCEPTION_STR( "missing --sigfile paramater." );
                }

                //  send the request to sign and save the signature
                //  in the specified filename
                bool retVal = crypto.Sign( s_privkeyOrProjName,
                                           s_shaDigest,
                                           s_signFileName,
                                           s_saHostName,
                                           s_saPortNum );
                THROW_EXCEPTION(retVal == false );
            }
            else
            {
                IBM_CfgManager cfgManager(s_configFileName);

                std::vector<ProjInfo> projInfoList;
                cfgManager.GetProjectInfoList( s_projectToken, projInfoList );

                for (auto itr : projInfoList)
                {
                    //  send the request to sign and save the signature
                    //  in the specified filename
                    bool retVal = crypto.Sign( itr.m_projectName,
                                               s_shaDigest,
                                               itr.m_signFileName,
                                               cfgManager.GetSignAgentHost(),
                                               cfgManager.GetSignAgentPort() );
                    THROW_EXCEPTION(retVal == false );
                }
            }
        }
        else if (flags & s_CMD_VERIFY)
        {
            // construct the Crypto Object
            IBM_Crypto crypto(s_mode);

            // digest parameter is common to both invocations
            if (s_shaDigest.size() == 0)
            {
                THROW_EXCEPTION_STR( "missing --digest parameter." );
            }

            // check if we are given a config file, if so use that
            if (s_configFileName.empty())
            {
                if (s_pubkeyFileName.size() == 0 )
                {
                    THROW_EXCEPTION_STR( "missing --pubkeyfile parameter." );
                }

                if (s_signFileName.size() == 0)
                {
                    THROW_EXCEPTION_STR( "missing --sigfile paramater." );
                }

                //  Verify the signature
                int status = crypto.Verify( s_pubkeyFileName,
                                            s_shaDigest,
                                            s_signFileName );

                rc = PrintVerifyStatus( status );
            }
            else
            {
                IBM_CfgManager cfgManager(s_configFileName);

                std::vector<ProjInfo> projInfoList;
                cfgManager.GetProjectInfoList( s_projectToken, projInfoList );

                for (auto itr : projInfoList)
                {
                    //  send the request to sign and save the signature
                    //  in the specified filename
                    int status = crypto.Verify( itr.m_projectName,
                                                s_shaDigest,
                                                itr.m_pubkeyFileName );
                    rc = PrintVerifyStatus( status );
                }
            }
        }
        else if (flags & s_CMD_CREATE_KEY)
        {
            // construct the Crypto Object
            IBM_Crypto crypto(s_mode);

            if (s_pubkeyFileName.size() == 0 )
            {
                THROW_EXCEPTION_STR( "missing --pubkeyfile parameter." );
            }

            if (s_privkeyOrProjName.size() == 0 )
            {
                THROW_EXCEPTION_STR( "missing --privkeyfile parameter." );
            }

            //  Create the keypair and save them in the specfied
            //  files in PEM foramt
            crypto.CreateKeyPair( s_privkeyOrProjName,
                                  s_pubkeyFileName );
        }
        else if (flags & s_CMD_GET_PUBLIC_KEY)
        {
            // construct the Crypto Object
            IBM_Crypto crypto(s_mode);

            // check if we are given a config file, if so use that
            if (s_configFileName.empty())
            {
                if (s_pubkeyFileName.size() == 0 )
                {
                    THROW_EXCEPTION_STR( "missing --pubkeyfile parameter." );
                }

                if (s_privkeyOrProjName.size() == 0 )
                {
                    if (s_mode == e_MODE_IBM_PRODUCTION)
                    {
                        THROW_EXCEPTION_STR( "missing --projname parameter." );
                    }
                    else
                    {
                        THROW_EXCEPTION_STR( "missing --privkeyfile parameter." );
                    }
                }

                //  Get the public key assocaited with the project
                crypto.GetPublicKey( s_privkeyOrProjName,
                                     s_pubkeyFileName,
                                     s_saHostName,
                                     s_saPortNum );
            }
            else
            {
                IBM_CfgManager cfgManager(s_configFileName);

                std::vector<ProjInfo> projInfoList;
                cfgManager.GetProjectInfoList( s_projectToken, projInfoList );

                for (auto itr : projInfoList)
                {
                    //  send the request to get the public key and save it
                    //  in the specified filename
                    crypto.GetPublicKey( itr.m_projectName,
                                         itr.m_pubkeyFileName,
                                         cfgManager.GetSignAgentHost(),
                                         cfgManager.GetSignAgentPort() );
                }
            }
        }
        else if (flags & s_CMD_CALCULATE_HASH)
        {
            if (s_imgFileName.size() == 0)
            {
                THROW_EXCEPTION_STR( "misssing --imagefile parameter." );
            }
 
            if (s_hashHdrType.size() == 0)
            {
                THROW_EXCEPTION_STR( "missing --fldtype parameter." );
            }

            if (s_hashAlgo.size() == 0)
            {
                THROW_EXCEPTION_STR( "missing --hashalgo parameter." );
            }

            // calculate the hash of the requested field of the specfied container
            // using the specified hash algoritm
            IBM_Container contObj(s_mode, s_imgFileName);

            std::string digestStr;

            THROW_EXCEPTION( contObj.ComputeHash( s_hashHdrType, s_hashAlgo, digestStr ) == false );

            std::cout << digestStr << std::endl;
        }
    }
    catch ( IBM_Exception& e )
    {
        std::cout << e.what() << std::endl;
        rc = 3;
    }
    
    return rc;
}
