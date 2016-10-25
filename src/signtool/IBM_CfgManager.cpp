/*
 * IBM_CfgManager.cpp
 *
 * -------------------------------------------------------------------------
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

#include <iostream>
#include <sstream>

#include "IBM_Tokenizer.h"
#include "IBM_Exception.h"
#include "IBM_CfgFileReader.h"
#include "IBM_CfgManager.h"


IBM_CfgManager::IBM_CfgManager( const std::string& p_configFileName )
   : m_configFileName(p_configFileName),
     m_cfgReader(p_configFileName)
     
{
    parse();
}


IBM_CfgManager::~IBM_CfgManager()
{
}


void IBM_CfgManager::PrintItems()
{
    m_cfgReader.PrintItems();
}


const std::string& IBM_CfgManager::GetSignAgentHost()
{
    return m_signAgentHost;
}


const std::string& IBM_CfgManager::GetSignAgentPort()
{
    return m_signAgentPort;
}


void IBM_CfgManager::GetProjectInfoList( const std::string&      p_projectToken,
                                         std::vector<ProjInfo>&  p_projInfoList )
{
    std::vector<std::string> projInfoList;

    m_cfgReader.GetValue( p_projectToken,
                          s_KEY_NAME_DETAILS,
                          projInfoList );

    for (auto itr : projInfoList)
    {
        std::vector<std::string> infoList;
        IBM_Tokenizer<IsComma>::Tokenize( infoList, itr, IsComma());

        THROW_EXCEPTION( infoList.size() != 3 );
        
        ProjInfo projInfo = { infoList[0], infoList[1], infoList[2] };

        p_projInfoList.push_back( projInfo );
    }
}



void IBM_CfgManager::parse() 
{
    // check if the section [GLOBAL] is present
    if (!m_cfgReader.IsSectionPresent( s_SECTION_NAME_GLOBAL ))
    {
        std::stringstream ss;
        ss << "section <" << s_SECTION_NAME_GLOBAL << "> is missing from config file " 
           << m_configFileName;

        THROW_EXCEPTION_STR(ss.str().c_str()); 
    }

    // check if the keyname <host> is present
    if (!m_cfgReader.IsKeyPresent( s_SECTION_NAME_GLOBAL, s_KEY_NAME_HOST ))
    {
        std::stringstream ss;
        ss << "key <" << s_KEY_NAME_HOST << "> is missing from section <"
           << s_SECTION_NAME_GLOBAL << "> in config file <" << m_configFileName << ">";

        THROW_EXCEPTION_STR(ss.str().c_str()); 
    }
    m_cfgReader.GetValue( s_SECTION_NAME_GLOBAL, s_KEY_NAME_HOST, m_signAgentHost );

    // check if the keyname <port> is present
    if (!m_cfgReader.IsKeyPresent( s_SECTION_NAME_GLOBAL, s_KEY_NAME_PORT ))
    {
        std::stringstream ss;
        ss << "key <" << s_KEY_NAME_PORT << "> is missing from section <"
           << s_SECTION_NAME_GLOBAL << "> in config file <" << m_configFileName << ">";

        THROW_EXCEPTION_STR(ss.str().c_str()); 
    }
    m_cfgReader.GetValue( s_SECTION_NAME_GLOBAL, s_KEY_NAME_PORT, m_signAgentPort );
}
