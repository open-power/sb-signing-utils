/*
 * IBM_CfgManager.h
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

#ifndef IBM_CfgManager_H_
#define IBM_CfgManager_H_

#include <map>
#include <vector>
#include <string>

#include "IBM_CfgFileReader.h"


constexpr char s_SECTION_NAME_GLOBAL[]   = "GLOBAL";
constexpr char s_SECTION_NAME_DEFAULTS[] = "DEFAULTS";

constexpr char s_KEY_NAME_HOST[]  = "host";
constexpr char s_KEY_NAME_PORT[]  = "port";
constexpr char s_KEY_NAME_MODE[]  = "mode";
constexpr char s_KEY_NAME_HW[]    = "HW";
constexpr char s_KEY_NAME_SW[]    = "SW";


struct ProjInfo
{
    std::string  m_projectName;
    std::string  m_signFileName;
    std::string  m_pubkeyFileName;
};


class IBM_CfgManager
{
public:
    IBM_CfgManager( const std::string& p_configFileName );
    ~IBM_CfgManager();

    IBM_CfgManager( IBM_CfgManager& ) = delete;
    IBM_CfgManager( IBM_CfgManager&& ) = delete;
    IBM_CfgManager& operator = ( const IBM_CfgManager& ) = delete;

    void PrintItems();

    const std::string&  GetModeString();
    const std::string&  GetSignAgentHost();
    const std::string&  GetSignAgentPort();

    void GetProjectInfoList( const std::string&      p_projectToken,
                             const std::string&      p_keyName,
                             std::vector<ProjInfo>&  p_projInfoList );

private:
    void parse();

    std::string  m_modeString;
    std::string  m_signAgentHost;
    std::string  m_signAgentPort;
    std::string  m_configFileName;

    IBM_CfgFileReader m_cfgReader;
};

#endif // IBM_CfgManager_H_
