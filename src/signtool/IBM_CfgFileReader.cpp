#include <errno.h>

#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <map>
#include <regex>

#include "IBM_Exception.h"
#include "IBM_CfgFileReader.h"

// There is not Regualar Expression support in the compiler toolchain of RHEL 7.2
// so this extra code, else use RE when newer compilers are available that support
// c++14

IBM_CfgFileReader::IBM_CfgFileReader( const std::string& p_cfgFileName )
{
    parse(p_cfgFileName);
}


IBM_CfgFileReader::~IBM_CfgFileReader()
{
}


void IBM_CfgFileReader::PrintItems()
{
    auto itb1 = m_cfgItemsMap.begin();
    auto ite1 = m_cfgItemsMap.end();

    for ( ; itb1 != ite1; itb1++ )
    {
        std::cout << "[" << itb1->first << "]" << std::endl;

        auto& keyValMap = itb1->second;

        auto itb2 = keyValMap.begin();
        auto ite2 = keyValMap.end();

        for ( ; itb2 != ite2; ++itb2 )
        {
            std::cout << "    " << itb2->first << "=" << itb2->second << std::endl;
        }
    }
}


bool IBM_CfgFileReader::IsSectionPresent( const std::string& p_sectionName )
{
    bool retVal = false;

    const auto it1 = m_cfgItemsMap.find( p_sectionName );

    if (it1 != m_cfgItemsMap.end())
    {
        retVal = true;
    }

    return retVal;
}


bool IBM_CfgFileReader::IsKeyPresent( const std::string& p_sectionName,
                                      const std::string& p_keyName )
{
    bool retVal = false;

    const auto it1 = m_cfgItemsMap.find( p_sectionName );

    if (it1 != m_cfgItemsMap.end())
    {
        auto kvMap = it1->second;

        const auto it2 = kvMap.find( p_keyName );
        if (it2 != kvMap.end())
        {
            retVal = true;
        }
    }

    return retVal;
}


void IBM_CfgFileReader::GetSection( 
                  const std::string&                       p_sectionName,
                  std::multimap<std::string, std::string>& p_keyValMap )
{
    p_keyValMap.clear();

    const auto it1 = m_cfgItemsMap.find( p_sectionName );

    if (it1 != m_cfgItemsMap.end())
    {
        p_keyValMap.insert( it1->second.begin(), it1->second.end() );
    }
}


void IBM_CfgFileReader::GetValue( const std::string&   p_sectionName,
                                  const std::string&   p_keyName,
                                  std::string&         p_value )
{
    p_value.clear();

    const auto it1 = m_cfgItemsMap.find( p_sectionName );

    if (it1 != m_cfgItemsMap.end())
    {
        auto& keyValMap = it1->second;

        auto it2 = keyValMap.find( p_keyName );
        if (it2 != keyValMap.end())
        {
            p_value = it2->second;
        }
    }
}



void IBM_CfgFileReader::GetValue( const std::string&         p_sectionName,
                                  const std::string&         p_keyName,
                                  std::vector<std::string>&  p_valueList )
{
    p_valueList.clear();

    const auto it1 = m_cfgItemsMap.find( p_sectionName );

    if (it1 != m_cfgItemsMap.end())
    {
        auto& keyValMap = it1->second;

        auto result = keyValMap.equal_range( p_keyName );
        for (auto it2 = result.first; it2 != result.second; ++it2)
        {
            p_valueList.push_back(it2->second);
        }
    }
}


void IBM_CfgFileReader::parse( const std::string& p_cfgFileName )
{
    std::ifstream fstrm;
    fstrm.open(p_cfgFileName);

    if (!fstrm)
    {
        std::stringstream ss;
        ss << "failed to open ini file <" << p_cfgFileName + "> : " << strerror(errno);

        THROW_EXCEPTION_STR(ss.str().c_str());
    }

    std::multimap<std::string, std::string> keyValMap;
    std::string current_section;

    for (std::string line; std::getline(fstrm, line);)
    {
        if (!line.empty() && (line[0] == ';' || line[0] == '#'))
        {
            // allow both ; and # comments at the start of a line
        }
        else if (line[0] == '[')
        {
            /* A "[section]" line */
            size_t end = line.find_first_of(']');
            if (end != std::string::npos)
            {
                // this is a new section so if we have a current section populated, add it to list
                if (!current_section.empty())
                {
                    m_cfgItemsMap[current_section] = keyValMap;
                    keyValMap.clear();
                }
                current_section = line.substr(1, end - 1);
            }
            else
            {
                // section has no closing ] char
                std::stringstream ss;
                ss << "missing \"]\" in section <" 
                   << line.substr(1) << ">";
                
                THROW_EXCEPTION_STR(ss.str().c_str());
            }
        }
        else if (!line.empty())
        {
            /* Not a comment, must be a name[=]value pair */
            size_t end = line.find_first_of("=");
            if (end != std::string::npos)
            {
                std::string name = line.substr(0, end);
                trim(name);

                std::string value = line.substr(end + 1);
                trim(value);

                keyValMap.insert(std::pair<std::string, std::string>(name, value));
            }
            else
            {
                // no key value delimitter
                std::stringstream ss;
                ss << "no key value delimiter found in section <" 
                   << current_section << ">";
                
                THROW_EXCEPTION_STR(ss.str().c_str());
            }
        }
    }

    if (!current_section.empty())
    {
        m_cfgItemsMap[current_section] = keyValMap;
        keyValMap.clear();
    }
}


void IBM_CfgFileReader::trim( std::string& p_str )
{
    p_str.erase( 0, p_str.find_first_not_of(' ') );  //prefixing spaces
    p_str.erase( p_str.find_last_not_of(' ')+1 );    //suffixing spaces
}
