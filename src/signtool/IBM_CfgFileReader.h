/*
 * IBM_CfgFileReader.h
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

#ifndef IBM_CfgFileReader_H_
#define IBM_CfgFileReader_H_

#include <string>
#include <map>

class IBM_CfgFileReader
{
public:
    typedef std::pair<std::string, std::string> KeyValPair;

    IBM_CfgFileReader( const std::string& p_cfgFileName );
    ~IBM_CfgFileReader();

    void PrintItems();

    bool IsSectionPresent( const std::string& p_sectionName );

    void GetSection( const std::string&                        p_sectionName,
                     std::multimap<std::string, std::string>&  p_keyValMap );

    bool IsKeyPresent( const std::string& p_sectionName,
                       const std::string& p_keyName );

    void GetValue( const std::string&        p_sectionName,
                   const std::string&        p_keyName,
                   std::string&              p_value );

    void GetValue( const std::string&        p_sectionName,
                   const std::string&        p_keyName,
                   std::vector<std::string>& p_valueList );

private:
    void parse( const std::string& p_cfgFileName );
    void trim( std::string& p_str );


    std::map< std::string, std::multimap<std::string, std::string> > m_cfgItemsMap;
};

#endif // IBM_CfgFileReader_H_
