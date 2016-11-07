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

#ifndef IBM_TOKENIZER_H_
#define IBM_TOKENIZER_H_

#include <stdint.h>
#include <ctype.h>

#include <string>
#include <vector>
#include <algorithm>

class IsComma : public std::unary_function<char, bool>
{
public:
    inline bool operator()( char c ) const
    { 
        // iscomma() returns true if c == ','
        return ( c == ',' );
    }
}; 


class IsColon : public std::unary_function<char, bool>
{
public:
    inline bool operator()( char c ) const
    { 
        // iscolon() returns true if c == ':'
        return ( c == ':' );
    }
}; 


template<class Pred>
class IBM_Tokenizer
{
public:
    //The predicate should evaluate to true when applied to a separator.
    
    static inline void Tokenize( std::vector<std::string>& result, 
                                 std::string const& srcStr, 
                                 Pred const& pred = Pred() ) 
    { 
        //First clear the results vector
        result.clear(); 
        
        std::string::const_iterator it = srcStr.begin(); 
        std::string::const_iterator itTokenEnd = srcStr.begin(); 
        while ( it != srcStr.end() ) 
        {
            //Eat seperators
            while ( pred(*it) ) 
            {
                it++;
            }
            
            //Find next token
            itTokenEnd = std::find_if(it, srcStr.end(), pred); 
            
            //Append token to result
            if ( it < itTokenEnd ) 
            {
                std::string token = std::string(it, itTokenEnd); 
                
                result.push_back(token);
            }
            
            it = itTokenEnd;
        }
    }
}; 

#endif //  IBM_TOKENIZER_H_
