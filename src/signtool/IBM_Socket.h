#ifndef IBM_Socket_h_
#define IBM_Socket_h_

#include <arpa/inet.h>

#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#include <string>

/**
 * IBM_Socket
 *
 * A general interface to a socket 
 */
class IBM_Socket
{
public:
    //! Type of the socket
    enum TYPE 
    {
        INVALID,        //!< Uninitialized / invalid
        UDP_SERVER,     //!< UDP Server socket
        UDP_CLIENT,     //!< UDP client socket
        TCP_SERVER,     //!< TCP Server socket
        TCP_CLIENT      //!< TCP client socket
    };

    IBM_Socket();
    ~IBM_Socket();

    //! copy constructor and assignment operator not provided
    IBM_Socket( const IBM_Socket& rhs ) = delete;
    const IBM_Socket& operator= ( const IBM_Socket& rhs ) = delete;

    void     Close();
    bool     Initialize( TYPE p_type, int p_socket = -1 );

    bool     Accept( IBM_Socket* p_pNewSocket );
    bool     Bind( const std::string& p_listenAddr,
                   const std::string& p_listenPort );
    bool     Connect( const std::string& p_hostName, 
                      const std::string& p_port );
    bool     Listen( int p_connections = 1 );

    bool     SetLinger( bool p_on, int time );
    bool     SetReceiveTimeout( struct timeval p_tv );

    bool     ReadInt( uint32_t& p_val, struct sockaddr* p_pSockAddress = NULL );
    bool     Read( char* p_pBuf, size_t* p_length,
                   struct sockaddr* p_pSockAddress = NULL );

    bool     WriteInt( uint32_t p_val, struct sockaddr* p_pSockAddress = NULL );
    bool     Write( const char* p_pBuf, size_t p_length, 
                    const struct sockaddr* p_pSockAddress = NULL );

    int      GetHandle();

    TYPE     GetSocketType();

private:

    int                  m_socket;      //!< handle to socket
    int                  m_initialized; //!< initialization flag
    TYPE                 m_type;        //!< Type of the socket
    struct sockaddr_in   m_sockAddress; //!< Address the socket is bound to
};


#endif  // IBM_Socket_h_
