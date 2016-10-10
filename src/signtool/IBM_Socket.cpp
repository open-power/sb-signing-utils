#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

#include "IBM_Socket.h"
#include "IBM_Exception.h"


IBM_Socket::IBM_Socket()
    : m_socket( -1 ),
      m_initialized( false ),
      m_type( INVALID )
{
    memset( (void *) &m_sockAddress, 0, sizeof(m_sockAddress) );
}


IBM_Socket::~IBM_Socket()
{
    this->Close();
}


/**
 * @brief Close underlying socket
 *
 * @return true if the operation succeeded, false otherwise
 */
void IBM_Socket::Close()
{
    if (!m_initialized)
    {
        return;
    }

    ::close( m_socket );
    m_socket = -1;
    m_initialized = false;
}


/**
 * @brief Create a socket of the given type, or use the given socket.
 *
 * If p_socket is not given or is <= 0, this function will create a new
 * UDP or TCP socket according to the type parameter.  Otherwise it will
 * use the given socket.  The IBM_Socket object will take ownership of
 * the socket and will release it in IBM_Socket::close.
 *
 * @param p_type Type of the socket.
 *      @li UDP_SERVER
 *      @li UDP_CLIENT
 *      @li TCP_SERVER
 *      @li TCP_CLIENT
 *
 * @param p_socket Optional socket handle.
 *
 * @return true if the operation succeeded, false otherwise
 */
bool IBM_Socket::Initialize( TYPE p_type, int p_socket )
{
    bool retVal = true;

    if (m_initialized)
    {
        return true; 
    }

    m_type = p_type;
    if (m_type == INVALID)
    {
        return false;
    }

    if (p_socket > 0)
    {
        m_socket = p_socket;

        socklen_t len = sizeof(m_sockAddress);
        if (!getpeername( m_socket, (struct sockaddr*) &m_sockAddress, &len ))
        {
            retVal = false;
        }
    }
    else
    {
        switch( m_type )
        {
            case UDP_SERVER:
            case UDP_CLIENT:
            {
                m_socket = socket(AF_INET, SOCK_DGRAM, 0);
                break;
            }

            case TCP_SERVER:
            case TCP_CLIENT:
            {
                m_socket = socket(AF_INET, SOCK_STREAM, 0);
                break;
            }

            default:
            {
                retVal = false;
            }
        }
    }

    m_initialized = (m_socket > 0) ? true : false;
    retVal = m_initialized;

    return retVal;
}


/**
 * @brief Accept an incoming connection on a TCP server socket.
 *
 * This function may only be called on TCP server sockets.  The socket
 * argument points to an uninitialized socket created by the caller, which
 * will be initialized if the accept operation succeeds.
 *
 * @param p_pNewSocket  Pointer to an uninitialized socket
 *
 * @return true if the operation succeeded and p_pNewSocket was initialized.
 */
bool IBM_Socket::Accept( IBM_Socket* p_pNewSocket )
{
    if( m_socket < 0 )
    {
        return false;
    }

    if( m_type != TCP_SERVER )
    { 
        return false;
    }

    socklen_t len = sizeof(m_sockAddress);
   
    int socket;
    socket = ::accept( m_socket, (struct sockaddr *) &m_sockAddress, &len );
    if (socket < 0)
    {
        std::cout << "accept failed : " << strerror(errno) << std::endl;

        return false;
    }
 
    return p_pNewSocket->Initialize( TCP_CLIENT, socket );
}


/**
 * @brief Binds the socket to a local port.  Server sockets only.
 *
 * For now this function is restricted to server sockets.  It would
 * become useful for client sockets on a system with multiple adapter.
 *
 * @param p_ipAddr  what IP interface to bind to
 * @param p_port    Port to bind to, or 0 for any port.
 *
 * @return true if the operation succeeded, false otherwise
 */
bool IBM_Socket::Bind( const std::string& p_listenAddr,
                       const std::string& p_listenPort )
{
    if (m_socket < 0)
    {
        return false;
    }

    if (!((m_type == UDP_SERVER) || (m_type == TCP_SERVER)))
    {
        return false;
    }

    int optval = 1;
    if (setsockopt( m_socket, SOL_SOCKET, SO_REUSEADDR, 
                              (char *) &optval, sizeof(optval) ) < 0)
    { 
        throw IBM_Exception( "setsockopt() call failed: %s", strerror(errno) );
    }

    struct addrinfo  hints;
    memset( &hints, 0, sizeof hints );

    hints.ai_family   = AF_INET;     // need IPv6 support as well?
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;  // use my IP address

    struct addrinfo* servinfo;
    int rv = getaddrinfo( p_listenAddr.c_str(),
                          p_listenPort.c_str(),
                          &hints,
                          &servinfo );
    if (rv != 0)
    {
        throw IBM_Exception( "getaddrinfo() call failed: %s", gai_strerror(rv) );
    }

    bool retVal = true;

    // loop through all the results and bind to the first we can
    for (struct addrinfo* p = servinfo; p != NULL; p = p->ai_next)
    {
        char ipAddress[32];
        inet_ntop( AF_INET,
                   &(((struct sockaddr_in *)p->ai_addr)->sin_addr),
                   ipAddress,
                   sizeof(ipAddress) );
        
        if (::bind( m_socket, p->ai_addr, p->ai_addrlen) == 0)
        {
            memcpy( &m_sockAddress, (struct sockaddr_in *) p->ai_addr, p->ai_addrlen );

            std::cout << "server is now listenting on "
                      << ipAddress << ":" 
                      << p_listenPort << std::endl;;

            retVal = true;
            break;
        }

        // bind failed, log the info and try the next one in the list (if any?)
        std::cout << "bind to address " << ipAddress << ":" 
                  << p_listenPort << "failed" << std::endl;;

    }
    free(servinfo);
 
    return retVal;   
}


/**
 * @brief   Connect a client socket to a remote host / port
 *
 * This function may only be called on client sockets.  For TCP sockets,
 * a successful connect establishes a TCP connection.  For UDP sockets,
 * it establishes the default remote host for send() and recv() commands.
 * This function should not be re-called after a successful call.
 *
 * @param p_pHostName   Name of the remote host, may be "localhost".
 * @param p_port        Port of the service we're trying to connect to.
 *
 * @return true if the operation succeeded, false otherwise
 */
bool IBM_Socket::Connect( const char* p_pHostName, uint16_t p_port )
{
    bool retVal = true;

    if (m_socket < 0)
    {
        return false;
    }

    if (!((m_type == UDP_CLIENT) || (m_type == TCP_CLIENT)))
    {
        return false;
    }

    struct hostent *hostInfo = gethostbyname( p_pHostName );
    if (hostInfo == NULL) 
    {
        return false;
    }

    // Connect to server.
    m_sockAddress.sin_family = hostInfo->h_addrtype;
    m_sockAddress.sin_port   = htons( p_port );

    memcpy( (char *) &m_sockAddress.sin_addr.s_addr,
             hostInfo->h_addr_list[0], 
             hostInfo->h_length );
				
    if (::connect( m_socket, (struct sockaddr *) &m_sockAddress,
                       sizeof(m_sockAddress) ) < 0)
    {
        retVal = false;
    }
   
    return retVal;
}


/**
 * @brief Prepare a server socket to accept connections.
 *
 * This function may only be called on TCP server sockets.  This function
 * must be called before calling accept().  If the number
 * of pending connections exceeds p_connections, clients may receive
 * ECONNREFUSED.
 *
 * @param p_connections     Maximum number of pending connections.
 *
 * @return true if the operation succeeded, false otherwise
 */
bool IBM_Socket::Listen( int p_connections )
{
    if( m_socket < 0 )
    {
        return false;
    }

    if (m_type != TCP_SERVER)
    {
        return false;
    }

    ::listen( m_socket, p_connections );

    return true; 
}


/**
 * @brief Set the receive timeout.
 *
 * On subsequent calls to receive, if no message is received within the
 * given time, receive will return true but the length of the message
 * will be zero.
 *
 * @param p_tv  Timeval structure specifying seconds + microseconds.
 *
 * @return true if the operation succeeded, false otherwise
 */
bool IBM_Socket::SetReceiveTimeout( struct timeval p_tv )
{
    bool retVal = true;

    if (m_socket < 0)
    {
        return false;
    }

    socklen_t optlen = sizeof(p_tv);
    if ( setsockopt( m_socket, SOL_SOCKET, SO_RCVTIMEO, &p_tv, optlen ) < 0)
    {
        retVal = false;
    }

    return retVal;
}


bool IBM_Socket::SetLinger( bool p_on, int time )
{
    bool retVal = true;

    if (m_socket < 0)
    {
        return false;
    }

    struct linger soLinger;
    soLinger.l_onoff  = p_on;
    soLinger.l_linger = time;

    socklen_t optlen = sizeof(soLinger);
    if ( setsockopt( m_socket, SOL_SOCKET, SO_LINGER, &soLinger, optlen ) < 0)
    {
        retVal = false;
    }

    return retVal;
}


/**
 * @brief Receive a packet
 *
 * @param p_pBuf            Buffer to store the packet that was received
 * @param p_length          IN Length of the buffer / OUT length of the packet
 * @param p_pSockAddress    OUT Address of the sender.
 *
 * @return Always true or throws IBM_Exception on errors
 */
bool IBM_Socket::Read( char* p_pBuf, size_t* p_length, struct sockaddr* p_pSockAddress )
{
    int count = 0;

    if ((m_socket < 0) || (m_type == INVALID))
    {
        throw IBM_Exception( "Attempt to read data from Invalid Socket.");
    }

    if (p_pSockAddress)
    {
        socklen_t len = sizeof(*p_pSockAddress);
        count = recvfrom( m_socket, p_pBuf, *p_length, 0, p_pSockAddress, &len );
    }
    else
    {
        count = recv( m_socket, p_pBuf, *p_length, 0 );
    }

    if (count == -1)
    {
        Close();
        m_socket = -1;

        throw IBM_Exception( "Socket receive failed.");
    }
    else if (count == 0)
    {
        Close();
        m_socket = -1;

        throw IBM_Exception( "Connection closed by peer." );
    }
    *p_length = count;

    return true;
}



/**
 * @brief Receive an Integer
 *
 * @param p_val            Variable to receive the integer
 * @param p_pSockAddress   OUT Address of the sender.
 *
 * @return Always true or throws IBM_Exception on errors
 */
bool IBM_Socket::ReadInt( uint32_t& p_val, struct sockaddr* p_pSockAddress )
{
    size_t len = 4;
    uint32_t data;

    Read( (char*) &data, &len, p_pSockAddress );
    
    p_val = ntohl(data);

    return true;
}



/**
 * @brief   Send a packet.
 *
 * If the send fails, this function closes the underlying socket.
 *
 * @param p_pBuf    Pointer to the buffer holding the message
 * @param p_length  Length of the message to send.
 * @param p_pSockAddress    Destination address.
 *
 * @return true if the operation succeeded, false otherwise
 */
bool IBM_Socket::Write( const char* p_pBuf, size_t p_length, 
                        const struct sockaddr* p_pSockAddress )
{
    if ((m_socket < 0) || (m_type == INVALID))
    {
        throw IBM_Exception( "Attempt to send data on Invalid Socket.");
    }

    if (p_pSockAddress)
    {
        if (::sendto( m_socket, p_pBuf, p_length, 0, 
                      p_pSockAddress, sizeof(*p_pSockAddress) ) < 0) 
        {
            Close();
            m_socket = -1;

            throw IBM_Exception( "sendto() error <%d>, closing socket", errno );
        }
    }
    else
    {
        if (::send( m_socket, p_pBuf, p_length, 0 ) < 0) 
        {
            Close();
            m_socket = -1;

            throw IBM_Exception( "send() error <%d>, closing socket", errno );
        }
    }

    return true;
}


bool IBM_Socket::WriteInt( uint32_t p_val, struct sockaddr* p_pSockAddress )
{
    size_t len = 4;
    uint32_t data = htonl(p_val);

    return Write( (char *) &data, len, p_pSockAddress );
}


/**
 * @brief get the handle to the device
 */
int IBM_Socket::GetHandle()
{
    return m_socket;
}


/**
 * @brief get the socket type
 */
IBM_Socket::TYPE IBM_Socket::GetSocketType()
{
    return m_type;
}
