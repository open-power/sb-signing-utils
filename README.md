To sign an official build, we need sign_agent to talk to the signing server via Notes. 
It takes a little work to setup the environment.


== Setup ==

=== Lotus Notes ===

   Install Notes on your build server, 8.5.1 or 8.5.2 is fine. 
   Import your Notes ID to allow Notes to send/receive emails.
   Set up Notes so it will sign the sent email.

=== sign_agent ===

  You may be able to use a prebuilt sign_agent executable.  If not, you will need the lotus notes toolkit to build it.

  To build sign_agent: 
     1. Install Notes Toolkit from IBM website: 
        http://www14.software.ibm.com/webapp/download/nochargesearch.jsp?k=ALL&status=Active&q=Lotus+%22C+API%22
        or 
        https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=ESD-SUPPORT&S_PKG=CRB98EN&lang=en_US&cp=UTF-8

        IBM Lotus C API Toolkit for Notes/Domino 8.5 for Windows 32 and 64 Bit English
        or 
        IBM Lotus C API Toolkit for Notes/Domino 8.5 for AIX 32 and 64 Bit, Solaris, Linux 32 Bit, zLinux 64 Bit English

     2. Check out security/buildtools/sign_agent.
     3. Edit gnu makefile to point to your lotus toolkit and runtime: 
           NOTES_PATH = /opt/ibm/lotus/notes
           NOTES_DEVEL = /opt/lotus/notesapi
     4. Run "make" to build sign_agent.

=== Create sign agent rc file ===

   This is saved as ~/.sign_agentrc 
   epwd value comes from signing server

   # default options used with sign_agent
   --server     d03nm690
   --mailfile   mail3/rhjewell.nsf 
   --send_to    "CN=System x EPCS/OU=Raleigh/O=IBM"
   --user       rhjewell
   --epwd       442a4e7... 
   --port       8001
   --retries    30
   -v 

=== CCA profiles ===

   The keynames used by signtool must be mapped to the project names used by the CCA signing server.
   This is done using an ini file that can be passed in on the command line, or included in the "rc" file.

    --ini       ini file containing mapping from keyname to CCA profile name

    The file is created by the user and contains ini file type statements to map from the keyname to the project name,
    for example, 


    # mapping of signtool key names to CCA profiles needed for signing with production keys
    # 9/12/2011
    # 

    [ CCA_profiles ]                                                                                       
    crtm_boot  = imm2-crtm_boot  
    crtm_flash = imm2-crtm_flash 
    immfw      = imm2-immfw      
    securefs   = imm2-securefs   
    uimage     = imm2-uimage     
    debug      = imm2-debug

=== running === 

The path to the notes executables must be known by sign_agent.  
If you are not using /opt/ibm/lotus/notes,  use the --notes option or export NotesInitExtended to set it.

start lotus notes
start sign_agent 
signtool run in production mode will connect to sign_agent to sign images.

Note: Use killall -9 sign_agent to stop a running sign_agent.  
( It currently blocks waiting for a socket connection and does not see other signals. )

./sign_agent --ini sign_agent.ini  & 


=== testing === 

echo testthis > /tmp/testthis
CHKSUM=`sha256sum /tmp/testthis | awk '{print $1}'`
signtool --sign $CHKSUM --output test.sig --keyname debug --mode production  
signtool --verify_with_sigfile /tmp/testthis --sigfile test.sig --keyname debug --verbose

                                              


