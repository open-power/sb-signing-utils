
#include "crystals-oids.h"
#include "mlca2.h"
#include "pqalgs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 8000

int readFile(unsigned char* data, size_t* length, const char* filename);
int writeFile(const unsigned char* data, size_t length, const char* filename);

int main(int argc, char** argv)
{
    size_t      sRawBytes  = BUF_SIZE;
    size_t      sKeyBytes  = BUF_SIZE;
    int         sRc        = 0;
    int         sIdx       = 0;
    int         sPubIn     = 0;
    int         sPubOut    = 0;
    int         sRawIn     = 0;
    int         sRawOut    = 0;
    const char* sInFile    = NULL;
    const char* sOutFile   = NULL;
    int         sPrintHelp = 0;
    int         sVerbose   = 0;

    for(sIdx = 1; sIdx < argc; sIdx++)
    {
        if(strcmp(argv[sIdx], "-h") == 0)
        {
            sPrintHelp = 1;
        }
        else if(strcmp(argv[sIdx], "-k") == 0)
        {
            sIdx++;
            sInFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-o") == 0)
        {
            sIdx++;
            sOutFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-pubin") == 0)
        {
            sPubIn = 1;
        }
        else if(strcmp(argv[sIdx], "-pubout") == 0)
        {
            sPubOut = 1;
        }
        else if(strcmp(argv[sIdx], "-outraw") == 0)
        {
            sRawOut = 1;
        }
        else if(strcmp(argv[sIdx], "-inraw") == 0)
        {
            sRawIn = 1;
        }
        else if(strcmp(argv[sIdx], "-v") == 0)
        {
            sVerbose = 1;
        }
        else
        {
            printf("**** ERROR : Unknown parameter : %s\n", argv[sIdx]);
            sPrintHelp = 1;
        }
    }

    if(NULL == sInFile || (NULL == sOutFile && sRawOut))
    {
        printf("**** ERROR : Invalid input parms\n");
        sPrintHelp = 1;
    }

    if(0 != sPrintHelp)
    {
        printf(
            "\nextractdilkey -k <input key> [-pubin] [-inraw] [-o <output filename> [-outraw]]\n");
        exit(0);
    }

    unsigned char* sRawKey = malloc(BUF_SIZE);
    unsigned char* sKey    = malloc(BUF_SIZE);

    sRc = readFile(sKey, &sKeyBytes, sInFile);
    if(0 != sRc)
    {
        printf("**** ERROR : Unable to read from : %s\n", sInFile);
        sRc = 1;
    }

    do
    {
        // Now validate our input
        if(0 == sRc && sPubIn)
        {
            if(sRawIn)
            {
                // We have a raw Dilithium R2 8x7 public key
                if(2336 == sKeyBytes)
                {
                    // We have a raw public key, lets convert it
                    if(sVerbose)
                        printf("extractdilkey: Found raw public key\n");
                    memcpy(sRawKey, sKey, sKeyBytes);
                    sRawBytes = sKeyBytes;

                    sKeyBytes = BUF_SIZE;

                    // Convert public key
                    sRc = mlca_key2wire(sKey, sKeyBytes, sRawKey, sRawBytes, 0, NULL, 0, NULL, 0);
                    if(sRc < 0)
                    {
                        printf("**** ERROR: Failure during public key conversion : %d\n", sRc);
                        break;
                    }
                    sKeyBytes = sRc;
                    sRc       = 0;
                }
                else
                {
                    printf("**** ERROR: Unrecognized raw public key : %s\n", sInFile);
                    sRc = 1;
                    break;
                }
            }
            else
            {
                // Attempt to convert encoded key
                unsigned int sWireType = 0;
                sRc = mlca_wire2key(sRawKey, sRawBytes, &sWireType, sKey, sKeyBytes, NULL, ~0);
                if(sVerbose)
                    printf("extractdilkey: Found public key\n");
                // We have a raw Dilithium R2 8x7 public key
                if(2336 != sRc)
                {
                    printf("**** ERROR: Unable to convert public key : %d\n", sRc);
                    sRc = 1;
                    break;
                }
                else
                {
                    sRawBytes = sRc;
                    sRc       = 0;
                }
            }

            if(NULL != sOutFile)
            {
                printf("Writing public key to : %s\n", sOutFile);
                if(sRawOut)
                {
                    sRc = writeFile(sRawKey, sRawBytes, sOutFile);
                }
                else
                {
                    sRc = writeFile(sKey, sKeyBytes, sOutFile);
                }
            }
            else
            {
                printf("Valid Dilithium public keyfile detected\n");
            }
        }

        // Private keys
        else if(0 == sRc && !sPubIn)
        {
            if(sRawIn)
            {
                // Raw private key size for dilithium r2 8/7
                if(5136 == sKeyBytes)
                {
                    if(sVerbose)
                        printf("extractdilkey: Found raw private key\n");
                    // We have a raw private key, lets convert it
                    memcpy(sRawKey, sKey, sKeyBytes);
                    sRawBytes = sKeyBytes;

                    sKeyBytes = BUF_SIZE;

                    // TODO , convert raw private key to encoded format without the public key
                    if(sOutFile)
                    {
                        sRc = 1;
                        printf("**** ERROR: Unable to convert private raw -> encoded\n");
                        break;
                    }
                }
                else
                {
                    printf("**** ERROR: Unrecognized raw private key : %s\n", sInFile);
                    sRc = 1;
                    break;
                }
            }
            else
            {
                // Attempt to convert encoded key
                unsigned int sWireType = 0;
                if(sPubOut)
                {
                    // Get the raw public key
                    sRc = mlca_wire2key(sRawKey,
                                        sRawBytes,
                                        &sWireType,
                                        sKey,
                                        sKeyBytes,
                                        (const unsigned char*)CR_OID_SPECIAL_PRV2PUB,
                                        CR_OID_SPECIAL_PRV2PUB_BYTES);
                    if(0 >= sRc)
                    {
                        printf("**** ERROR: Unable to convert private key : %d\n", sRc);
                        sRc = 1;
                        break;
                    }
                    else
                    {
                        sRawBytes = sRc;
                        sRc       = 0;
                    }
                    if(sVerbose)
                        printf("extractdilkey: Found public key\n");

                    // Encode it
                    sRc = mlca_key2wire(sKey, sKeyBytes, sRawKey, sRawBytes, 0, NULL, 0, NULL, 0);
                    if(sRc < 0)
                    {
                        printf("**** ERROR: Failure during public key conversion : %d\n", sRc);
                        break;
                    }
                    sKeyBytes = sRc;
                }
                else
                {
                    sRc = mlca_wire2key(sRawKey, sRawBytes, &sWireType, sKey, sKeyBytes, NULL, ~0);

                    // Raw private key size for dilithium r2 8/7
                    if(0 >= sRc || 5136 != sRc)
                    {
                        printf("**** ERROR: Unable to convert private key : %d\n", sRc);
                        sRc = 1;
                        break;
                    }
                    else
                    {
                        sRawBytes = sRc;
                        sRc       = 0;
                    }
                }
            }

            if(NULL != sOutFile)
            {
                printf("Writing private key to : %s\n", sOutFile);
                if(sRawOut)
                {
                    sRc = writeFile(sRawKey, sRawBytes, sOutFile);
                }
                else
                {
                    sRc = writeFile(sKey, sKeyBytes, sOutFile);
                }
            }
            else
            {
                printf("Valid Dilithium private keyfile detected\n");
            }
        }
    } while(0);

    exit(sRc);

    free(sKey);
    free(sRawKey);
    exit(sRc);
}

int readFile(unsigned char* data, size_t* length, const char* filename)
{
    int    sRc    = 0;
    size_t sBytes = 0;

    FILE* sFile = fopen(filename, "rb");
    if(NULL == sFile)
    {
        printf("**** ERROR: Unable to open file : %s\n", filename);
        sRc = 1;
    }

    /* Verify we have enough space */
    if(0 == sRc)
    {
        sRc = fseek(sFile, 0, SEEK_END);
        if(-1 == sRc)
        {
            printf("**** ERROR : Unable to find end of : %s\n", filename);
            sRc = 1;
        }
    }

    if(0 == sRc)
    {
        long sLen = ftell(sFile);
        if(-1 == sLen)
        {
            printf("**** ERROR : Unable to determine length of %s\n", filename);
            sRc = 1;
        }
        else if(*length < (size_t)sLen)
        {
            printf("**** ERROR : Not enough space for contents of file E:%lu A:%lu : %s\n",
                   (size_t)sLen,
                   *length,
                   filename);
            sRc = 1;
        }
        else
        {
            *length = (size_t)sLen;
        }
    }

    if(0 == sRc)
    {
        fseek(sFile, 0, SEEK_SET);

        sBytes = fread(data, 1, *length, sFile);
        if(sBytes != *length)
        {
            printf("**** ERROR: Failure reading from file : %s\n", filename);
            sRc = 1;
        }
    }
    if(NULL != sFile)
    {
        if(fclose(sFile))
        {
            printf("**** ERROR: Failure closing file : %s\n", filename);
            if(0 == sRc)
                sRc = 1;
        }
    }
    return sRc;
}

int writeFile(const unsigned char* data, size_t length, const char* filename)
{
    int    sRc    = 0;
    size_t sBytes = 0;

    FILE* sFile = fopen(filename, "wb");
    if(NULL == sFile)
    {
        printf("**** ERROR: Unable to open file : %s\n", filename);
        sRc = 1;
    }

    if(0 == sRc)
    {
        sBytes = fwrite(data, 1, length, sFile);
        if(sBytes != length)
        {
            printf("**** ERROR: Failure writing to file : %s\n", filename);
            sRc = 1;
        }
    }
    if(NULL != sFile)
    {
        if(fclose(sFile))
        {
            printf("**** ERROR: Failure closing file : %s\n", filename);
            if(0 == sRc)
                sRc = 1;
        }
    }
    return sRc;
}
