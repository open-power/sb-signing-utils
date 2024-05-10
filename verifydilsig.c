
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
    size_t      sPubKeyBytes     = BUF_SIZE;
    size_t      sWirePubKeyBytes = BUF_SIZE;
    size_t      sDigestBytes     = BUF_SIZE;
    size_t      sSignatureBytes  = BUF_SIZE;
    int         sRc              = 0;
    int         sIdx             = 0;
    const char* sPubKeyFile      = NULL;
    const char* sDigestFile      = NULL;
    const char* sSigFile         = NULL;
    int         sPrintHelp       = 0;

    for(sIdx = 1; sIdx < argc; sIdx++)
    {
        if(strcmp(argv[sIdx], "-h") == 0)
        {
            sPrintHelp = 1;
        }
        else if(strcmp(argv[sIdx], "-i") == 0)
        {
            sIdx++;
            sDigestFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-k") == 0)
        {
            sIdx++;
            sPubKeyFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-s") == 0)
        {
            sIdx++;
            sSigFile = argv[sIdx];
        }
        else
        {
            printf("**** ERROR : Unknown parameter : %s\n", argv[sIdx]);
            sPrintHelp = 1;
        }
    }

    if(NULL == sDigestFile || NULL == sPubKeyFile || NULL == sSigFile)
    {
        printf("**** ERROR : Missing input parms\n");
        sPrintHelp = 1;
    }

    if(0 != sPrintHelp)
    {
        printf("\nverifydilsig -i <input digest> -k <public key> -s <signature filename>\n");
        exit(0);
    }

    mlca_ctx_t     sCtx;
    MLCA_RC        sMlRc       = 0;
    unsigned char* sPubKey     = malloc(BUF_SIZE);
    unsigned char* sWirePubKey = malloc(BUF_SIZE);
    unsigned char* sDigest     = malloc(BUF_SIZE);
    unsigned char* sSignature  = malloc(BUF_SIZE);

    sRc = readFile(sDigest, &sDigestBytes, sDigestFile);
    if(0 == sRc && (512 / 8) != sDigestBytes)
    {
        printf("**** ERROR : %s doesn't appear to be a SHA3-512 digest\n", sDigestFile);
        sRc = 1;
    }

    if(0 == sRc)
    {
        sRc = readFile(sWirePubKey, &sWirePubKeyBytes, sPubKeyFile);
    }

    if(0 == sRc)
    {
        sRc = readFile(sSignature, &sSignatureBytes, sSigFile);
    }

    if(0 == sRc)
    {
        // Raw public key size for dilithium r2 8/7
        if(2336 == sWirePubKeyBytes)
        {
            // Raw key, just copy
            memcpy(sPubKey, sWirePubKey, sWirePubKeyBytes);
            sPubKeyBytes = sWirePubKeyBytes;
        }
        else
        {

            unsigned int sWireType = 0;
            sRc                    = mlca_wire2key(
                sPubKey, sPubKeyBytes, &sWireType, sWirePubKey, sWirePubKeyBytes, NULL, ~0);
            if(0 >= sRc)
            {
                printf("**** ERROR: Unable to convert public key : %d\n", sRc);
                sRc = 1;
            }
            else
            {
                sPubKeyBytes = sRc;
                sRc          = 0;
            }
        }
    }

    if(0 == sRc)
    {
        sMlRc = mlca_init(&sCtx, 1, 0);
        if(sMlRc)
        {
            printf("**** ERROR : Failed mlca_init : %d\n", sMlRc);
            sRc = 1;
        }
    }
    if(0 == sRc)
    {
        sMlRc = mlca_set_alg(&sCtx, MLCA_ALGORITHM_SIG_DILITHIUM_R2_8x7_OID, OPT_LEVEL_AUTO);
        if(sMlRc)
        {
            printf("**** ERROR : Failed mlca_set_alg : %d\n", sMlRc);
            sRc = 1;
        }
    }
    if(0 == sRc)
    {
        sMlRc = mlca_set_encoding_by_idx(&sCtx, 0);
        if(sMlRc)
        {
            printf("**** ERROR : Failed mlca_set_encoding_by_name_oid : %d\n", sMlRc);
            sRc = 1;
        }
    }
    if(0 == sRc)
    {
        printf("Verifying Dilthium R2 8x7 signature ...\n");
        sMlRc = mlca_sig_verify(&sCtx, sDigest, sDigestBytes, sSignature, sSignatureBytes, sPubKey);
        if(1 != sMlRc)
        {
            printf("**** ERROR: Signature verification failure : %d\n", sMlRc);
            sRc = 1;
        }
    }

    free(sDigest);
    free(sSignature);
    free(sPubKey);
    free(sWirePubKey);
    mlca_ctx_free(&sCtx);

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
