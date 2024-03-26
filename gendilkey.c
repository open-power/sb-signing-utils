
#include "mlca2.h"
#include "pqalgs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 8000

int writeFile(const unsigned char *data,
	      size_t length,
	      const char *filename);

int main(int argc, char** argv)
{
	size_t sPrivKeyBytes = BUF_SIZE;
	size_t sPubKeyBytes = BUF_SIZE;
	size_t sWirePrivKeyBytes = BUF_SIZE;
	size_t sWirePubKeyBytes = BUF_SIZE;
	int sIdx = 0;
	int sRc = 0;
	int sPrintHelp = 0;
	const char* sPubKeyFile = NULL;
	const char* sPrivKeyFile = NULL;

	for (sIdx = 1; sIdx < argc; sIdx ++)
	{
		if (strcmp(argv[sIdx], "-h") == 0)
		{
			sPrintHelp = 1;
		}
		else if (strcmp(argv[sIdx], "-pub") == 0)
		{
			sIdx++;
			sPubKeyFile = argv[sIdx];
		}
		else if (strcmp(argv[sIdx], "-priv") == 0)
		{
			sIdx++;
			sPrivKeyFile = argv[sIdx];
		}
		else
		{
			printf("**** ERROR : Unknown parameter : %s\n", argv[sIdx]);
			sPrintHelp = 1;
		}
	}


	if (NULL == sPubKeyFile || NULL == sPrivKeyFile)
	{
		printf("**** ERROR : Missing input parms\n");
		sPrintHelp = 1;
	}

	if (0 != sPrintHelp)
	{
		printf("\ngendilkey -priv <private key file> -pub <public key file>\n");
		exit(0);
	}

	mlca_ctx_t sCtx;
	MLCA_RC    sMlRc = 0;
	unsigned char* sPubKey = malloc(BUF_SIZE);
	unsigned char* sPrivKey = malloc(BUF_SIZE);
	unsigned char* sWirePubKey = malloc(BUF_SIZE);
	unsigned char* sWirePrivKey = malloc(BUF_SIZE);

	if (0 == sRc)
	{
		sMlRc = mlca_init(&sCtx,1,0);
		if (sMlRc)
		{
			printf("**** ERROR : Failed mlca_init : %d\n", sMlRc);
			sRc = 1;
		}
	}
	if (0 == sRc)
	{
		sMlRc = mlca_set_alg(&sCtx, MLCA_ALGORITHM_SIG_DILITHIUM_R2_8x7_OID, OPT_LEVEL_AUTO);
		if (sMlRc)
		{
			printf("**** ERROR : Failed mlca_set_alg : %d\n", sMlRc);
			sRc = 1;
		}
	}
	if (0 == sRc)
	{
		sMlRc = mlca_set_encoding_by_idx(&sCtx, 0);
		if (sMlRc)
		{
			printf("**** ERROR : Failed mlca_set_encoding_by_name_oid : %d\n", sMlRc);
			sRc = 1;
		}
	}


	if (0 == sRc)
	{
		printf("Generating Dilthium R2 8x7 key pair ...\n");
		sPubKeyBytes = mlca_sig_crypto_publickeybytes(&sCtx);
		sPrivKeyBytes = mlca_sig_crypto_secretkeybytes(&sCtx);
		sMlRc = mlca_sig_keygen(&sCtx, sPubKey, sPrivKey);
		if (sMlRc)
		{
			printf("**** ERROR : Failed mlca_sig_keygen : %d\n", sMlRc);
			sRc = 1;
		}
	}

	if (0 == sRc)
	{
        // Convert private key
        sRc = mlca_key2wire(sWirePrivKey, sWirePrivKeyBytes,
                            sPrivKey, sPrivKeyBytes, 0,
                            sPubKey,  sPubKeyBytes,
                            NULL, ~0);
        if (sRc < 0)
        {
            printf("**** ERROR: Failure during private key conversion : %d\n", sRc);
        }
		else 
		{
        	sWirePrivKeyBytes = sRc;
			sRc = 0;
		}
	}

	if (0 == sRc)
	{

        // Convert public key
        sRc = mlca_key2wire(sWirePubKey, sWirePubKeyBytes,
                            sPubKey,     sPubKeyBytes, 0,
                            NULL, 0,
                            NULL, 0);
        if (sRc < 0)
        {
            printf("**** ERROR: Failure during public key conversion : %d\n", sRc);
			sRc = 1;
        }
		else
		{
        	sWirePubKeyBytes = sRc;
			sRc = 0;
		}
	}

	if (0 == sRc)
	{
   		writeFile(sWirePrivKey, sWirePrivKeyBytes, sPrivKeyFile);
	    writeFile(sWirePubKey, sWirePubKeyBytes, sPubKeyFile);

		printf("Private Key Size : %lu\n", sPrivKeyBytes);
		printf("Public Key Size  : %lu\n", sPubKeyBytes);

		printf("Private Key File : %s\n",sPrivKeyFile);
		printf("Public Key File  : %s\n",sPubKeyFile);

	}


	free(sPrivKey);
	free(sPubKey);
	free(sWirePrivKey);
	free(sWirePubKey);

	mlca_ctx_free(&sCtx);
	exit(sRc);
}

int writeFile(const unsigned char *data,
	      size_t length,
	      const char *filename)
{
    int sRc = 0;
    size_t sBytes;

    FILE *sFile = fopen(filename, "wb");
    if (NULL == sFile)
    {
	    printf("**** ERROR: Unable to open file : %s\n", filename);
	    sRc = 1;
    }

    if (0 == sRc)
    {
	    sBytes = fwrite(data, 1, length, sFile);
	    if (sBytes != length)
	    {
		    printf("**** ERROR: Failure writing to file : %s\n", filename);
		    sRc = 1;
	    }
    }
    if (NULL != sFile) {
	    if (fclose(sFile)) {
		    printf("**** ERROR: Failure closing file : %s\n", filename);
		    if (0 == sRc) sRc = 1;
	    }
    }
    return sRc;
}
