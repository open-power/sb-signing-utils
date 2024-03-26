
#include "mlca2.h"
#include "pqalgs.h"
#include "crystals-oids.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 8000

int readFile(unsigned char *data,
	     size_t *length,
	     const char *filename);
int writeFile(const unsigned char *data,
	      size_t length,
	      const char *filename);

int main(int argc, char** argv)
{
	size_t sPrivKeyBytes = BUF_SIZE;
	size_t sWirePrivKeyBytes = BUF_SIZE;
	size_t sDigestBytes = BUF_SIZE;
	size_t sSignatureBytes = BUF_SIZE;
	int sRc = 0;
	int sIdx = 0;
	const char* sPrivKeyFile = NULL;
	const char* sDigestFile = NULL;
	const char* sSigFile = NULL;
	int sPrintHelp = 0;
	int sVerbose = 0;

	for (sIdx = 1; sIdx < argc; sIdx ++)
	{
		if (strcmp(argv[sIdx], "-h") == 0)
		{
			sPrintHelp = 1;
		}
		else if (strcmp(argv[sIdx], "-i") == 0)
		{
			sIdx++;
			sDigestFile = argv[sIdx];
		}
		else if (strcmp(argv[sIdx], "-k") == 0)
		{
			sIdx++;
			sPrivKeyFile = argv[sIdx];
		}
		else if (strcmp(argv[sIdx], "-o") == 0)
		{
			sIdx++;
			sSigFile = argv[sIdx];
		}
		else if (strcmp(argv[sIdx], "-v") == 0)
		{
			sVerbose = 1;
		}
		else
		{
			printf("**** ERROR : Unknown parameter : %s\n", argv[sIdx]);
			sPrintHelp = 1;
		}
	}


	if (NULL == sDigestFile || NULL == sPrivKeyFile || NULL == sSigFile)
	{
		printf("**** ERROR : Missing input parms\n");
		sPrintHelp = 1;
	}

	if (0 != sPrintHelp)
	{
		printf("\ngendilsig -i <input digest> -k <private key> -o <output filename>\n");
		exit(0);
	}

	mlca_ctx_t sCtx;
	MLCA_RC    sMlRc = 0;
	unsigned char* sDigest = malloc(BUF_SIZE);
	unsigned char* sSignature = malloc(BUF_SIZE);
	unsigned char* sPrivKey = malloc(BUF_SIZE);
	unsigned char* sWirePrivKey = malloc(BUF_SIZE);

	sRc = readFile(sDigest,&sDigestBytes,sDigestFile);
	if (0 == sRc && (512/8) != sDigestBytes)
	{
		printf("**** ERROR : %s doesn't appear to be a SHA3-512 digest\n", sDigestFile);
		sRc = 1;
	}

	if (0 == sRc)
	{
		sRc = readFile(sWirePrivKey, &sWirePrivKeyBytes, sPrivKeyFile);
	}

	// Convert the key
	if (0 == sRc)
	{
		// Raw private key size for dilithium r2 8/7
        if (5136 == sWirePrivKeyBytes)
        {
            if (sVerbose) printf("gendilsig: Found raw private key\n");

            // Raw key, just copy
            memcpy(sPrivKey, sWirePrivKey, sWirePrivKeyBytes);
            sPrivKeyBytes = sWirePrivKeyBytes;
        }
        else
        {
			if (sVerbose) printf("gendilsig: Found private key\n");

		    unsigned int sWireType = 0;
    	    sRc = mlca_wire2key(sPrivKey, sPrivKeyBytes, &sWireType,
        	                    sWirePrivKey, sWirePrivKeyBytes,
            	                NULL, ~0);
        	if (0 >= sRc || 5136 != sRc)
        	{
            	printf("**** ERROR: Unable to convert raw private key : %d\n",sRc);
            	sRc = 1;
        	}
        	else
        	{
            	sPrivKeyBytes = sRc;
            	sRc = 0;
        	}
		}
	}

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
		printf("Generating Dilthium R2 8x7 signature ...\n");
#if 0
		sMlRc = mlca_sig_sign(&sCtx, sSignature, &sSignatureBytes,
							sDigest, sDigestBytes,
							sPrivKey);
		if (sMlRc)
		{
			printf("**** ERROR: Failure during signature generation : %d\n", sMlRc);
			sRc = 1;
		}
#else
		int gRc = mlca_sign(sSignature, sSignatureBytes,   /// validate RC
				    sDigest, sDigestBytes,
				    sPrivKey, sPrivKeyBytes,
				    (const unsigned char *)CR_OID_DIL_R2_8x7,
				    CR_OID_DIL_R2_8x7_BYTES);
		if (gRc < 0)
		{
			printf("**** ERROR: Failure during signature generation : %d\n", sMlRc);
			sRc = 1;
		}
		else
		{
			sSignatureBytes = gRc;
		}

#endif
	}

    if (0 == sRc)
	{
        printf("Signature Size : %lu\n", sSignatureBytes);

        writeFile(sSignature, sSignatureBytes, sSigFile);
    }

	free(sDigest);
	free(sSignature);
	free(sPrivKey);
	free(sWirePrivKey);
	mlca_ctx_free(&sCtx);

	exit(sRc);
}


int readFile(unsigned char *data,
	     size_t *length,
	     const char *filename)
{
	int sRc = 0;
	size_t sBytes = 0;

	FILE *sFile = fopen(filename, "rb");
	if (NULL == sFile)
	{
		printf("**** ERROR: Unable to open file : %s\n", filename);
		sRc = 1;
	}

	/* Verify we have enough space */
	if (0 == sRc)
	{
		sRc = fseek(sFile, 0, SEEK_END);
		if (-1 == sRc) {
			printf("**** ERROR : Unable to find end of : %s\n", filename);
			sRc = 1;
		}
	}

	if (0 == sRc)
	{
		long sLen = ftell(sFile);
		if (-1 == sLen)
		{
			printf("**** ERROR : Unable to determine length of %s\n", filename);
			sRc = 1;
		}
		else if (*length < (size_t)sLen)
		{
			printf("**** ERROR : Not enough space for contents of file E:%lu A:%lu : %s\n",
			       (size_t)sLen, *length, filename);
			sRc = 1;
		}
		else
		{
			*length = (size_t)sLen;
		}
	}

	if (0 == sRc)
	{
		fseek(sFile, 0, SEEK_SET);

		sBytes = fread(data, 1, *length, sFile);
		if (sBytes != *length)
		{
			printf("**** ERROR: Failure reading from file : %s\n", filename);
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

int writeFile(const unsigned char *data,
	      size_t length,
	      const char *filename)
{
	int sRc = 0;
	size_t sBytes = 0;

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
