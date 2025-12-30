/* Copyright 2024 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crystals-oids.h"
#include "dilutils.h"
#include "mlca2.h"
#include "pqalgs.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 8000
char* gAlgname = MLCA_ALGORITHM_SIG_DILITHIUM_87_R2;
char* gOid = CR_OID_DIL_R2_8x7;
size_t gOidBytes = CR_OID_DIL_R2_8x7_BYTES;

int main(int argc, char** argv)
{
    size_t      sPrivKeyBytes     = BUF_SIZE;
    size_t      sWirePrivKeyBytes = BUF_SIZE;
    size_t      sTBSBytes         = 0;
    size_t      sSignatureBytes   = BUF_SIZE;
    int         sRc               = 0;
    int         sIdx              = 0;
    const char* sPrivKeyFile      = NULL;
    const char* sTBSDataFile      = NULL; /* sha512 or sha3-512 digest or plain data */
    const char* sSigFile          = NULL;
    bool        sPrintHelp        = false;
    bool        sVerbose          = false;
    bool        sMLDSAPureMode    = false;

    for(sIdx = 1; sIdx < argc; sIdx++)
    {
        if(strcmp(argv[sIdx], "-h") == 0)
        {
            sPrintHelp = true;
        }
        else if(strcmp(argv[sIdx], "-i") == 0)
        {
            sIdx++;
            sTBSDataFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-k") == 0)
        {
            sIdx++;
            sPrivKeyFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-o") == 0)
        {
            sIdx++;
            sSigFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-v") == 0)
        {
            sVerbose = true;
        }
        else if(strcmp(argv[sIdx], "--pure") == 0)
        {
            sMLDSAPureMode = true;
        }
        else
        {
            printf("**** ERROR : Unknown parameter : %s\n", argv[sIdx]);
            sPrintHelp = true;
        }
    }

    if(!sPrintHelp && (NULL == sTBSDataFile || NULL == sPrivKeyFile || NULL == sSigFile))
    {
        printf("**** ERROR : Missing input parms\n");
        sPrintHelp = true;
    }

    if(sPrintHelp)
    {
        printf("\ngendilsig -i <input digest> -k <private key> -o <output filename>\n");
        exit(0);
    }

    mlca_ctx_t     sCtx;
    MLCA_RC        sMlRc        = 0;
    unsigned char* sTBS         = NULL;
    unsigned char* sSignature   = malloc(BUF_SIZE);
    unsigned char* sPrivKey     = malloc(BUF_SIZE);
    unsigned char* sWirePrivKey = malloc(BUF_SIZE);

    if(!sSignature || !sPrivKey || !sWirePrivKey)
    {
        printf("**** ERROR : Allocation Failure\n");
        exit(1);
    }

    sRc = readFileAlloc(sTBSDataFile, &sTBS, &sTBSBytes);
    /* if pure mode was NOT chosen, then input data must be SHA3-512 or SHA512 */
    if(0 == sRc && sMLDSAPureMode == false && SHA3_512_DigestSize != sTBSBytes)
    {
        printf("**** ERROR : %s doesn't appear to be a SHA3-512 digest\n", sTBSDataFile);
        sRc = 1;
    }

    if(0 == sRc)
    {
        sRc = readFile(sWirePrivKey, &sWirePrivKeyBytes, sPrivKeyFile);
    }

    // Convert the key
    if(0 == sRc)
    {
        // Raw private key size for dilithium r2 8/7
        if(RawDilithiumR28x7PrivateKeySize == sWirePrivKeyBytes)
        {
            if(sVerbose)
                printf("gendilsig: Found raw dilithium r2 87 private key\n");

            // Raw key, just copy
            memcpy(sPrivKey, sWirePrivKey, sWirePrivKeyBytes);
            sPrivKeyBytes = sWirePrivKeyBytes;
            gAlgname = MLCA_ALGORITHM_SIG_DILITHIUM_87_R2;
            gOid = MLCA_ALGORITHM_SIG_DILITHIUM_R2_8x7_OID;
            gOidBytes = 13;
        }
        else if (RawMldsa87PrivateKeySize == sWirePrivKeyBytes)
        {
            if(sVerbose)
                printf("gendilsig: Found raw mldsa 87 private key\n");

            // Raw key, just copy
            memcpy(sPrivKey, sWirePrivKey, sWirePrivKeyBytes);
            sPrivKeyBytes = sWirePrivKeyBytes;
            gAlgname = MLCA_ALGORITHM_SIG_MLDSA_87;
            gOid = MLCA_ALGORITHM_SIG_MLDSA_87_OID;
            gOidBytes = 11;
        }
        else
        {
            if(sVerbose)
                printf("gendilsig: Found private key\n");

            unsigned int sWireType = 0;
            sRc                    = mlca_wire2key(
                sPrivKey, sPrivKeyBytes, &sWireType, sWirePrivKey, sWirePrivKeyBytes, NULL, ~0);
            if (0 >= sRc || 
                (RawDilithiumR28x7PrivateKeySize != sRc && RawMldsa87PrivateKeySize != sRc))
            {
                printf("**** ERROR: Unable to convert raw private key : %d\n", sRc);
                sRc = 1;
            }
            else
            {
                sPrivKeyBytes = sRc;
                sRc           = 0;

                if (RawMldsa87PrivateKeySize == sPrivKeyBytes)
                {
                    gAlgname = MLCA_ALGORITHM_SIG_MLDSA_87;
                    gOid = MLCA_ALGORITHM_SIG_MLDSA_87_OID;
                    gOidBytes = 11;
                }
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
        sMlRc = mlca_set_alg(&sCtx, gAlgname, OPT_LEVEL_AUTO);
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
        printf("Generating %s signature ... (signing %zu bytes)\n",gAlgname, sTBSBytes);
        int gRc = mlca_sign(sSignature,
                            sSignatureBytes, /// validate RC
                            sTBS,
                            sTBSBytes,
                            sPrivKey,
                            sPrivKeyBytes,
                            NULL,
                            (const unsigned char*)gOid,
                            gOidBytes);
        if(gRc < 0)
        {
            printf("**** ERROR: Failure during signature generation : %d\n", sMlRc);
            sRc = 1;
        }
        else
        {
            sSignatureBytes = gRc;
        }
    }

    if(0 == sRc)
    {
        printf("Signature Size : %lu\n", sSignatureBytes);

        writeFile(sSignature, sSignatureBytes, sSigFile);
    }

    free(sTBS);
    free(sSignature);
    free(sPrivKey);
    free(sWirePrivKey);
    mlca_ctx_free(&sCtx);

    exit(sRc);
}
