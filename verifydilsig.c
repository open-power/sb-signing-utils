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

#include "dilutils.h"
#include "mlca2.h"
#include "pqalgs.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 8000

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
    bool        sPrintHelp       = false;

    for(sIdx = 1; sIdx < argc; sIdx++)
    {
        if(strcmp(argv[sIdx], "-h") == 0)
        {
            sPrintHelp = true;
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
            sPrintHelp = true;
        }
    }

    if(!sPrintHelp && (NULL == sDigestFile || NULL == sPubKeyFile || NULL == sSigFile))
    {
        printf("**** ERROR : Missing input parms\n");
        sPrintHelp = true;
    }

    if(sPrintHelp)
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

    if(!sPubKey || !sWirePubKey || !sDigest || !sSignature)
    {
        printf("**** ERROR : Allocation Failure\n");
        exit(1);
    }

    sRc = readFile(sDigest, &sDigestBytes, sDigestFile);
    if(0 == sRc && SHA3_512_DigestSize != sDigestBytes)
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
        if(RawDilithiumR28x7PublicKeySize == sWirePubKeyBytes)
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
